#!/usr/bin/env bash
# =============================================================================
# recon_portscan.sh — Smart targeted port scanner (v1.0)
#
# PURPOSE
#   Finds exposed services on non-standard ports that httpx never sees.
#   Scans ~120 purposeful ports across three tiers:
#
#   CRITICAL  — Unauthenticated DB/API/container exposure (Redis, MongoDB,
#               Docker daemon, etcd, Memcached, Cassandra, WebLogic …)
#               Finding = often P0 or critical severity.
#
#   ADMIN     — Management panels with frequent auth bypass / default creds
#               (Jenkins, Grafana, Kibana, Consul, Vault, Jupyter, Solr …)
#
#   ALT-HTTP  — Shadow APIs and dev servers on alternate HTTP ports
#               (81-90, 8000-8100, 3000-5001 …) that carry real endpoints.
#
# TARGETING (smart filtering — never wastes a scan)
#   ✔ P1+ in-scope paying hosts, sorted by triage_score desc
#   ✔ Direct-IP hosts only — skips CDN-fronted (Cloudflare/Akamai/Fastly
#     edge nodes filter non-HTTP ports; scanning them is pure noise)
#   ✔ Per-host cooldown (7 days, stored as portscan_at in ES)
#   ✔ Hard cap per cycle — configurable batch, default 50 hosts
#
# OUTPUT
#   • ES: portscan_at, portscan_open_ports[], portscan_critical (bool)
#   • triage_signals updated with port:N entries for every open port
#   • triage_score boosted: +12 critical / +6 admin / +3 alt-http
#   • Discord alert for any critical port find
#   • Nuclei targeted sweep for services with known templates
#
# EGRESS  Target-facing. Invoked via run_scanner (sudo -u reconrun) so
#   it egresses through Mullvad like every other scanner.
# =============================================================================
set -uo pipefail
IFS=$'\n\t'

log()  { printf '[%s PORTSCAN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s PORTSCAN WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
die()  { warn "$*"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/recon_net.sh"
setup_es_netrc
ES_AUTH=(--netrc-file "$HOME/.recon_es_netrc")

BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"
INDEX_NAME="${INDEX_NAME:-recon_alive}"

LOCK_FILE="$STATE_DIR/portscan.lock"
SCAN_DIR="$BASE_DIR/portscan"
mkdir -p "$SCAN_DIR"

exec 9>"$LOCK_FILE"
flock -n 9 || { warn "portscan already running"; exit 0; }

# ── Port tiers ───────────────────────────────────────────────────────────────
# CRITICAL: unauthenticated service exposure — finding these is almost always
# a high/critical bug bounty report. Mapped to +12 triage score bonus.
PORTS_CRITICAL=(
  2375 2376          # Docker daemon (unauth = container escape)
  6379               # Redis (usually unauth)
  27017              # MongoDB (usually unauth)
  9200 9300          # Elasticsearch
  11211              # Memcached (always unauth)
  2181               # ZooKeeper
  2379 2380          # etcd (K8s control plane secrets)
  5984               # CouchDB (CVE-2017-12635 auth bypass)
  9042               # Cassandra
  7474               # Neo4j browser (default no-auth)
  9092               # Kafka (auth bypass, message poisoning)
  15672              # RabbitMQ management (default guest/guest)
  1099               # Java RMI (deserialize RCE)
  7001 7002          # WebLogic (T3 deserialization RCE)
  4848               # GlassFish admin console
  8983               # Apache Solr admin (SSRF + data exposure)
)
CRITICAL_SET=" $(printf '%s ' "${PORTS_CRITICAL[@]}") "   # space-delimited; IFS-safe (IFS=$'\n\t' would break array expansion)

# ADMIN: management panels — auth bypass / default creds common. +6 bonus.
PORTS_ADMIN=(
  8080               # Jenkins, Tomcat, Spring Boot actuator
  8443               # HTTPS admin variants
  8888               # Jupyter notebook (code exec!), others
  9090               # Prometheus, Cockpit
  3000               # Grafana (admin/admin default), Node dev
  5601               # Kibana dashboard
  8089               # Splunk API
  8500               # Consul UI/API (config, secrets readable)
  8200               # Vault (secrets management)
  6443               # Kubernetes API server
  10250              # Kubelet API (unauth = node RCE in old K8s)
  10255              # Kubelet read-only (pod info leak)
  9000               # SonarQube, MinIO API, Portainer
  9001               # MinIO console, Supervisord
  8161               # ActiveMQ admin console
  61616              # ActiveMQ broker
  8069               # Odoo/OpenERP
  8787               # RStudio Server (arbitrary code exec)
  4873               # Verdaccio/npm registry (package poisoning)
  8086               # InfluxDB (metrics + possible auth bypass)
  5000 5001          # Docker Registry, Flask dev, various
)
ADMIN_SET=" $(printf '%s ' "${PORTS_ADMIN[@]}") "

# ALT-HTTP: shadow APIs and dev servers. +3 bonus if live HTTP response.
PORTS_ALT_HTTP=(
  81 82 83 84 85 86 87 88 89 90
  8000 8001 8008 8081 8082 8083 8084 8085 8090 8091
  8092 8093 8094 8095 8096 8097 8098 8099 8100
  8180 8181 8280 8380 8480
  3001 3002 3003 4000 4001 4567
  7777 9999
)

ALL_PORTS="$(IFS=,; echo "${PORTS_CRITICAL[*]},${PORTS_ADMIN[*]},${PORTS_ALT_HTTP[*]}")"

# ── Service names (port → readable name for Discord/logs) ────────────────────
declare -A SVC_NAME=(
  [2375]="docker-daemon" [2376]="docker-daemon-tls"
  [6379]="redis"         [27017]="mongodb"
  [9200]="elasticsearch" [9300]="elasticsearch-transport"
  [11211]="memcached"    [2181]="zookeeper"
  [2379]="etcd"          [2380]="etcd-peer"
  [5984]="couchdb"       [9042]="cassandra"
  [7474]="neo4j"         [9092]="kafka"
  [15672]="rabbitmq-mgmt" [1099]="java-rmi"
  [7001]="weblogic"      [7002]="weblogic-ssl"
  [4848]="glassfish"     [8983]="solr"
  [8080]="http-alt-8080" [8443]="https-alt"
  [8888]="jupyter"       [9090]="prometheus"
  [3000]="grafana"       [5601]="kibana"
  [8089]="splunk-api"    [8500]="consul"
  [8200]="vault"         [6443]="k8s-api"
  [10250]="kubelet-api"  [10255]="kubelet-readonly"
  [9000]="sonarqube"     [9001]="minio-console"
  [8161]="activemq"      [61616]="activemq-broker"
  [8069]="odoo"          [8787]="rstudio"
  [5000]="docker-registry" [5001]="docker-registry-tls"
  [8086]="influxdb"      [8280]="http-alt-8280"
)

# ── Nuclei templates for critical services ───────────────────────────────────
declare -A NUCLEI_TEMPLATES=(
  [6379]="network/detection/redis-unauth-detect.yaml"
  [27017]="network/detection/mongodb-unauth-detect.yaml"
  [9200]="network/detection/elasticsearch-unauth-detect.yaml"
  [2375]="network/detection/docker-api-unauth-detect.yaml"
  [11211]="network/detection/memcached-unauth-detect.yaml"
  [9090]="http/exposed-panels/prometheus-metrics.yaml"
  [3000]="http/default-logins/grafana-default-login.yaml"
  [5601]="http/exposed-panels/kibana-panel.yaml"
  [8080]="http/exposed-panels/jenkins-dashboard.yaml"
  [8888]="http/exposed-panels/jupyter-notebook.yaml"
  [8983]="http/exposed-panels/apache-solr-panel.yaml"
  [8500]="http/exposed-panels/consul-agent-panel.yaml"
  [8200]="http/exposed-panels/hashicorp-vault-panel.yaml"
  [9000]="http/exposed-panels/sonarqube-panel.yaml"
  [15672]="http/default-logins/rabbitmq-default-login.yaml"
)

# ── Config ───────────────────────────────────────────────────────────────────
NAABU_BIN="${NAABU_BIN:-$(command -v naabu 2>/dev/null || echo '')}"
NUCLEI_BIN="${NUCLEI_BIN:-$(command -v nuclei 2>/dev/null || echo '')}"
PORTSCAN_RATE="${PORTSCAN_RATE:-1500}"        # naabu pkt/s (throttle for VPN)
PORTSCAN_TIMEOUT="${PORTSCAN_TIMEOUT:-3}"     # per-port connect timeout (s)
PORTSCAN_RETRIES="${PORTSCAN_RETRIES:-1}"     # naabu retries per port
PORTSCAN_BATCH="${PORTSCAN_BATCH:-50}"        # hosts per cycle
PORTSCAN_MIN_SCORE="${PORTSCAN_MIN_SCORE:-8}" # min triage_score to target
PORTSCAN_COOLDOWN="${PORTSCAN_COOLDOWN:-604800}" # 7 days in seconds
PORTSCAN_MAX_RUNTIME="${PORTSCAN_MAX_RUNTIME:-1800}" # hard cap: 30 min

# ── Tool check ───────────────────────────────────────────────────────────────
[[ -x "$NAABU_BIN" ]] || die "naabu not found — install: go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"

es_curl() { curl -sS -m30 "${ES_AUTH[@]}" "$@"; }

# discord_alert: uses discord_hook + discord_post from recon_net.sh.
# Reads webhook from ~/.recon_discord_ports (per-channel pattern).
# Rate-limit aware (429 retry), 5-attempt delivery guarantee.
discord_alert() {
  local hook; hook="$(discord_hook ports)"
  [[ -z "$hook" ]] && return 0
  discord_post "$hook" "$(jq -nc --arg c "$1" '{content:$c}')"
}

# ── Target selection ─────────────────────────────────────────────────────────
# Pull in-scope paying P1+ hosts not scanned within cooldown, not CDN-fronted.
# cdn_name being set means the resolved IP is a CDN edge — port scan is noise.
cooldown_cutoff="$(date -u -d "-${PORTSCAN_COOLDOWN} seconds" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || \
  python3 -c "from datetime import datetime,timedelta; print((datetime.utcnow()-timedelta(seconds=${PORTSCAN_COOLDOWN})).strftime('%Y-%m-%dT%H:%M:%SZ'))")"

query="$(jq -nc \
  --argjson min_score "$PORTSCAN_MIN_SCORE" \
  --arg cutoff "$cooldown_cutoff" \
  --argjson size "$PORTSCAN_BATCH" '{
    size: $size,
    _source: ["host","ip","cdn_name","triage_score","triage_signals","portscan_at","triage_program"],
    query: {bool: {
      filter: [
        {term: {triage_in_scope: true}},
        {term: {triage_pays: true}},
        {range: {triage_score: {gte: $min_score}}}
      ],
      must_not: [
        # Exclude CDN-fronted hosts — their edge IPs filter non-HTTP ports
        {exists: {field: "cdn_name"}},
        # Exclude recently scanned
        {range: {portscan_at: {gte: $cutoff}}}
      ]
    }},
    sort: [{triage_score: {order: "desc"}}]
  }')"

resp="$(es_curl -H 'Content-Type: application/json' \
  -X POST "$ES_URL/$INDEX_NAME/_search" -d "$query" 2>/dev/null)"

total="$(printf '%s' "$resp" | jq -r '.hits.total.value // 0')"
log "Eligible targets (score≥${PORTSCAN_MIN_SCORE} / P1+, no CDN, not scanned in 7d): $total — scanning up to $PORTSCAN_BATCH"
[[ "$total" -eq 0 ]] && { log "Nothing to scan this cycle"; exit 0; }

# Build host list
host_list="$SCAN_DIR/hosts_$(date -u +%Y%m%dT%H%M%SZ).txt"
printf '%s' "$resp" | jq -r '.hits.hits[]._source.host' > "$host_list"
nhosts="$(wc -l < "$host_list" | tr -d ' ')"
log "Scanning $nhosts hosts for ${#PORTS_CRITICAL[@]} critical + ${#PORTS_ADMIN[@]} admin + ${#PORTS_ALT_HTTP[@]} alt-http ports"

# ── Run naabu ────────────────────────────────────────────────────────────────
scan_out="$SCAN_DIR/scan_$(date -u +%Y%m%dT%H%M%SZ).jsonl"
log "naabu: rate=$PORTSCAN_RATE pkt/s  timeout=${PORTSCAN_TIMEOUT}s  ports=$(echo "$ALL_PORTS" | tr ',' '\n' | wc -l)"

timeout --kill-after=60 "$PORTSCAN_MAX_RUNTIME" \
  "$NAABU_BIN" \
    -list "$host_list" \
    -p "$ALL_PORTS" \
    -rate "$PORTSCAN_RATE" \
    -timeout "$PORTSCAN_TIMEOUT" \
    -retries "$PORTSCAN_RETRIES" \
    -json \
    -silent \
    -c 25 \
  > "$scan_out" 2>/dev/null || warn "naabu exited non-zero (partial results kept)"

rm -f "$host_list"

if [[ ! -s "$scan_out" ]]; then
  log "No open ports found this cycle"
  # Still update portscan_at for scanned hosts (no cooldown re-scan)
  _update_scanned_at() {
    printf '%s' "$resp" | jq -r '.hits.hits[]._id' | while read -r doc_id; do
      es_curl -H 'Content-Type: application/json' \
        -X POST "$ES_URL/$INDEX_NAME/_update/$doc_id" \
        -d '{"doc":{"portscan_at":"'"$(date -u '+%Y-%m-%dT%H:%M:%SZ')"'","portscan_open_ports":[],"portscan_critical":false}}' \
        2>/dev/null | grep -q '"result"' || true
    done
  }
  _update_scanned_at
  exit 0
fi

nfindings="$(wc -l < "$scan_out" | tr -d ' ')"
log "naabu found $nfindings open port(s)"

# ── Group results by host ─────────────────────────────────────────────────────
# naabu JSON per line: {"ip":"...","port":...,"host":"..."}
declare -A HOST_PORTS        # host → space-separated port list
declare -A HOST_CRITICAL     # host → 1 if any critical port
declare -A HOST_TIER         # host → max tier (critical/admin/althttp)
declare -A HOST_IP           # host → resolved IP (for CDN dedup)
declare -A IP_PORT_HITS      # "ip:port" → count of distinct hosts sharing it

while IFS= read -r line; do
  h="$(printf '%s' "$line" | jq -r '.host // empty' 2>/dev/null)"
  p="$(printf '%s' "$line" | jq -r '.port // empty' 2>/dev/null)"
  ip="$(printf '%s' "$line" | jq -r '.ip // empty' 2>/dev/null)"
  [[ -z "$h" || -z "$p" ]] && continue

  HOST_PORTS[$h]="${HOST_PORTS[$h]:-} $p"
  [[ -n "$ip" ]] && HOST_IP[$h]="$ip"
  [[ -n "$ip" ]] && IP_PORT_HITS["${ip}:${p}"]=$(( ${IP_PORT_HITS["${ip}:${p}"]:-0} + 1 ))

  if [[ "$CRITICAL_SET" == *" $p "* ]]; then
    HOST_CRITICAL[$h]=1
    HOST_TIER[$h]="critical"
  elif [[ "$ADMIN_SET" == *" $p "* ]]; then
    [[ "${HOST_TIER[$h]:-}" != "critical" ]] && HOST_TIER[$h]="admin"
  else
    [[ -z "${HOST_TIER[$h]:-}" ]] && HOST_TIER[$h]="althttp"
  fi
done < "$scan_out"

# ── CDN verification: filter shared-IP CDN edges and httpx-confirmed CDN ─────
# Pass 1 — IP dedup: if the same IP:port is shared by 3+ different hosts it is
# almost certainly a CDN edge node (Fastly/Cloudflare shared infra), not per-
# host exposure.  Removes e.g. *.shopify.com all hitting the same Fastly IP.
for _cdnhost in "${!HOST_PORTS[@]}"; do
  _cdnip="${HOST_IP[$_cdnhost]:-}"
  _clean_ports=""
  for _cdnp in ${HOST_PORTS[$_cdnhost]}; do
    _cnt="${IP_PORT_HITS["${_cdnip}:${_cdnp}"]:-1}"
    if [[ -n "$_cdnip" && "$_cnt" -ge 3 ]]; then
      log "  CDN-dedup: $_cdnhost:$_cdnp (IP $_cdnip shared by $_cnt hosts — CDN edge)"
    else
      _clean_ports="$_clean_ports $_cdnp"
    fi
  done
  _clean_ports="${_clean_ports# }"   # strip leading space
  if [[ -z "$_clean_ports" ]]; then
    unset "HOST_PORTS[$_cdnhost]" "HOST_CRITICAL[$_cdnhost]" "HOST_TIER[$_cdnhost]" 2>/dev/null || true
    es_curl -H 'Content-Type: application/json' \
      -X POST "$ES_URL/$INDEX_NAME/_update/$_cdnhost" \
      -d "$(jq -nc --arg n "$now_iso" '{"doc":{"cdn_name":"portscan-cdn","portscan_at":$n}}')" \
      2>/dev/null > /dev/null || true
  else
    HOST_PORTS[$_cdnhost]="$_clean_ports"
  fi
done

# Pass 2 — httpx CDN check: for remaining HTTP-tier findings, run httpx with
# -cdn to catch CDN fronting that IP-dedup missed (single-host CDN aliases,
# per-region anycast where each host has a different edge IP).
HTTPX_BIN="${HTTPX_BIN:-$(command -v httpx 2>/dev/null || echo '')}"
if [[ -n "$HTTPX_BIN" && "${#HOST_PORTS[@]}" -gt 0 ]]; then
  _vtmp="$(mktemp)"; _vout="$(mktemp)"
  for _vh in "${!HOST_PORTS[@]}"; do
    for _vp in ${HOST_PORTS[$_vh]}; do
      _vsc="http"
      [[ "$_vp" =~ ^(8443|443|2376|5001)$ ]] && _vsc="https"
      printf '%s://%s:%s\n' "$_vsc" "$_vh" "$_vp"
    done
  done | sort -u > "$_vtmp"

  timeout 120 "$HTTPX_BIN" -list "$_vtmp" -cdn -silent -json -timeout 8 \
    >> "$_vout" 2>/dev/null || true
  rm -f "$_vtmp"

  while IFS= read -r _vl; do
    # httpx CDN field is boolean .cdn or non-empty string ."cdn-name"
    _vc="$(printf '%s' "$_vl" | jq -r \
      'if (.cdn==true) or (."cdn-name"//""!="") then "cdn" else "ok" end' 2>/dev/null)"
    [[ "$_vc" != "cdn" ]] && continue
    # Extract host — httpx may report as .host or inside .url
    _vh2="$(printf '%s' "$_vl" | jq -r '.host // empty' 2>/dev/null)"
    [[ -z "$_vh2" ]] && \
      _vh2="$(printf '%s' "$_vl" | jq -r '.url // empty' 2>/dev/null | \
              sed -E 's|^https?://||;s|:[0-9]+(/.*)?$||')"
    _vp2="$(printf '%s' "$_vl" | jq -r '(.port // 0) | tostring' 2>/dev/null)"
    [[ -z "$_vh2" ]] && continue
    log "  CDN-httpx: $_vh2:$_vp2 (CDN-fronted — filtered)"
    _vrem=""
    for _vpp in ${HOST_PORTS[$_vh2]:-}; do
      [[ "$_vpp" == "$_vp2" ]] || _vrem="$_vrem $_vpp"
    done
    _vrem="${_vrem# }"
    if [[ -z "$_vrem" ]]; then
      unset "HOST_PORTS[$_vh2]" "HOST_CRITICAL[$_vh2]" "HOST_TIER[$_vh2]" 2>/dev/null || true
      es_curl -H 'Content-Type: application/json' \
        -X POST "$ES_URL/$INDEX_NAME/_update/$_vh2" \
        -d "$(jq -nc --arg n "$now_iso" '{"doc":{"cdn_name":"portscan-cdn","portscan_at":$n}}')" \
        2>/dev/null > /dev/null || true
    else
      HOST_PORTS[$_vh2]="$_vrem"
      # Recalculate tier for remaining ports
      HOST_TIER[$_vh2]="althttp"; unset "HOST_CRITICAL[$_vh2]" 2>/dev/null || true
      for _vpp2 in ${HOST_PORTS[$_vh2]}; do
        if [[ "$CRITICAL_SET" == *" $_vpp2 "* ]]; then
          HOST_CRITICAL[$_vh2]=1; HOST_TIER[$_vh2]="critical"; break
        elif [[ "$ADMIN_SET" == *" $_vpp2 "* ]]; then
          [[ "${HOST_TIER[$_vh2]}" != "critical" ]] && HOST_TIER[$_vh2]="admin"
        fi
      done
    fi
  done < "$_vout"
  rm -f "$_vout"
fi

nhosts_with_findings="${#HOST_PORTS[@]}"
log "$nhosts_with_findings host(s) have open ports (after CDN filtering)"

# ── Process each host ─────────────────────────────────────────────────────────
now_iso="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

for host in "${!HOST_PORTS[@]}"; do
  ports_str="${HOST_PORTS[$host]}"
  # Build sorted unique port array
  mapfile -t port_arr < <(printf '%s' "$ports_str" | tr ' ' '\n' | grep -E '^[0-9]+$' | sort -un)
  is_critical="${HOST_CRITICAL[$host]:-0}"
  tier="${HOST_TIER[$host]:-althttp}"

  log "  $host — open ports: ${port_arr[*]} [tier=$tier]"

  # Score bonus: critical=+12, admin=+6, althttp=+3
  score_bonus=3
  [[ "$tier" == "admin" ]] && score_bonus=6
  [[ "$tier" == "critical" ]] && score_bonus=12

  # Build port signal array for triage_signals
  port_sigs="$(printf '%s\n' "${port_arr[@]}" | jq -Rs 'split("\n") | map(select(. != "") | "port:" + .) | . + ["portscan:open"]')"

  # Build ES open ports array
  ports_json="$(printf '%s\n' "${port_arr[@]}" | jq -Rs 'split("\n") | map(select(. != "") | tonumber)')"

  # Painless script: update portscan fields + append port signals to triage_signals + boost score
  painless="
    ctx._source.portscan_at = params.now;
    ctx._source.portscan_open_ports = params.ports;
    ctx._source.portscan_critical = params.critical;
    if (ctx._source.triage_signals == null) ctx._source.triage_signals = new ArrayList();
    for (sig in params.port_sigs) {
      if (!ctx._source.triage_signals.contains(sig)) ctx._source.triage_signals.add(sig);
    }
    if (ctx._source.triage_score != null) ctx._source.triage_score += params.bonus;
    // Promote priority if score now qualifies
    if (ctx._source.triage_score >= 15) ctx._source.triage_priority = 'P0';
    else if (ctx._source.triage_score >= 8) ctx._source.triage_priority = 'P1';
  "

  update_body="$(jq -nc \
    --arg now "$now_iso" \
    --argjson ports "$ports_json" \
    --argjson critical "${is_critical}" \
    --argjson port_sigs "$port_sigs" \
    --argjson bonus "$score_bonus" \
    --arg script "$painless" '{
      script: {lang:"painless", source:$script,
        params:{now:$now, ports:$ports, critical:$critical, port_sigs:$port_sigs, bonus:$bonus}}
    }')"

  update_result="$(es_curl -H 'Content-Type: application/json' \
    -X POST "$ES_URL/$INDEX_NAME/_update/$host" \
    -d "$update_body" 2>/dev/null)"

  if ! printf '%s' "$update_result" | grep -q '"result"'; then
    warn "ES update failed for $host: $update_result"
  fi

  # ── Discord alert for critical/admin finds ────────────────────────────────
  if [[ "$tier" == "critical" || "$tier" == "admin" ]]; then
    svc_list=""
    for p in "${port_arr[@]}"; do
      svc="${SVC_NAME[$p]:-port-$p}"
      if [[ "$CRITICAL_SET" == *" $p "* ]]; then
        svc_list="${svc_list}🔴 **$p/$svc**  "
      elif [[ "$ADMIN_SET" == *" $p "* ]]; then
        svc_list="${svc_list}🟠 **$p/$svc**  "
      fi
    done

    emoji="🟠"; [[ "$tier" == "critical" ]] && emoji="🔴"
    discord_alert "${emoji} **PORT SCAN FIND — $host**
Services: $svc_list
Tier: \`$tier\`  Score bonus: +${score_bonus}
Run: \`recon-inspect $host\`"
  fi

  # ── Nuclei targeted sweep for services with known templates ───────────────
  if [[ -n "$NUCLEI_BIN" ]]; then
    for p in "${port_arr[@]}"; do
      tmpl="${NUCLEI_TEMPLATES[$p]:-}"
      [[ -z "$tmpl" ]] && continue
      scheme="http"; [[ "$p" == "443" || "$p" == "8443" || "$p" == "2376" ]] && scheme="https"
      target_url="${scheme}://${host}:${p}"
      log "    nuclei: $target_url → $tmpl"
      timeout 120 "$NUCLEI_BIN" \
        -target "$target_url" -t "$tmpl" \
        -silent -json \
        >> "$BASE_DIR/nuclei/portscan_confirmed.jsonl" 2>/dev/null || true
    done
  fi
done

# ── Mark zero-result hosts as scanned (prevent re-scan in cooldown) ──────────
declare -A scanned_hosts
for h in "${!HOST_PORTS[@]}"; do scanned_hosts[$h]=1; done

# Get all queried host IDs from original ES response
while IFS=$'\t' read -r doc_id h; do
  [[ -n "${scanned_hosts[$h]:-}" ]] && continue   # already updated above
  # Host had no open ports — still record the scan time
  es_curl -H 'Content-Type: application/json' \
    -X POST "$ES_URL/$INDEX_NAME/_update/$doc_id" \
    -d "$(jq -nc --arg now "$now_iso" \
      '{"doc":{"portscan_at":$now,"portscan_open_ports":[],"portscan_critical":false}}')" \
    2>/dev/null | grep -q '"result"' || true
done < <(printf '%s' "$resp" | jq -r '.hits.hits[] | [._id, ._source.host] | @tsv')

# ── Force ES refresh so recon-ports shows results immediately ─────────────────
es_curl -X POST "$ES_URL/$INDEX_NAME/_refresh" > /dev/null 2>&1 || true

# ── Summary ───────────────────────────────────────────────────────────────────
critical_hosts="${#HOST_CRITICAL[@]}"   # array length — correct even when empty
log "=== portscan cycle done ==="
log "  Scanned: $nhosts hosts"
log "  Open ports found on: $nhosts_with_findings host(s)"
log "  Critical tier: $critical_hosts host(s)"

# Keep scan output for 7 days then auto-prune
find "$SCAN_DIR" -name 'scan_*.jsonl' -mtime +7 -delete 2>/dev/null || true
find "$SCAN_DIR" -name 'hosts_*.txt' -mtime +1 -delete 2>/dev/null || true

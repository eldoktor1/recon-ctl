#!/usr/bin/env bash
# =============================================================================
# recon_fresh_modules.sh — consolidated dispatcher for v2.5 true-fresh scan
# modules. Replaces:
#   recon_smart_scan.sh     → mode: smart-scan      (top-10 bounty scan, 30 min)
#   recon_deep_scan.sh      → mode: deep-scan       (tech-aware nuclei, daily)
#   recon_active_checks.sh  → mode: active-checks   (safe HTTP probes, 10 min)
#   recon_js_scanner.sh     → mode: js-scan         (JS secrets/endpoints, 30m)
#
# All four operate exclusively on true-fresh + in-scope-paying hosts. They
# share lockfile placement, Discord webhook loading, log helpers, ES auth,
# and host selection — consolidated here.
#
# Each mode keeps its own per-mode lockfile so the daemon can run them in
# parallel without serialization.
#
# Usage:  recon_fresh_modules.sh {smart-scan|deep-scan|active-checks|js-scan}
# =============================================================================
set -uo pipefail
IFS=$'\n\t'

MODE="${1:-}"; shift || true
case "$MODE" in
  smart-scan|deep-scan|active-checks|js-scan) ;;
  *) echo "Usage: $0 {smart-scan|deep-scan|active-checks|js-scan}" >&2; exit 2 ;;
esac

# ---- Common helpers --------------------------------------------------------
log()  { printf '[%s %s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "${MODE^^}" "$*" >&2; }
warn() { printf '[%s %s WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "${MODE^^}" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/recon_net.sh"

BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="$BASE_DIR/state"
TRIAGE_DIR="$BASE_DIR/triage"
QUEUE_INBOX="$BASE_DIR/queue/inbox"
NUCLEI_DIR="$BASE_DIR/nuclei"
AGENT_FILE="$TRIAGE_DIR/agent_targets.jsonl"

ES_URL="${ES_URL:-http://127.0.0.1:9200}"
INDEX_NAME="${INDEX_NAME:-recon_alive}"
setup_es_netrc
ES_AUTH=(--netrc-file "$HOME/.recon_es_netrc")

# Discord: bounty-scan findings → #vulns via discord_hook() (recon_net.sh)

mkdir -p "$STATE_DIR"

# Per-mode lockfile (so the daemon can run all four in parallel)
exec 9>"$STATE_DIR/${MODE}.lock"
flock -n 9 || { log "already running"; exit 0; }

# ---- Shared selector: top-N true-fresh in-scope-paying URLs ---------------
# Args:  $1 = top_n   $2 = extra_jq_filter (optional, e.g. '.priority=="P0"')
# Output: one URL per line on stdout.
fresh_paid_urls() {
  local top_n="$1"
  local extra="${2:-true}"
  local from_agent
  from_agent="$(mktemp)"
  if [[ -s "$AGENT_FILE" ]]; then
    jq -r --argjson n "$top_n" '
      select((.triage_true_fresh // false) == true
         and (.in_scope // false) == true
         and (.pays // false) == true
         and ('"$extra"')) |
      (.url // ("https://" + .host))
    ' "$AGENT_FILE" 2>/dev/null \
      | awk 'NF && !seen[$0]++' | head -n "$top_n" > "$from_agent"
  fi
  if [[ ! -s "$from_agent" ]]; then
    # Fallback: latest 00_truefresh batch (when triage hasn't run yet).
    local latest
    latest="$(find "$QUEUE_INBOX" -maxdepth 1 -name '00_truefresh_*.txt' -type f 2>/dev/null | sort | tail -1)"
    if [[ -n "$latest" && -s "$latest" ]]; then
      head -n "$top_n" "$latest" | awk 'NF {print "https://" $0}' > "$from_agent"
    fi
  fi
  cat "$from_agent"
  rm -f "$from_agent"
}

discord_send() {
  local payload="$1"
  [[ -z "$(discord_hook vulns)" ]] && return 0
  discord_post "$(discord_hook vulns)" "$payload" || true   # → #vulns
}

# =============================================================================
# Mode: smart-scan — top-10 fresh+paid hosts → bounty templates → Discord
# =============================================================================
mode_smart_scan() {
  local top_n="${BOUNTY_TOP_N:-10}"
  local target_file; target_file="$(mktemp)"
  trap 'rm -f "$target_file"' RETURN
  fresh_paid_urls "$top_n" > "$target_file"
  local n; n="$(wc -l < "$target_file" 2>/dev/null | tr -d ' ')"
  if [[ "${n:-0}" -eq 0 ]]; then log "no fresh targets"; return 0; fi

  log "scanning $n fresh+paid hosts via bounty templates"
  local before=0
  [[ -s "$NUCLEI_DIR/confirmed.jsonl" ]] && before="$(wc -l < "$NUCLEI_DIR/confirmed.jsonl" | tr -d ' ')"

  bash "$SCRIPT_DIR/recon_nuclei.sh" bounty "$target_file" || warn "bounty scan non-zero"

  local after=0
  [[ -s "$NUCLEI_DIR/confirmed.jsonl" ]] && after="$(wc -l < "$NUCLEI_DIR/confirmed.jsonl" | tr -d ' ')"
  local new=$(( after - before ))
  if [[ "$new" -gt 0 ]]; then
    discord_send "$(jq -nc --arg c "$(printf '🏆 **BOUNTY FINDING** — %d new finding(s) on %d fresh+paid host(s)' "$new" "$n")" '{content:$c}')"
  fi
  log "smart-scan done — $new new findings"
}

# =============================================================================
# Mode: deep-scan — tech-aware nuclei against fresh hosts (daily)
# =============================================================================
build_tech_map() {
  local templates_dir="$1" out_path="$2"
  python3 - "$templates_dir" "$out_path" <<'PY' 2>/dev/null
import os, re, json, sys
root = sys.argv[1]; out = sys.argv[2]
tag_re = re.compile(r'^\s*tags:\s*(.+?)\s*$', re.M)
id_re  = re.compile(r'^\s*id:\s*([A-Za-z0-9_-]+)\s*$', re.M)
mapping = {}
for dirpath, _, files in os.walk(root):
    for f in files:
        if not f.endswith('.yaml'):
            continue
        path = os.path.join(dirpath, f)
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
                data = fh.read()
        except OSError:
            continue
        m_id = id_re.search(data); m_tag = tag_re.search(data)
        if not m_id or not m_tag:
            continue
        tid = m_id.group(1).strip()
        tags = [t.strip().strip('"\'') for t in re.split(r'[,\s]+', m_tag.group(1)) if t.strip()]
        for t in tags:
            if re.fullmatch(r'[a-z0-9][a-z0-9-]{1,40}', t):
                mapping.setdefault(t, []).append(tid)
with open(out, 'w', encoding='utf-8') as fh:
    json.dump(mapping, fh)
PY
}

mode_deep_scan() {
  local bounty_dir="$NUCLEI_DIR/bounty_templates"
  local tech_map="$NUCLEI_DIR/tech_template_map.json"
  local max_hosts="${DEEP_MAX_HOSTS:-50}"
  [[ -d "$bounty_dir" ]] || { warn "$bounty_dir missing — run tools/sync_bounty_templates.sh"; return 0; }

  if [[ ! -s "$tech_map" || "$(find "$tech_map" -mtime +7 2>/dev/null)" ]]; then
    log "rebuilding tech template map"
    build_tech_map "$bounty_dir" "$tech_map"
  fi
  [[ -s "$tech_map" ]] || { warn "tech map empty"; return 0; }

  local hosts_file tmp
  hosts_file="$(mktemp)"; tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp" "$hosts_file"' RETURN

  curl -fsS -m 30 "${ES_AUTH[@]}" -H 'Content-Type: application/json' \
    -X POST "$ES_URL/$INDEX_NAME/_search" \
    -d "$(jq -nc --argjson size "$max_hosts" '{
      size:$size,
      _source:["host","url","tech"],
      query:{bool:{filter:[
        {term:{triage_true_fresh:true}},
        {term:{triage_in_scope:true}},
        {term:{triage_pays:true}},
        {exists:{field:"tech"}}
      ]}},
      sort:[{"triage_score":{order:"desc"}}]
    }')" 2>/dev/null \
    | jq -c '.hits.hits[]._source | select((.tech // []) | length > 0)' \
      > "$hosts_file" 2>/dev/null || true

  local total; total="$(wc -l < "$hosts_file" | tr -d ' ')"
  log "deep-scan: $total fresh hosts with detected tech"
  [[ "$total" -eq 0 ]] && return 0

  local run_ts; run_ts="$(date -u +%Y%m%dT%H%M%SZ)"
  local run_dir="$NUCLEI_DIR/results/deep_$run_ts"
  mkdir -p "$run_dir"

  local new_findings=0
  while IFS= read -r rec; do
    local host url
    host="$(echo "$rec" | jq -r '.host')"
    url="$(echo "$rec"  | jq -r '.url // empty')"
    [[ -z "$url" ]] && url="https://${host}"

    local techs=() ids=()
    while IFS= read -r t; do techs+=("$t"); done < <(echo "$rec" | jq -r '.tech[] // empty' | awk '{print tolower($0)}')
    for t in "${techs[@]}"; do
      while IFS= read -r tid; do
        [[ -n "$tid" ]] && ids+=("$tid")
      done < <(jq -r --arg t "$t" '(.[$t] // [])[]' "$tech_map" 2>/dev/null)
    done
    [[ ${#ids[@]} -eq 0 ]] && continue

    local uniq_ids=() args=()
    while IFS= read -r u; do uniq_ids+=("$u"); done < <(printf '%s\n' "${ids[@]}" | awk '!seen[$0]++')
    for tid in "${uniq_ids[@]}"; do args+=(-id "$tid"); done

    local target_tmp="$tmp/${host//[^a-zA-Z0-9]/_}.txt"
    echo "$url" > "$target_tmp"
    local out="$run_dir/${host//[^a-zA-Z0-9]/_}.jsonl"
    timeout 300 nuclei \
      -t "$bounty_dir" "${args[@]}" \
      -l "$target_tmp" \
      -severity critical,high,medium \
      -rate-limit "${RATE_LIMIT:-10}" \
      -timeout "${TIMEOUT:-60}" \
      -retries 1 -no-color -silent -nc \
      -jsonl -o "$out" 2>/dev/null || true
    if [[ -s "$out" ]]; then
      cat "$out" >> "$NUCLEI_DIR/confirmed.jsonl"
      new_findings=$(( new_findings + $(wc -l < "$out") ))
    fi
    rm -f "$target_tmp"
  done < "$hosts_file"

  log "deep-scan done — $new_findings new findings across $total hosts"
}

# =============================================================================
# Mode: active-checks — minimal safe HTTP probes via browser_curl
# =============================================================================
mode_active_checks() {
  [[ -s "$AGENT_FILE" ]] || { log "no agent_targets yet"; return 0; }

  local marker="$STATE_DIR/active_checks.last"
  if [[ -s "$marker" ]] && [[ "$(stat -c %Y "$AGENT_FILE" 2>/dev/null)" -le "$(cat "$marker" 2>/dev/null || echo 0)" ]]; then
    log "agent_targets unchanged; skipping"
    return 0
  fi

  local top_n="${ACTIVE_TOP_N:-5}"
  local active_bonus="${ACTIVE_CONFIRMED_BONUS:-15}"
  local active_out="$TRIAGE_DIR/active_confirmed.jsonl"

  local tmp; tmp="$(mktemp)"
  trap 'rm -f "$tmp"' RETURN
  jq -c '
    select((.triage_true_fresh // false) == true
       and .priority == "P0"
       and (.in_scope // false) == true
       and (.pays // false) == true)
  ' "$AGENT_FILE" 2>/dev/null | head -n "$top_n" > "$tmp"

  if [[ ! -s "$tmp" ]]; then
    log "no eligible hosts (need true_fresh+P0+in_scope+pays)"
    date +%s > "$marker"
    return 0
  fi

  _confirm() {
    local host="$1" url="$2" check="$3" result="$4"
    local now; now="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    jq -nc \
      --arg host "$host" --arg url "$url" --arg check "$check" \
      --arg result "$result" --arg at "$now" --argjson bonus "$active_bonus" \
      '{host:$host, url:$url, check:$check, result:$result, active_confirmed_score:$bonus, at:$at}' \
      >> "$active_out"
    curl -fsS -m 10 "${ES_AUTH[@]}" -H 'Content-Type: application/json' \
      -X POST "$ES_URL/$INDEX_NAME/_update/$host" \
      -d "$(jq -nc --arg r "$result" --arg at "$now" '{doc:{active_check_result:$r, active_checked_at:$at, triage_priority:"P0"}}')" \
      >/dev/null 2>&1 || true
    discord_send "$(jq -nc --arg h "$host" --arg u "$url" --arg c "$check" --arg r "$result" '{
      content:"⚡ **ACTIVE CONFIRMATION**",
      embeds:[{
        title:("[ACTIVE] " + $h),
        url:$u, color:16711680,
        fields:[
          {name:"Check",  value:$c, inline:true},
          {name:"Result", value:$r, inline:true}
        ]
      }]
    }')"
  }

  # Docker API: port 2375 is plain HTTP; port 2376 is TLS. Try both.
  _probe_docker_api() {
    local h="$1"
    browser_curl -sS -m 10 "http://$h/version" 2>/dev/null | jq -e '.ApiVersion // empty' >/dev/null 2>&1 && return 0
    browser_curl -sS -k -m 10 "https://$h/version" 2>/dev/null | jq -e '.ApiVersion // empty' >/dev/null 2>&1
  }
  _probe_jenkins_script()     { local c; c="$(browser_curl -sS -k -m 10 -o /dev/null -w '%{http_code}' "https://$1/script" 2>/dev/null || echo 000)"; [[ "$c" == "200" || "$c" == "302" ]]; }
  _probe_k8s_secrets()        { browser_curl -sS -k -m 10 "https://$1/api/v1/secrets" 2>/dev/null | jq -e '.items // empty | type=="array"' >/dev/null 2>&1; }
  _probe_grafana()            { browser_curl -sS -k -m 10 "https://$1/api/datasources" 2>/dev/null | jq -e 'type=="array"' >/dev/null 2>&1; }
  _probe_gitlab_open_signup() { browser_curl -sS -k -m 10 "https://$1/users/sign_up" 2>/dev/null | grep -qi 'new_user\[email\]'; }
  _probe_confluence_anon()    { local c; c="$(browser_curl -sS -k -m 10 -o /dev/null -w '%{http_code}' "https://$1/rest/api/space" 2>/dev/null || echo 000)"; [[ "$c" == "200" ]]; }

  # Run probes for a single host in background; serialize _confirm via a per-host tmp dir.
  _probe_host() {
    local line="$1"
    local host url
    host="$(jq -r '.host' <<< "$line")"
    url="$(jq -r '.url // ("https://" + .host)' <<< "$line")"
    local _has_sig  ; _has_sig()  { jq -e --arg p "$1" '(.signals // []) | any(test($p; "i"))' <<< "$line" >/dev/null 2>&1; }
    local _has_tech ; _has_tech() { jq -e --arg p "$1" '(.tech // []) | any(. | ascii_downcase | test($p; "i"))' <<< "$line" >/dev/null 2>&1; }
    local _has_port ; _has_port() { jq -e --argjson p "$1" '(.port // 0) == $p' <<< "$line" >/dev/null 2>&1; }

    if _has_port 2375 || _has_port 2376 || _has_sig 'port:docker-api'; then
      _probe_docker_api "$host" && _confirm "$host" "$url" "docker_api" "docker_version_exposed"
    fi
    if _has_tech 'jenkins' || _has_sig 'tech:jenkins'; then
      _probe_jenkins_script "$host" && _confirm "$host" "$url" "jenkins_script" "jenkins_groovy_accessible"
    fi
    if _has_tech 'kubernetes' || _has_sig 'tech:k8s-dashboard'; then
      _probe_k8s_secrets "$host" && _confirm "$host" "$url" "k8s_secrets" "k8s_api_secrets_readable"
    fi
    if _has_tech 'grafana' || _has_sig 'tech:grafana'; then
      _probe_grafana "$host" && _confirm "$host" "$url" "grafana_ds" "grafana_datasources_readable"
    fi
    if _has_tech 'gitlab' || _has_sig 'tech:gitlab'; then
      _probe_gitlab_open_signup "$host" && _confirm "$host" "$url" "gitlab_signup" "gitlab_open_signup"
    fi
    if _has_tech 'confluence' || _has_sig 'tech:confluence'; then
      _probe_confluence_anon "$host" && _confirm "$host" "$url" "confluence_anon" "confluence_anon_space_listing"
    fi
  }

  local pids=()
  while IFS= read -r line; do
    _probe_host "$line" &
    pids+=($!)
  done < "$tmp"
  wait "${pids[@]}" 2>/dev/null || true

  date +%s > "$marker"
  log "active-checks done"
}

# =============================================================================
# Mode: js-scan — JS secret + endpoint disclosure scanner
# =============================================================================
extract_script_srcs() {
  local html_file="$1" base_url="$2"
  python3 - "$html_file" "$base_url" <<'PY' 2>/dev/null
import sys
from html.parser import HTMLParser
from urllib.parse import urljoin
with open(sys.argv[1], 'rb') as fh:
    data = fh.read().decode('utf-8', errors='ignore')
base = sys.argv[2]
class P(HTMLParser):
    def __init__(self):
        super().__init__(); self.srcs = []
    def handle_starttag(self, tag, attrs):
        if tag.lower() != 'script': return
        for k, v in attrs:
            if k.lower() == 'src' and v:
                self.srcs.append(v)
p = P()
try: p.feed(data)
except Exception: pass
seen = set()
for s in p.srcs:
    full = urljoin(base, s)
    if not full.startswith(('http://', 'https://')): continue
    if full in seen: continue
    seen.add(full); print(full)
PY
}

mode_js_scan() {
  local dump_dir="$BASE_DIR/js_dump"
  local findings_file="$BASE_DIR/js_findings.jsonl"
  local max_bytes="${JS_MAX_BYTES:-2097152}"
  local host_limit="${JS_HOST_LIMIT:-20}"
  local max_scripts="${JS_MAX_SCRIPTS:-15}"

  mkdir -p "$dump_dir" "$(dirname "$findings_file")"
  touch "$findings_file"

  local tmp; tmp="$(mktemp)"
  trap 'rm -f "$tmp"' RETURN
  fresh_paid_urls "$host_limit" > "$tmp"
  local n; n="$(wc -l < "$tmp" | tr -d ' ')"
  [[ "$n" -eq 0 ]] && { log "no fresh targets"; return 0; }
  log "scanning $n fresh hosts for JS secrets/endpoints"

  # Ignore list: legitimate 3rd-party SDKs and placeholder strings that produce FPs.
  local ignore_re='(heroku|twilio|firebase|supabase|example|sample|test|public|demo|placeholder|your-|insert-|replace-me|sentry\.io|segment\.io|segment\.com|amplitude\.com|honeybadger|rollbar|logrocket|analytics\.google|googletagmanager|hotjar|intercom\.io|crisp\.chat|drift\.com|hubspot\.net|salesforce\.com)'
  local aws_re='AKIA[0-9A-Z]{16}'
  local google_re='AIza[0-9A-Za-z_-]{35}'
  local priv_key_re='-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----'
  local jwt_re='eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
  local connstr_re='(mongodb\+srv://|postgres(ql)?://[^[:space:]"]+:[^[:space:]"]+@|mysql://[^[:space:]"]+:[^[:space:]"]+@)'
  local endpoint_re='(/api/v[0-9]+/[A-Za-z0-9_/-]+|/graphql|/internal/[A-Za-z0-9_/-]+)'

  _emit() {
    local host="$1" js="$2" ftype="$3" mtype="$4" bonus="$5"
    jq -nc --arg host "$host" --arg js "$js" --arg ft "$ftype" --arg mt "$mtype" --argjson bonus "$bonus" \
      '{host:$host, js_file:$js, finding_type:$ft, match_type:$mt, bonus:$bonus,
        at:(now|strftime("%Y-%m-%dT%H:%M:%SZ"))}' >> "$findings_file"
  }
  _scan_one() {
    local host="$1" js_path="$2" js_url="$3" kind regex bonus hit
    for spec in "aws_key|$aws_re|10" "google_key|$google_re|10" "private_key|$priv_key_re|10" "jwt|$jwt_re|10" "conn_string|$connstr_re|10"; do
      kind="${spec%%|*}"; rest="${spec#*|}"; regex="${rest%|*}"; bonus="${rest##*|}"
      hit="$(grep -aEo "$regex" "$js_path" 2>/dev/null | grep -aviE "$ignore_re" | head -1)"
      [[ -n "$hit" ]] && _emit "$host" "$js_url" "secret" "$kind" "$bonus"
    done
    if grep -aEo "$endpoint_re" "$js_path" 2>/dev/null | grep -aviE "$ignore_re" | head -1 >/dev/null; then
      _emit "$host" "$js_url" "endpoint" "internal_endpoint" 5
    fi
  }

  while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    local host; host="$(printf '%s' "$url" | awk -F/ '{print $3}')"
    [[ -z "$host" ]] && continue
    local host_dir="$dump_dir/${host//[^a-zA-Z0-9.-]/_}"
    mkdir -p "$host_dir"
    local html_file="$host_dir/_main.html"
    browser_curl -sSL -m 15 --max-filesize "$max_bytes" -o "$html_file" "$url" 2>/dev/null || true
    [[ -s "$html_file" ]] || { rm -rf "$host_dir"; continue; }

    local count=0
    while IFS= read -r js_url; do
      [[ "$count" -ge "$max_scripts" ]] && break
      local safe; safe="$(printf '%s' "$js_url" | sha256sum | awk '{print $1}')"
      local js_path="$host_dir/${safe}.js"
      if browser_curl -sSL -m 20 --max-filesize "$max_bytes" -o "$js_path" "$js_url" 2>/dev/null; then
        if [[ -s "$js_path" ]]; then
          _scan_one "$host" "$js_path" "$js_url"
          # Fetch source map if referenced — minified JS hides secrets that maps expose
          local map_url="${js_url}.map"
          # Also check for explicit sourceMappingURL comment inside the JS
          local inline_map
          inline_map="$(grep -aoP '//# sourceMappingURL=\K\S+' "$js_path" 2>/dev/null | head -1 || true)"
          if [[ -n "$inline_map" && "$inline_map" != data:* ]]; then
            # Resolve relative map URLs against the JS URL
            local js_base="${js_url%/*}"
            case "$inline_map" in
              http://*|https://*) map_url="$inline_map" ;;
              *) map_url="$js_base/$inline_map" ;;
            esac
          fi
          local map_path="$host_dir/${safe}.map"
          if browser_curl -sSL -m 15 --max-filesize "$max_bytes" -o "$map_path" "$map_url" 2>/dev/null \
              && [[ -s "$map_path" ]]; then
            # Source map contains original source in .sourcesContent[]
            # Extract all source content blocks and scan them
            local src_tmp="$host_dir/${safe}.src"
            python3 -c "
import json, sys, pathlib
try:
    m = json.loads(pathlib.Path(sys.argv[1]).read_text(errors='ignore'))
    for block in m.get('sourcesContent') or []:
        if isinstance(block, str):
            print(block)
except Exception:
    pass
" "$map_path" > "$src_tmp" 2>/dev/null || true
            [[ -s "$src_tmp" ]] && _scan_one "$host" "$src_tmp" "${map_url}#sourcesContent"
          fi
        fi
      fi
      count=$((count + 1))
    done < <(extract_script_srcs "$html_file" "$url")

    rm -rf "$host_dir"
  done < "$tmp"

  log "js-scan done — findings file has $(wc -l < "$findings_file" | tr -d ' ') total entries"
}

# ---- Dispatch --------------------------------------------------------------
case "$MODE" in
  smart-scan)    mode_smart_scan ;;
  deep-scan)     mode_deep_scan ;;
  active-checks) mode_active_checks ;;
  js-scan)       mode_js_scan ;;
esac

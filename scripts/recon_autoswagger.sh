#!/usr/bin/env bash
# =============================================================================
# recon_autoswagger.sh — unauth Swagger/OpenAPI BOLA/broken-authz discovery lane
#
# THE EDGE: bare API gateways / headless backends that ship a Swagger/OpenAPI spec advertise
# their whole route table. The crowd flags "swagger exposed" (Info/dup). We READ the spec and
# hit every documented endpoint UNAUTHENTICATED, GET-only — a 200 that shouldn't answer without
# auth, screened for PII/secrets/oversized payloads, is a provenance-confirmed broken-authz LEAD
# (same rigor as recon_idor_candidates.py). Complements recon-kr (routes on bare gateways) and
# native GraphQL schema-reasoning: same "read the spec, reason over what shouldn't be reachable
# unauth" idea, for REST/Swagger. Backend = Autoswagger (intruder-io/autoswagger, ADOPT'd
# 2026-07-18). KB: docs/knowledge/tool-autoswagger.md.
#
# SAFETY (safe-probe doctrine): UNAUTHENTICATED + GET-only + non-mutating + no creds — never the
# `-risk` mutating-method mode (we NEVER enable that autonomously). Everything it surfaces is a
# LEAD; a 200 needing more than "this endpoint answers unauth" (real cross-object IDOR/BOLA) is
# Claude-VERIFY + human 2-owned-account swap (hard line — never enumerate third-party IDs). Anti-
# burn: bounded batch, per-host cooldown, in-scope+pays gate, Mullvad via run_scanner.
#
# GRACEFUL NO-OP: if the `autoswagger` binary is not installed, the lane logs a one-line install
# hint and exits 0 (never fails the daemon). Install is the OPERATOR's call — this script never
# installs anything. See tool-autoswagger.md for the command.
#
# OUTPUT: briefings/autoswagger_candidates_<date>.md + autoswagger_worklist.jsonl + the jsintel
# endpoints feedstock (→ IDOR/BAC ranker) + ES stamp; surfaced in the 6:30 briefing.
#
# USAGE: recon_autoswagger.sh [scan] | check <host-or-url> | results [N]
# =============================================================================
set -uo pipefail
IFS=$'\n\t'
log()  { printf '[%s AUTOSWAGGER] %s\n'      "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s AUTOSWAGGER WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/recon_net.sh"
setup_es_netrc
ES_AUTH=(--netrc-file "$HOME/.recon_es_netrc")

BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"
INDEX_NAME="${INDEX_NAME:-recon_alive}"
SCOPE_CHECK="${SCOPE_CHECK:-$SCRIPT_DIR/recon_scope_check.sh}"
JSINTEL="${JSINTEL:-$BASE_DIR/js_recon/endpoints.jsonl}"   # shared endpoints feedstock (→ IDOR ranker)
BRIEF_DIR="${BRIEF_DIR:-$BASE_DIR/briefings}"

AS_DIR="$BASE_DIR/autoswagger"
WORKLIST="$AS_DIR/autoswagger_worklist.jsonl"
SCANNED="$AS_DIR/scanned.tsv"          # host<TAB>epoch (dedup/cooldown ledger)
WORK="$AS_DIR/work"
LOCK_FILE="$STATE_DIR/autoswagger.lock"

# ---- killswitch: `touch state/kill/v2_autoswagger` pauses the lane (matches the other v2_* lanes) ----
KILLSWITCH="${KILLSWITCH:-$STATE_DIR/kill/v2_autoswagger}"

AS_BIN="${AS_BIN:-$(command -v autoswagger 2>/dev/null || echo "$HOME/.local/bin/autoswagger")}"
AS_BATCH="${AS_BATCH:-40}"              # candidate hosts probed per cycle
AS_COOLDOWN_DAYS="${AS_COOLDOWN_DAYS:-7}"
AS_TIMEOUT="${AS_TIMEOUT:-90}"          # per-host wall-clock cap
# common spec locations Autoswagger brute-forces when jsintel gives only a host (it also parses
# Swagger-UI pages); kept small + bounded so a non-API host stays cheap.
AS_SPEC_PATHS="${AS_SPEC_PATHS:-/swagger.json /openapi.json /v2/api-docs /v3/api-docs /api-docs /swagger/v1/swagger.json /openapi.yaml /swagger.yaml}"

mkdir -p "$AS_DIR" "$WORK" "$BRIEF_DIR" "$STATE_DIR" 2>/dev/null || true
touch "$WORKLIST" "$SCANNED" 2>/dev/null || true
command -v jq >/dev/null 2>&1 || { warn "jq missing"; exit 0; }

vpn_gate()  { [[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down — refusing target-facing autoswagger work"; exit 0; }; }
kill_gate() { [[ -f "$KILLSWITCH" ]] && { log "killswitch v2_autoswagger present — paused"; exit 0; }; }
es_curl()   { curl -sS -m30 "${ES_AUTH[@]}" -H 'Content-Type: application/json' "$@"; }

# ---- tool presence: no-op gracefully if Autoswagger is not installed (operator installs it) ----
have_autoswagger() {
  [[ -x "$AS_BIN" ]] && return 0
  command -v autoswagger >/dev/null 2>&1 && { AS_BIN="$(command -v autoswagger)"; return 0; }
  return 1
}
require_autoswagger() {
  have_autoswagger && return 0
  log "autoswagger not installed — lane is a NO-OP. Install (operator):"
  log "    pipx install git+https://github.com/intruder-io/autoswagger.git"
  log "    (or: git clone https://github.com/intruder-io/autoswagger && pip install -r requirements.txt)"
  log "  then set AS_BIN or put 'autoswagger' on PATH. See docs/knowledge/tool-autoswagger.md."
  return 1
}

# ---- candidate host discovery (in-scope provenance, dup-resistant) ----
# A) jsintel endpoints that reference a swagger/openapi spec; B) ES recon_alive in-scope hosts whose
# url/title/tech signal a spec (swagger-ui, openapi, api-docs). Emits: host<TAB>program on stdout.
discover_hosts() {
  # A) jsintel spec references
  if [[ -s "$JSINTEL" ]]; then
    jq -rc 'select((.endpoint//"")|test("swagger|openapi|api-docs";"i")) | [.host,(.program//"")] | @tsv' "$JSINTEL" 2>/dev/null \
      | awk -F'\t' 'NF{print}'
  fi
  # B) ES recon_alive: in-scope + not benched, url/title/tech ~ swagger/openapi
  local q resp
  q='{"size":1500,"_source":["host","triage_program"],
      "query":{"bool":{
        "filter":[{"term":{"triage_in_scope":true}}],
        "must_not":[{"range":{"ignore_expires_at":{"gt":"now"}}}],
        "minimum_should_match":1,
        "should":[{"wildcard":{"url":"*swagger*"}},{"wildcard":{"url":"*openapi*"}},
                  {"wildcard":{"url":"*api-docs*"}},{"match":{"title":"swagger"}},
                  {"match":{"tech":"swagger"}},{"match":{"tech":"openapi"}}]}}}'
  resp="$(es_curl -X POST "$ES_URL/$INDEX_NAME/_search" -d "$q" 2>/dev/null)" || resp=""
  printf '%s' "$resp" | jq -rc '.hits.hits[]?._source | [.host,(.triage_program//"")] | @tsv' 2>/dev/null \
    | awk -F'\t' 'NF{print}'
}

# ---- run Autoswagger against ONE host, GET-only, unauth. Emits compact JSON per unauth-reachable
# endpoint hit on stdout: {endpoint,status,flags[]}. Empty if no spec / nothing reachable. The exact
# Autoswagger CLI/JSON shape is version-dependent (young project) — parse defensively, never fail hard.
autoswagger_host() {   # $1=host $2=program
  local host="$1"
  local base="https://${host}"
  # GET-only, no creds, no mutating -risk flag. -o json requested; tolerate plain output.
  local out
  out="$(timeout "$AS_TIMEOUT" "$AS_BIN" -u "$base" --format json 2>/dev/null)" || out=""
  [[ -z "$out" ]] && return 0
  # Best-effort: pull an array of endpoint results if the tool emits JSON; otherwise skip (LEAD-only,
  # never fabricate). We look for objects carrying a path/url + status + any pii/secret/interesting flag.
  printf '%s' "$out" | jq -c '
      ( if type=="array" then . elif (.results?|type=="array") then .results elif (.findings?|type=="array") then .findings else [] end )
      | .[]? | select((.status//.status_code//0) >= 200 and (.status//.status_code//0) < 400)
      | {endpoint:(.url // .path // .endpoint // ""),
         status:(.status // .status_code // 0),
         flags:([ (if (.pii//false) then "pii" else empty end),
                  (if (.secrets//.secret//false) then "secrets" else empty end),
                  (if (.interesting//.oversized//false) then "interesting" else empty end) ])}
      | select(.endpoint != "")' 2>/dev/null || true
}

# ---- append discovered endpoints into the jsintel feedstock (→ IDOR/BAC ranker) ----
feed_endpoints() {   # $1=host $2=program ; reads compact endpoint JSON on stdin
  [[ -s "$JSINTEL" || -f "$JSINTEL" ]] || return 0
  local host="$1" prog="$2" now; now="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  while IFS= read -r rec; do
    [[ -z "$rec" ]] && continue
    local ep; ep="$(jq -r '.endpoint' <<<"$rec")"; [[ -z "$ep" ]] && continue
    jq -nc --arg h "$host" --arg e "$ep" --arg p "$prog" --arg t "$now" \
      '{host:$h,endpoint:$e,program:$p,source:"autoswagger",method:"GET",discovered_at:$t}' >> "$JSINTEL" 2>/dev/null || true
  done
}

es_stamp() {   # stamp swagger posture onto the host doc (best-effort)
  local host="$1" nhits="$2"; [[ -z "$host" ]] && return 0
  local now; now="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  es_curl -X POST "$ES_URL/$INDEX_NAME/_update/$host" \
    -d "$(jq -nc --argjson n "$nhits" --arg t "$now" \
      '{doc:{swagger_spec:true,swagger_unauth_endpoints:$n,autoswagger_scan_at:$t}}')" \
    >/dev/null 2>&1 || true
}
note_host() { local h="$1" t="$2"; [[ -z "$h" ]] && return 0; bash "$SCRIPT_DIR/recon_ctl.sh" note "$h" "$t" >/dev/null 2>&1 || true; }

# ---- one bounded cycle ----
cmd_scan() {
  kill_gate; vpn_gate
  require_autoswagger || exit 0
  exec 9>"$LOCK_FILE"; flock -n 9 || { log "another autoswagger scan running"; exit 0; }

  local cand="$WORK/cand.tsv"; discover_hosts | sort -u > "$cand" || true
  local ncand; ncand="$(wc -l < "$cand" | tr -d ' ')"
  [[ "$ncand" -eq 0 ]] && { log "no swagger/openapi candidate hosts discovered"; exit 0; }
  log "discovered $ncand candidate host(s)"

  # scope + pays gate
  local inscope="$WORK/inscope.txt"
  cut -f1 "$cand" | sort -u | bash "$SCOPE_CHECK" --filter in-scope-paying 2>/dev/null | sort -u > "$inscope" || true
  [[ -s "$inscope" ]] || { log "no candidate host is in-scope+paying"; exit 0; }
  local gated="$WORK/gated.tsv"
  awk -F'\t' 'NR==FNR{ok[$1]=1;next} ($1 in ok)' "$inscope" "$cand" > "$gated" || true

  # dedup vs cooldown ledger (by host), cap batch
  local cutoff; cutoff=$(( $(date +%s) - AS_COOLDOWN_DAYS*86400 ))
  local batch="$WORK/batch.tsv"; : > "$batch"; local kept=0
  while IFS=$'\t' read -r h prog; do
    [[ "$kept" -ge "$AS_BATCH" ]] && break
    local last; last="$(awk -F'\t' -v x="$h" '$1==x{print $2}' "$SCANNED" | tail -1)"
    [[ -n "$last" && "$last" =~ ^[0-9]+$ && "$last" -gt "$cutoff" ]] && continue
    printf '%s\t%s\n' "$h" "$prog" >> "$batch"; kept=$((kept+1))
  done < "$gated"
  [[ "$kept" -eq 0 ]] && { log "all in-scope candidates within cooldown"; exit 0; }
  log "probing $kept host(s) (GET-only, unauth)"

  local nowep; nowep="$(date +%s)" total_hits=0 hosts_with_hits=0
  : > "$WORK/enriched.jsonl"
  while IFS=$'\t' read -r host prog; do
    [[ -z "$host" ]] && continue
    printf '%s\t%s\n' "$host" "$nowep" >> "$SCANNED"   # record probed (cooldown), hit or miss
    local hits; hits="$(autoswagger_host "$host" "$prog")"
    local nhits; nhits="$(printf '%s' "$hits" | grep -c . || true)"
    [[ "$nhits" -eq 0 ]] && continue
    hosts_with_hits=$((hosts_with_hits+1)); total_hits=$(( total_hits + nhits ))
    local ts; ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf '%s' "$hits" | while IFS= read -r rec; do
      [[ -z "$rec" ]] && continue
      jq -c --arg h "$host" --arg p "$prog" --arg ts "$ts" \
        '. + {host:$h,program:$p,ts:$ts,status_tier:"to-test",vuln_type:"swagger-broken-authz"}' <<<"$rec"
    done >> "$WORK/enriched.jsonl"
    printf '%s' "$hits" | feed_endpoints "$host" "$prog"
    es_stamp "$host" "$nhits"
    note_host "$host" "autoswagger: $nhits unauth-reachable documented endpoint(s) — broken-authz LEAD (human 2-acct BOLA confirm; never third-party IDs)"
  done < "$batch"

  cat "$WORK/enriched.jsonl" >> "$WORKLIST" 2>/dev/null || true
  write_briefing
  # keep the cooldown ledger bounded
  tail -n 8000 "$SCANNED" > "$SCANNED.tmp" 2>/dev/null && mv "$SCANNED.tmp" "$SCANNED" 2>/dev/null || true
  log "cycle done — 📖 $hosts_with_hits host(s) with $total_hits unauth-reachable documented endpoint(s) → worklist"
}

# ---- ranked briefing markdown ----
write_briefing() {
  local today md; today="$(date '+%Y-%m-%d')"; md="$BRIEF_DIR/autoswagger_candidates_$today.md"
  local recent; recent="$(tail -n 600 "$WORKLIST" 2>/dev/null | jq -c '.' 2>/dev/null \
    | jq -s 'map(select(.ts and (.ts >= (now - 3*86400 | todate)))) | group_by(.host)
             | map({host:.[0].host, program:.[0].program,
                    n:length, pii:(map(select(.flags|index("pii")))|length),
                    secrets:(map(select(.flags|index("secrets")))|length), eps:.})
             | sort_by(.secrets*100 + .pii*10 + .n) | reverse' 2>/dev/null || echo '[]')"
  {
    printf '# 📖 Autoswagger — unauth Swagger/OpenAPI broken-authz worklist — %s\n\n' "$today"
    printf '_GET-only unauth spec-walk (LEADs). A 200 that shouldn'\''t answer unauth = broken-authz candidate._\n'
    printf '_Cross-object IDOR/BOLA confirm = Claude VERIFY + human 2 OWNED accounts (never third-party IDs)._\n\n'
    printf '%s' "$recent" | jq -r '.[] |
      "## \(.host)  (\(.program // "?"))  — \(.n) unauth endpoint(s)\((if .pii>0 then " · \(.pii) PII" else "" end))\((if .secrets>0 then " · \(.secrets) secrets" else "" end))",
      ( .eps[]? | "  - [\(.status)] `\(.endpoint)`\((if (.flags|length)>0 then "  ⚑ \(.flags|join(","))" else "" end))" ),
      ""' 2>/dev/null
  } > "$md" 2>/dev/null
  log "briefing → $md"
}

cmd_check() {
  kill_gate; vpn_gate
  require_autoswagger || exit 0
  local target="${1:?usage: check <host-or-url>}"
  local host; host="$(printf '%s' "$target" | sed -E 's#https?://##; s#/.*##')"
  local prog=""
  local hits; hits="$(autoswagger_host "$host" "$prog")"
  if [[ -z "$hits" ]]; then echo "no unauth-reachable documented endpoints (or no spec / tool no-op): $host"; return 0; fi
  printf '%s' "$hits" | jq -r '"[\(.status)] \(.endpoint)\((if (.flags|length)>0 then "  ⚑ "+(.flags|join(",")) else "" end))"' 2>/dev/null
}

cmd_results() {
  local n="${1:-15}"
  tail -n 400 "$WORKLIST" 2>/dev/null | jq -c '.' 2>/dev/null \
    | jq -s "sort_by(.ts) | reverse | unique_by(.host+.endpoint) | .[0:$n][]" 2>/dev/null \
    | jq -r '"\(.ts // "?")  \(.host)  [\(.status)] \(.endpoint)  \((.flags//[])|join(","))"' 2>/dev/null || true
}

case "${1:-scan}" in
  scan|"")      cmd_scan ;;
  check)        shift; cmd_check "$@" ;;
  results|list) shift; cmd_results "$@" ;;
  *) echo "usage: $0 [scan|check <host-or-url>|results [N]]" >&2; exit 2 ;;
esac

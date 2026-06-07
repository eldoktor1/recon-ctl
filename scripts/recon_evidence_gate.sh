#!/usr/bin/env bash
# =============================================================================
# recon_evidence_gate.sh — PHASE A: the evidence gate.
#
# Inverts "promote-then-maybe-confirm" into "score → P0-CANDIDATE (held at P1) →
# NON-INTRUSIVE probe → promote to P0 only on a real fire." triage.sh tags every
# detection-only P0 as triage_gate_state=candidate + triage_gate_class=<class>;
# this worker pulls candidates, runs the class-appropriate probe (reusing the
# existing scanners as tools — nuclei / dalfox / bypass), and:
#   • FIRE     → gate_state=confirmed, triage_priority=P0 (the ONLY detection-path
#                P0 mint), packages triage_gate_evidence, queues for the Reporter.
#   • NO FIRE  → attempts++, last_probe=now; after N attempts OR TTL → lead-exhausted
#                (stays P1, logged; becomes an FP-signature candidate in Phase B).
#
# NON-INTRUSIVE BOUNDARY: probes confirm the PRECONDITION (vulnerable version
# present / panel reachable unauth / break-out canary executes), never an exploit
# or data pull. nuclei runs with detection/exposure tags only and -etags
# intrusive,dos,fuzz,brute-force,sqli-exploit. Stays inside recon-not-attack on
# every tier (the financial-tier active-testing boundary is Phase D's concern).
#
# Target-facing → run via run_scanner (reconrun, Mullvad). Honours vpn_down and
# recon-scope before every probe.
# =============================================================================
set -uo pipefail
IFS=$'\n\t'

log()  { printf '[%s GATE] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s GATE WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/recon_net.sh"
setup_es_netrc
ES_AUTH=(--netrc-file "$HOME/.recon_es_netrc")

BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
V3_DIR="${V3_DIR:-$BASE_DIR/v3}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"
INDEX_NAME="${INDEX_NAME:-recon_alive}"
SCOPE_CHECK="${SCOPE_CHECK:-$SCRIPT_DIR/recon_scope_check.sh}"
NUCLEI_BIN="${NUCLEI_BIN:-$(command -v nuclei 2>/dev/null || echo '')}"
PARAMS_INDEX="${PARAMS_INDEX:-recon_params}"
REPORTER_QUEUE="${REPORTER_QUEUE:-$V3_DIR/reporter_queue.jsonl}"
# v3 SQLite bridge + confidence routing (article-style): a bare nuclei fire is NOT
# a P0 — confidence gates promotion. <0.70 stays LEAD; 0.70-0.84 confirmed/batch
# (P1); >=0.85 confirmed/immediate (P0). FP signatures learned from exhausted leads
# are queried before probing so the gate goes quieter over time.
V3_DB="${V3_DB:-$V3_DIR/findings.db}"
STATE_PY="${STATE_PY:-$SCRIPT_DIR/../v3/state.py}"
GATE_PROMOTE_CONF="${GATE_PROMOTE_CONF:-0.70}"
GATE_IMMEDIATE_CONF="${GATE_IMMEDIATE_CONF:-0.85}"

# Gate policy (decisions: N=5, 3h cooldown, 5d TTL)
GATE_BATCH="${GATE_BATCH:-30}"                 # candidates per cycle (interim volume cap; per-program ceiling is Phase D)
GATE_MAX_ATTEMPTS="${GATE_MAX_ATTEMPTS:-5}"
GATE_COOLDOWN_SECS="${GATE_COOLDOWN_SECS:-10800}"   # 3h between attempts
GATE_TTL_SECS="${GATE_TTL_SECS:-432000}"            # 5d, then lead-exhausted
NUCLEI_ETAGS="${NUCLEI_ETAGS:-intrusive,dos,fuzz,fuzzing,brute-force,bruteforce,sqli,xss,rce,oast}"
NUCLEI_RL="${NUCLEI_RL:-50}"
PROBE_TIMEOUT="${PROBE_TIMEOUT:-90}"

mkdir -p "$V3_DIR" "$STATE_DIR"
exec 9>"$STATE_DIR/evidence_gate.lock"; flock -n 9 || { warn "evidence gate already running"; exit 0; }
[[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down set — skipping gate"; exit 0; }

es() { curl -fsS -m 30 "${ES_AUTH[@]}" -H 'Content-Type: application/json' "$@"; }
now_epoch() { date -u +%s; }
iso() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }

# confidence from probe severity (article-style scoring)
confidence_of() {
  case "${1,,}" in
    critical) echo 0.95 ;; high) echo 0.85 ;; medium) echo 0.72 ;;
    low) echo 0.45 ;; info|informational) echo 0.35 ;; *) echo 0.40 ;;
  esac
}
ge() { awk "BEGIN{exit !($1>=$2)}"; }   # float a>=b

# v3 SQLite bridge (parameterized via state.py CLI — injection-safe). No-op if
# python3/state.py unavailable, so the gate degrades gracefully to ES-only.
_db_ok() { command -v python3 >/dev/null 2>&1 && [[ -f "$STATE_PY" ]]; }
fp_known() { _db_ok || return 1; [[ "$(V3_DB="$V3_DB" python3 "$STATE_PY" check-fp "$1" "$2" 2>/dev/null)" == "FP" ]]; }
fp_learn() { _db_ok || return 0; V3_DB="$V3_DB" python3 "$STATE_PY" record-fp "$1" "$2" "" "gate-exhausted" >/dev/null 2>&1 || true; }
db_confirm() { _db_ok || return 0; V3_DB="$V3_DB" python3 "$STATE_PY" record-confirmed "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" >/dev/null 2>&1 || true; }

# ---- candidate selection (the queue) ---------------------------------------
# gate_state in (candidate,verifying), attempts<N, cooled down, in-scope-paying.
pull_candidates() {
  local cutoff; cutoff="$(date -u -d "-${GATE_COOLDOWN_SECS} seconds" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || iso)"
  local q
  q="$(jq -nc --argjson n "$GATE_BATCH" --argjson maxa "$GATE_MAX_ATTEMPTS" --arg cut "$cutoff" '{
    size:$n,
    _source:["host","url","triage_gate_class","triage_gate_attempts","triage_gate_first_at",
             "triage_program","triage_payout_tier","triage_score"],
    query:{bool:{
      filter:[
        {terms:{triage_gate_state:["candidate","verifying"]}},
        {term:{triage_in_scope:true}},{term:{triage_pays:true}},
        {range:{triage_gate_attempts:{lt:$maxa}}}
      ],
      must_not:[{term:{triage_out_of_scope:true}},
                {range:{triage_gate_last_probe:{gte:$cut}}}]
    }},
    sort:[{triage_payout_tier:{order:"asc",missing:"_last"}},{triage_score:{order:"desc"}}]
  }')"
  es -X POST "$ES_URL/$INDEX_NAME/_search" -d "$q" 2>/dev/null \
    | jq -rc '.hits.hits[]?._source
        | [(.host//""),(.url//("https://"+(.host//""))),(.triage_gate_class//"none"),
           ((.triage_gate_attempts//0)|tostring),(.triage_gate_first_at//""),
           (.triage_program//""),(.triage_payout_tier//"none")] | @tsv' 2>/dev/null
}

# ---- ES state writers ------------------------------------------------------
set_state() {  # host gate_state [extra-json-doc-fields]
  local host="$1" state="$2" extra="${3:-{\}}"
  local doc; doc="$(jq -nc --arg s "$state" --arg t "$(iso)" --argjson x "$extra" \
    '{triage_gate_state:$s, triage_gate_last_probe:$t} + $x')"
  es -X POST "$ES_URL/$INDEX_NAME/_update/$host" \
     -d "$(jq -nc --argjson d "$doc" '{doc:$d}')" >/dev/null 2>&1 || true
}
bump_attempt() {  # host attempts first_at class
  local host="$1" attempts="$2" first_at="$3" class="${4:-none}"; local na=$((attempts+1))
  local fa="$first_at"; [[ -z "$fa" ]] && fa="$(iso)"
  local age_ok=1
  if [[ -n "$first_at" ]]; then
    local fe; fe="$(date -u -d "$first_at" +%s 2>/dev/null || echo 0)"
    (( fe > 0 && ( $(now_epoch) - fe ) > GATE_TTL_SECS )) && age_ok=0
  fi
  if (( na >= GATE_MAX_ATTEMPTS )) || (( age_ok == 0 )); then
    log "  $host — exhausted (attempts=$na) → lead-exhausted (stays P1)"
    set_state "$host" "lead-exhausted" "$(jq -nc --argjson a "$na" --arg fa "$fa" '{triage_gate_attempts:$a, triage_gate_first_at:$fa}')"
    fp_learn "$host" "$class"   # learn the signature so we stop re-probing this dead lead
  else
    set_state "$host" "candidate" "$(jq -nc --argjson a "$na" --arg fa "$fa" '{triage_gate_attempts:$a, triage_gate_first_at:$fa}')"
  fi
}
promote() {  # host url class evidence-json confidence review_tier program
  local host="$1" url="$2" class="$3" ev="$4" conf="$5" rt="$6" program="${7:-}"
  local prio="P1" score=14
  [[ "$rt" == "immediate" ]] && { prio="P0"; score=15; }
  log "  $host — PROBE FIRED ($class, conf=$conf, $rt) → $prio + reporter"
  set_state "$host" "confirmed" \
    "$(jq -nc --argjson ev "$ev" --arg p "$prio" --argjson sc "$score" --argjson c "$conf" --arg rt "$rt" \
       '{triage_priority:$p, triage_score:$sc, triage_gate_evidence:$ev, triage_gate_confidence:$c, triage_gate_review_tier:$rt, triage_p0_candidate:false}')"
  jq -nc --arg h "$host" --arg u "$url" --arg c "$class" --argjson ev "$ev" --argjson cf "$conf" --arg rt "$rt" --arg t "$(iso)" \
    '{host:$h, url:$u, gate_class:$c, evidence:$ev, confidence:$cf, review_tier:$rt, confirmed_at:$t, state:"confirmed"}' \
    >> "$REPORTER_QUEUE" 2>/dev/null || true
  db_confirm "$host" "$url" "$program" "$class" "" "$score" "$conf" "$ev"   # SQLite state truth (reporter/observability)
  # v3.2: the gate no longer pings Discord. A gate confirmation is only an evidence
  # candidate for the Claude VERIFY layer — which posts to #review ONLY on a "real" /
  # "needs-human" verdict. This stops gate-confirmed-but-Claude-fp from paging anyone.
}

# ---- probes (NON-INTRUSIVE; reuse existing tools) --------------------------
# Each prints a one-line evidence JSON on FIRE, nothing on no-fire.
nuclei_probe() {  # url  tag-set
  local url="$1" tags="$2"
  [[ -n "$NUCLEI_BIN" ]] || { warn "nuclei missing"; return 1; }
  local out; out="$(timeout "$PROBE_TIMEOUT" "$NUCLEI_BIN" -u "$url" \
      -tags "$tags" -etags "$NUCLEI_ETAGS" -severity info,low,medium,high,critical \
      -rl "$NUCLEI_RL" -silent -jsonl -nc -duc </dev/null 2>/dev/null | head -1)" || true
  [[ -z "$out" ]] && return 1
  printf '%s' "$out" | jq -c '{probe:"nuclei", template:(."template-id"//"?"),
      severity:(.info.severity//"?"), matched_at:(."matched-at"//.host//""), name:(.info.name//"")}' 2>/dev/null
}
xss_probe() {  # host — confirmed only if params lane already broke out unencoded
  local host="$1"
  local vf="$BASE_DIR/params/verify_xss.jsonl"
  [[ -s "$vf" ]] || return 1
  grep -F "\"$host\"" "$vf" 2>/dev/null | jq -c 'select(.status=="confirmed") |
      {probe:"dalfox/params-verify", url:.url, status:.status, severity:"high"}' 2>/dev/null | head -1 | grep . || return 1
}
bypass_probe() {  # host — confirmed only if the bypass lane verified an auth-differential
  local host="$1"
  es "$ES_URL/$INDEX_NAME/_source/$host" 2>/dev/null \
    | jq -ce 'select(.bypass_confirmed==true) | {probe:"bypass-auth-differential",
        path:(.bypass_path//"?"), waf:(.bypass_waf//"?"), severity:"high"}' 2>/dev/null || return 1
}

probe_for_class() {  # class url host  → echoes evidence json on FIRE
  case "$1" in
    version)        nuclei_probe "$2" "tech,detect,version,cve,exposure" ;;
    unauth-surface) nuclei_probe "$2" "exposure,exposed-panel,unauth,misconfig,default-login" ;;
    content-leak)   nuclei_probe "$2" "exposure,disclosure,files,listing,backup,config" ;;
    xss)            xss_probe "$3" ;;
    auth-bypass)    bypass_probe "$3" ;;
    *)              return 1 ;;   # unprobeable → caller marks lead-exhausted
  esac
}

# ---- main ------------------------------------------------------------------
main() {
  local cands; cands="$(pull_candidates)"
  local total; total="$(printf '%s' "$cands" | grep -c . || true)"
  [[ "${total:-0}" -eq 0 ]] && { log "no candidates due for probing"; exit 0; }
  log "evidence gate: $total candidate(s) this cycle (batch cap=$GATE_BATCH)"

  local fired=0 cleared=0 exhausted=0
  # Read the queue on FD 3 — probes (nuclei et al.) read stdin and would otherwise
  # consume the loop's here-string, ending the loop after the first candidate.
  while IFS=$'\t' read -r host url class attempts first_at program tier <&3; do
    [[ -z "$host" ]] && continue
    [[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down mid-run — halting"; break; }
    # scope gate — never probe out-of-scope
    if [[ -x "$SCOPE_CHECK" || -f "$SCOPE_CHECK" ]]; then
      local sv; sv="$(printf '%s\n' "$host" | bash "$SCOPE_CHECK" --batch 2>/dev/null | jq -r 'select(.in_scope==true and .out_of_scope!=true)|.host' 2>/dev/null)"
      [[ "$sv" == "$host" ]] || { warn "  $host — failed live scope gate, skipping"; continue; }
    fi
    if [[ "$class" == "none" ]]; then
      log "  $host — unprobeable class → lead-exhausted (stays P1)"
      set_state "$host" "lead-exhausted" '{"triage_gate_class":"none"}'; exhausted=$((exhausted+1)); continue
    fi
    # learned-FP pre-check — skip dead leads we already killed (quieter over time)
    if fp_known "$host" "$class"; then
      log "  $host — known FP signature, skipping (lead-exhausted)"
      set_state "$host" "lead-exhausted" '{}'; exhausted=$((exhausted+1)); continue
    fi
    set_state "$host" "verifying" "$(jq -nc --arg fa "${first_at:-$(iso)}" '{triage_gate_first_at:$fa}')"
    local ev; ev="$(probe_for_class "$class" "$url" "$host" || true)"
    if [[ -n "$ev" ]]; then
      local sev conf; sev="$(printf '%s' "$ev" | jq -r '.severity // "info"' 2>/dev/null)"; conf="$(confidence_of "$sev")"
      if ge "$conf" "$GATE_PROMOTE_CONF"; then
        local rt="batch"; ge "$conf" "$GATE_IMMEDIATE_CONF" && rt="immediate"
        promote "$host" "$url" "$class" "$ev" "$conf" "$rt" "$program"; fired=$((fired+1))
      else
        log "  $host — probe fired but low confidence ($sev=$conf < $GATE_PROMOTE_CONF) → stays LEAD"
        bump_attempt "$host" "${attempts:-0}" "$first_at" "$class"; cleared=$((cleared+1))
      fi
    else
      bump_attempt "$host" "${attempts:-0}" "$first_at" "$class"; cleared=$((cleared+1))
    fi
  done 3<<< "$cands"

  log "gate cycle done — fired(P0)=$fired, no-fire=$cleared, exhausted=$exhausted"
}
main "$@"

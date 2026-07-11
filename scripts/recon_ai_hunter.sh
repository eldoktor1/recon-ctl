#!/usr/bin/env bash
# =============================================================================
# recon_ai_hunter.sh — the Claude HUNTER lane (research-backed: Big Sleep + XBOW).
#
# Turns Claude from a downstream FILTER into a per-target HUNTER. Per high-value,
# in-scope+paying target it runs the loop the published work converges on
# (docs/knowledge/class-ai-hunter-design.md):
#   SEED        pick one authorized target + its already-collected surface (variant analysis;
#               never open-ended "find bugs here").
#   MODEL+HYPOTHESIZE  Opus reasons over the full app context (endpoints/tech/notes) -> a
#               structured app-model + SPECIFIC, FOCUSED, TESTABLE, dup-aware hypotheses.
#   TEST        the TRUSTED HARNESS (not the model) runs each unauth-safe hypothesis through
#               recon_safe_probe.sh (GET/HEAD/OPTIONS, scope+pays+rate+SSRF+Mullvad gated).
#   ADJUDICATE  Opus judges the REAL probe responses -> confirmed (execution-grounded) / refuted /
#               needs-human (authed/2-account) / needs-account. Overclaiming forbidden.
#   MINT/PLAN   confirmed unauth primitive -> state.py record-confirmed (-> verify gate -> #review);
#               authed/IDOR -> a precise 2-OWNED-ACCOUNT operator plan in the hunter briefing.
#   LEARN       confirmed/FP patterns -> KB (state.py kb-record).
#
# HARD LINES (make it legit AND valid): authorized + in-scope + pays only; UNAUTH GET/HEAD/OPTIONS
# probes only (safe_probe enforces); authed/IDOR is HUMAN-in-the-loop with 2 OWNED accounts, NEVER
# autonomous; confirm-don't-exploit-past-PoC; never third-party data; Mullvad + anti-burn.
# Claude runs as d0k (Max OAuth); the only target traffic is via safe_probe. Killswitch v2_ai_hunter.
#
# MODES:  cycle (autonomous: pick next target) | host <host> (on-demand) | status
# =============================================================================
set -uo pipefail
IFS=$'\n\t'
log()  { printf '[%s HUNTER] %s\n'      "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s HUNTER WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/recon_net.sh" 2>/dev/null || true   # discord_post (alerts)
BASE_DIR="${BASE_DIR:-$HOME/recon}"; STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"; INDEX_NAME="${INDEX_NAME:-recon_alive}"
NETRC="${NETRC:-$HOME/.recon_es_netrc}"
ENDPOINTS="${ENDPOINTS:-$BASE_DIR/js_recon/endpoints.jsonl}"
SAFE_PROBE="${SAFE_PROBE:-$SCRIPT_DIR/recon_safe_probe.sh}"
SCOPE_CHECK="${SCOPE_CHECK:-$SCRIPT_DIR/recon_scope_check.sh}"
STATE_PY="${STATE_PY:-$REPO_DIR/engine/state.py}"
V3_DB="${V3_DB:-$BASE_DIR/v3/findings.db}"
SEEN="${HUNTER_SEEN:-$STATE_DIR/hunter_seen.txt}"        # sliding window of hunted hosts
KILL_FILE="$STATE_DIR/kill/v2_ai_hunter"
BRIEF_DIR="${BRIEF_DIR:-$BASE_DIR/briefings}"
CLAUDE_BIN="${CLAUDE_BIN:-$HOME/.local/bin/claude}"; [[ -x "$CLAUDE_BIN" ]] || CLAUDE_BIN="$(command -v claude 2>/dev/null || echo '')"
HUNTER_MODEL="${HUNTER_MODEL:-opus}"            # the creative hunt = frontier model (XBOW model-alloying)
# Adjudication (judging real probe responses vs expected) is discriminative, not creative — a cheaper
# model does it well. Defaults to HUNTER_MODEL (no behaviour change); set HUNTER_ADJ_MODEL=sonnet in
# state/token_budget.env to keep Opus only for hypothesis generation (token economy).
HUNTER_ADJ_MODEL="${HUNTER_ADJ_MODEL:-$HUNTER_MODEL}"
HUNTER_TIMEOUT="${HUNTER_TIMEOUT:-300}"
HUNTER_MAX_HYP="${HUNTER_MAX_HYP:-6}"           # cap probes per target (anti-burn; safe_probe also caps)
HUNTER_PROBE_BUDGET="${HUNTER_PROBE_BUDGET:-8}" # per-target probe budget (passed to safe_probe)
HUNTER_EP_CAP="${HUNTER_EP_CAP:-60}"            # endpoints fed into the model (context size guard)
HUNTER_BODY_CAP="${HUNTER_BODY_CAP:-1200}"      # probe-body chars fed back to adjudication
es() { curl -fsS -m 25 --netrc-file "$NETRC" -H 'Content-Type: application/json' "$@"; }

mkdir -p "$STATE_DIR" "$BRIEF_DIR" "$(dirname "$KILL_FILE")"; touch "$SEEN"
[[ -n "$CLAUDE_BIN" && -x "$CLAUDE_BIN" ]] || { warn "claude CLI not found (need Max OAuth as d0k)"; exit 0; }
command -v jq >/dev/null 2>&1 || { warn "jq missing"; exit 0; }
[[ -f "$KILL_FILE" ]] && { warn "killed by $KILL_FILE"; exit 0; }
[[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down — probes would fail-closed; skip"; exit 0; }

# ---- schemas --------------------------------------------------------------------------------
HYP_SCHEMA='{"type":"object","properties":{
 "app_model":{"type":"string"},
 "hypotheses":{"type":"array","items":{"type":"object","properties":{
   "id":{"type":"string"},"vuln_class":{"type":"string"},"target_url":{"type":"string"},
   "method":{"type":"string","enum":["GET","HEAD","OPTIONS","OTHER"]},
   "rationale":{"type":"string"},"test":{"type":"string"},"expected_positive":{"type":"string"},
   "auth_required":{"type":"boolean"},"safe_to_probe":{"type":"boolean"},
   "dup_risk":{"type":"string","enum":["low","medium","high"]},"confidence":{"type":"number"}},
   "required":["id","vuln_class","target_url","method","rationale","auth_required","safe_to_probe","confidence"]}}},
 "required":["app_model","hypotheses"]}'
ADJ_SCHEMA='{"type":"object","properties":{
 "verdicts":{"type":"array","items":{"type":"object","properties":{
   "id":{"type":"string"},"verdict":{"type":"string","enum":["confirmed","refuted","needs-human","needs-account"]},
   "vuln_class":{"type":"string"},"severity":{"type":"string","enum":["critical","high","medium","low","info"]},
   "evidence":{"type":"string"},"operator_plan":{"type":"string"},"confidence":{"type":"number"}},
   "required":["id","verdict","evidence"]}}},
 "required":["verdicts"]}'

claude_json() {  # claude_json <model> <schema> <prompt>  -> .structured_output on stdout (or empty)
  local model="$1" schema="$2" prompt="$3" out
  out="$(timeout "$HUNTER_TIMEOUT" "$CLAUDE_BIN" -p "$prompt" --model "$model" \
        --permission-mode dontAsk --json-schema "$schema" --output-format json \
        --no-session-persistence </dev/null 2>/dev/null)" || return 1
  printf '%s' "$out" | jq -c '.structured_output // empty' 2>/dev/null
}

# ---- SEED: scope+pays gate for a host (authoritative per-asset) ------------------------------
in_scope_pays() {  # in_scope_pays <host> -> 0 if in-scope AND paying AND not benched/OOS
  local host="$1" q r
  if [[ -f "$SCOPE_CHECK" ]]; then   # offline + authoritative (local scope files); run via bash (no +x needed)
    bash "$SCOPE_CHECK" "$host" --pays >/dev/null 2>&1 && return 0 || return 1
  fi
  q="$(jq -nc --arg h "$host" '{size:1,_source:["triage_in_scope","triage_pays"],query:{bool:{
        filter:[{term:{host:$h}},{term:{triage_in_scope:true}},{term:{triage_pays:true}}],
        must_not:[{term:{triage_out_of_scope:true}},{range:{ignore_expires_at:{gt:"now"}}}]}}}')"
  r="$(es "$ES_URL/$INDEX_NAME/_search" -d "$q" 2>/dev/null | jq -r '.hits.total.value // 0' 2>/dev/null)"
  [[ "${r:-0}" -ge 1 ]]
}
program_of() {  # scope_check first (offline, authoritative), ES fallback
  local p=""
  [[ -f "$SCOPE_CHECK" ]] && p="$(bash "$SCOPE_CHECK" "$1" 2>/dev/null | jq -r '.program // empty' 2>/dev/null | sed 's/[[:space:]]*$//')"
  [[ -n "$p" ]] || p="$(es "$ES_URL/$INDEX_NAME/_search" -d "$(jq -nc --arg h "$1" '{size:1,_source:["program"],query:{term:{host:$h}}}')" 2>/dev/null | jq -r '.hits.hits[0]._source.program // empty' 2>/dev/null)"
  printf '%s\n' "${p:-unknown}"
}
host_ctx()   { # tech + notes (+ PHP framework-debug hint) for the app model
  local src base blob
  src="$(es "$ES_URL/$INDEX_NAME/_search" -d "$(jq -nc --arg h "$1" '{size:1,_source:["tech","host_notes_text","triage_payout_tier","title","webserver","headers_text","cookies_text"],query:{term:{host:$h}}}')" 2>/dev/null \
    | jq -c '.hits.hits[0]._source // {}' 2>/dev/null)"
  [[ -n "$src" ]] || src='{}'
  base="$(printf '%s' "$src" | jq -r '"tech=\(.tech // "?") tier=\(.triage_payout_tier // "?") server=\(.webserver // "?") title=\(.title // "?")\nnotes: \(.host_notes_text // "none")"' 2>/dev/null)"
  # PHP framework debug-panel hint: Laravel/Symfony leak high-value UNAUTH debug surfaces (the data IS
  # the finding; Ignition can be RCE if APP_DEBUG=true). Surface it so the model proposes safe GET reads.
  blob="$(printf '%s' "$src" | jq -r '[.tech,.webserver,.title,.headers_text,.cookies_text]|map(.//"")|join(" ")' 2>/dev/null | tr 'A-Z' 'a-z')"
  if printf '%s' "$blob" | grep -qE 'laravel|symfony|codeigniter|php|x-debug-token|laravel_session|xsrf-token|ci_session'; then
    base="${base}
FRAMEWORK-DEBUG HINT: PHP/Laravel/Symfony signals present — add UNAUTH-SAFE GET hypotheses for debug/info-disclosure surfaces if plausibly present: Laravel /_ignition/health-check, /telescope, /horizon, /_clockwork, /log-viewer; Symfony /_profiler/, /_wdt/, /_profiler/phpinfo. CONFIRM = the panel/stack-trace/env/route-list actually renders unauth (a 200 SPA-shell, redirect, or 404 = FP). safe_to_probe=true GET reads."
  fi
  printf '%s\n' "$base"
}

pick_target() {  # autonomous: next in-scope+pays host with endpoints, not yet hunted
  [[ -s "$ENDPOINTS" ]] || { warn "no endpoints feedstock ($ENDPOINTS)"; return 1; }
  local h
  while read -r h; do
    [[ -z "$h" ]] && continue
    grep -qxF "$h" "$SEEN" 2>/dev/null && continue
    in_scope_pays "$h" || continue
    printf '%s\n' "$h"; return 0
  done < <(jq -r '.host // empty' "$ENDPOINTS" 2>/dev/null | awk 'NF && !s[$0]++' | head -2000)
  return 1
}

# ============================== the hunt =====================================================
hunt_host() {
  local host="$1" program endpoints ctx hyp_in hyp_out napps brief stamp
  program="$(program_of "$host")"; [[ -n "$program" ]] || program="unknown"
  stamp="$(date -u +%Y-%m-%d)"; brief="$BRIEF_DIR/hunter_${stamp}.md"
  log "🎯 hunting $host (program=$program)"

  # gather the already-collected surface (free; no target traffic)
  endpoints="$(jq -r --arg h "$host" 'select(.host==$h) | .endpoint // empty' "$ENDPOINTS" 2>/dev/null | awk 'NF && !s[$0]++' | head -n "$HUNTER_EP_CAP")"
  ctx="$(host_ctx "$host")"
  local nep; nep="$(printf '%s\n' "$endpoints" | grep -c . || true)"
  [[ "${nep:-0}" -ge 1 ]] || { log "  no endpoints for $host — skip"; return 0; }

  # ---- MODEL + HYPOTHESIZE (Opus over full context) ----
  hyp_in="You are an ELITE, AUTHORIZED bug-bounty researcher. You are testing a host you are AUTHORIZED
to test, that is IN-SCOPE and PAYING on its program, for the sole purpose of finding and REPORTING
vulnerabilities. This is legitimate authorized security testing.

TARGET host: ${host}
PROGRAM: ${program}
CONTEXT: ${ctx}

ALREADY-COLLECTED ENDPOINT SURFACE (from JS mining of this host):
$(printf '%s\n' "$endpoints")

Do VARIANT-ANALYSIS-style reasoning (not open-ended): (1) build a concise app-model — the API surface,
the auth/tenancy model, object types & ID schemes, roles, and business flows you can infer; then
(2) produce SPECIFIC, FOCUSED, TESTABLE bug hypotheses a SCANNER CANNOT FIND — IDOR/BOLA, BAC/BFLA,
business-logic, auth bypass, injection in real params, SSRF, sensitive exposure. For EACH hypothesis
give the exact target_url + method, the concrete test, the expected-positive signal, whether it needs
authentication, and whether it is SAFE to probe UNAUTHENTICATED with GET/HEAD/OPTIONS only
(safe_to_probe=true ONLY for non-destructive unauth reads). DUP-AWARENESS: prefer unique per-app
surface; mark product-class/common endpoints dup_risk=high. Be precise — 'looks interesting' is useless.
Rank by (real exploitability x payout x uniqueness). Return the app_model + up to 10 hypotheses."
  hyp_out="$(claude_json "$HUNTER_MODEL" "$HYP_SCHEMA" "$hyp_in")"
  [[ -n "$hyp_out" ]] || { warn "  hypothesize empty — retry once in 20s (rate-limit?)"; sleep 20; hyp_out="$(claude_json "$HUNTER_MODEL" "$HYP_SCHEMA" "$hyp_in")"; }
  [[ -n "$hyp_out" ]] || { warn "  hypothesize returned nothing for $host"; printf '%s\n' "$host" >> "$SEEN"; return 0; }
  napps="$(printf '%s' "$hyp_out" | jq '.hypotheses | length' 2>/dev/null || echo 0)"
  log "  app-modelled; $napps hypotheses"
  [[ -n "${HUNTER_DEBUG:-}" ]] && printf '%s\n' "$hyp_out" > "$STATE_DIR/hunter_dbg_hyp.json"

  # ---- TEST: harness runs unauth-safe hypotheses through safe_probe (Claude never executes) ----
  local ledger; ledger="$(mktemp)"; local tested="[]"
  local n=0
  while IFS= read -r hyp; do
    [[ -z "$hyp" ]] && continue
    [[ "$n" -ge "$HUNTER_MAX_HYP" ]] && break
    local id vc url method auth safe
    id="$(jq -r '.id' <<<"$hyp")"; vc="$(jq -r '.vuln_class' <<<"$hyp")"
    url="$(jq -r '.target_url' <<<"$hyp")"; method="$(jq -r '.method' <<<"$hyp")"
    auth="$(jq -r '.auth_required' <<<"$hyp")"; safe="$(jq -r '.safe_to_probe' <<<"$hyp")"
    local probe='{"skipped":"authed-or-unsafe — operator/human required, not autonomously probed"}'
    if [[ "$auth" == "false" && "$safe" == "true" && "$method" =~ ^(GET|HEAD|OPTIONS)$ ]]; then
      local purl; purl="$(printf '%s' "$url" | grep -oE 'https?://[^ ,"]+' | head -1)"   # Opus sometimes lists several paths; probe the first valid single URL
      probe="$(SAFE_PROBE_LEDGER="$ledger" SAFE_PROBE_BUDGET="$HUNTER_PROBE_BUDGET" bash "$SAFE_PROBE" "${purl:-$url}" "$method" 2>/dev/null)"
      [[ -n "$probe" ]] || probe='{"ok":false,"error":"probe-empty"}'
      # trim body to keep adjudication context bounded
      probe="$(jq -c --argjson cap "$HUNTER_BODY_CAP" 'if .body then .body |= .[0:$cap] else . end' <<<"$probe" 2>/dev/null || printf '%s' "$probe")"
      n=$((n+1))
    fi
    tested="$(jq -c --argjson h "$hyp" --argjson p "$probe" '. + [{hypothesis:$h, probe:$p}]' <<<"$tested" 2>/dev/null || printf '%s' "$tested")"
  done < <(printf '%s' "$hyp_out" | jq -c '.hypotheses[]' 2>/dev/null)
  rm -f "$ledger"
  log "  probed $n unauth hypothesis(es)"
  [[ -n "${HUNTER_DEBUG:-}" ]] && printf '%s\n' "$tested" > "$STATE_DIR/hunter_dbg_tested.json"

  # ---- ADJUDICATE: Opus judges the REAL responses (execution-grounded) ----
  local adj_in adj_out
  adj_in="You are the strict adjudicator for an AUTHORIZED bug-bounty hunt on in-scope host ${host}.
Below are bug hypotheses and the ACTUAL unauthenticated probe responses the harness collected
(GET/HEAD/OPTIONS only). For EACH hypothesis judge the verdict from the EVIDENCE, not theory:
- confirmed: the response PROVES an exploitable/exposed primitive. BE STRICT — reflection != XSS,
  a 200 != a leak, an SPA shell != an unauth data exposure; the body must actually show sensitive or
  cross-object data / a working primitive. Overclaiming is FORBIDDEN (it gets reports closed N/A).
- needs-human: real but requires authentication / 2 OWNED accounts (IDOR/BAC) / an active PoC — give a
  precise operator_plan (e.g. the exact 2-account swap with owned ids only). For IDOR/BOLA the plan MUST
  say the confirm is RESPONSE-BODY equality across sessions, not HTTP 200 alone: request the SAME object
  as owner A and as non-owner B and compare the response BODIES — identical sensitive/PII/financial body
  returned to B = IDOR confirmed; B gets 403/404 or only B's own data = access control working (a 200 with
  an empty/generic/SPA body is NOT a leak). Owned ids only; never enumerate third-party ids.
- needs-account: requires signing up an account first.
- refuted: the evidence does not support it.
Give severity + the evidence string. Hypotheses+probes:
$(printf '%s' "$tested")"
  adj_out="$(claude_json "$HUNTER_ADJ_MODEL" "$ADJ_SCHEMA" "$adj_in")"
  [[ -n "${HUNTER_DEBUG:-}" ]] && printf '%s\n' "$adj_out" > "$STATE_DIR/hunter_dbg_adj.json"

  # ---- MINT / PLAN / LEARN ----
  local minted=0 leads=0
  if [[ -n "$adj_out" ]]; then
    while IFS= read -r v; do
      [[ -z "$v" ]] && continue
      local id verdict vc sev ev plan url
      id="$(jq -r '.id' <<<"$v")"; verdict="$(jq -r '.verdict' <<<"$v")"
      vc="$(jq -r '.vuln_class // "unknown"' <<<"$v")"; sev="$(jq -r '.severity // "info"' <<<"$v")"
      ev="$(jq -r '.evidence // ""' <<<"$v")"; plan="$(jq -r '.operator_plan // ""' <<<"$v")"
      url="$(printf '%s' "$tested" | jq -r --arg id "$id" '.[] | select(.hypothesis.id==$id) | .hypothesis.target_url' 2>/dev/null | head -1)"
      [[ -n "$url" ]] || url="https://$host"
      case "$verdict" in
        confirmed)
          # execution-grounded mint -> verify gate -> reporter hard-gates ai_verdict='real'
          local score conf evj
          case "$sev" in critical) score=15;; high) score=12;; medium) score=8;; *) score=5;; esac
          conf="$(jq -r '.confidence // 0.8' <<<"$v")"
          evj="$(jq -nc --arg ev "$ev" --arg src "ai_hunter" --arg vc "$vc" --arg sev "$sev" '{probe:"ai-hunter-unauth",source:$src,vuln_class:$vc,severity:$sev,evidence:$ev}')"
          if V3_DB="$V3_DB" python3 "$STATE_PY" record-confirmed "$host" "$url" "$program" "ai-hunter" "$vc" "$score" "$conf" "$evj" >/dev/null 2>&1; then
            minted=$((minted+1)); log "  🔥 CONFIRMED $vc ($sev) $url — minted → verify gate → #review"
          fi
          python3 "$STATE_PY" kb-record "$host" "$program" "$(printf '%s' "$ctx"|head -1)" "ai-hunter" "$vc" "real" "${conf:-0.8}" "ai_hunter" "$ev" >/dev/null 2>&1 || true ;;
        needs-human|needs-account)
          leads=$((leads+1))
          local defplan="2-owned-account test; owned ids only; confirm-then-stop"
          case "${vc,,}" in
            *idor*|*bola*|*bac*|*bfla*)
              defplan="2 OWNED accounts A/B — request the SAME object as owner A then as non-owner B and COMPARE RESPONSE BODIES: identical sensitive/PII/financial body returned to B = IDOR confirmed; 403/404 or only-B's-own-data = access control working (a 200 with empty/generic/SPA body is NOT a leak). Owned ids only; never enumerate third-party ids; confirm-then-stop." ;;
          esac
          { [[ -s "$brief" ]] || printf '# Hunter worklist — %s\n\n' "$stamp" > "$brief"
            printf -- '- **[%s] %s** `%s` — %s\n  - %s\n  - OPERATOR: %s\n' "$sev" "$vc" "$url" "$host" "$ev" "${plan:-$defplan}" >> "$brief"; } ;;
      esac
    done < <(printf '%s' "$adj_out" | jq -c '.verdicts[]' 2>/dev/null)
  else
    warn "  adjudication returned nothing for $host"
  fi

  printf '%s\n' "$host" >> "$SEEN"; tail -n 5000 "$SEEN" > "$SEEN.tmp" 2>/dev/null && mv "$SEEN.tmp" "$SEEN" 2>/dev/null || true
  log "  done $host — $minted confirmed, $leads operator-lead(s)$([ "$leads" -gt 0 ] && echo " → $brief")"
}

case "${1:-cycle}" in
  cycle|"")
    h="$(pick_target)" || { log "no fresh in-scope+pays target with endpoints (window may be lapped)"; exit 0; }
    hunt_host "$h" ;;
  host)
    [[ -n "${2:-}" ]] || { echo "usage: recon_ai_hunter.sh host <host>"; exit 1; }
    in_scope_pays "$2" || { warn "$2 is NOT in-scope+paying (authoritative) — refusing"; exit 1; }
    hunt_host "$2" ;;
  status)
    echo "hunter: model=$HUNTER_MODEL adj=$HUNTER_ADJ_MODEL  hunted(window)=$(wc -l < "$SEEN" 2>/dev/null | tr -d ' ')  endpoints=$( [ -f "$ENDPOINTS" ] && wc -l < "$ENDPOINTS" | tr -d ' ' || echo 0)"
    echo "killswitch: $( [ -f "$KILL_FILE" ] && echo ON || echo off )" ;;
  *) echo "usage: recon_ai_hunter.sh {cycle|host <host>|status}" >&2; exit 1 ;;
esac

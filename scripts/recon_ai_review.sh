#!/usr/bin/env bash
# =============================================================================
# recon_ai_review.sh — Claude-Max VALIDATION agent (the accuracy layer).
#
# Runs headless Claude Code (`claude -p`) on your Max subscription — NO API key,
# no API bill. It judges only evidence-gate-CONFIRMED findings (a handful/day, so
# trivial Max quota), adversarially: assume false-positive until the evidence
# proves otherwise. Writes a verdict to the SQLite state machine:
#   real        -> stays confirmed, reaches the human review queue
#   fp          -> dismissed + FP signature learned (never re-surfaced)
#   needs-human -> stays confirmed, flagged for the operator
#
# v3.3 — Claude at full capability (still pure REASONING, never acts on a target):
#   * MULTIMODAL: the asset SCREENSHOT is handed to Claude as primary evidence
#     (a "cors-misconfig" on a marketing homepage looks nothing like a real
#     exposed panel — vision kills those FPs). Each finding gets a throwaway temp
#     dir containing ONLY its own screenshot; Claude is Read-scoped to that dir
#     (--tools Read --add-dir --permission-mode dontAsk), never the filesystem.
#   * RICH CONTEXT: the finding is enriched with ES asset truth (tech/title/
#     server/status/content-type/final-url + the gate's nuclei evidence).
#   * SCHEMA-VALIDATED OUTPUT: --json-schema -> .structured_output (no regex
#     scraping of free text; unparseable => safe needs-human).
#   * SMARTER ESCALATION: re-judge with the big model on genuine ambiguity OR a
#     LOW-CONFIDENCE real/fp call (a confidently-wrong verdict is the real risk).
#
# Runs as the daemon user (d0k) — Claude Code auth (~/.claude/.credentials.json) is
# per-user. NOT target-facing (pure reasoning over stored evidence), so no Mullvad
# requirement, but we still honour vpn_down to stay quiet during incidents.
# NOTE: never pass --bare (it forces ANTHROPIC_API_KEY auth and ignores the Max
# OAuth login this pipeline runs on).
# =============================================================================
set -uo pipefail
IFS=$'\n\t'

log()  { printf '[%s AI-REVIEW] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s AI-REVIEW WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/recon_net.sh" 2>/dev/null || true   # discord_hook / discord_post (#review)
BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
V3_DB="${V3_DB:-$BASE_DIR/v3/findings.db}"
STATE_PY="${STATE_PY:-$SCRIPT_DIR/../engine/state.py}"
# absolute path — claude is a native install in ~/.local/bin (not always on PATH)
CLAUDE_BIN="${CLAUDE_BIN:-$HOME/.local/bin/claude}"; [[ -x "$CLAUDE_BIN" ]] || CLAUDE_BIN="$(command -v claude 2>/dev/null || echo '')"
CLAUDE_MODEL="${CLAUDE_MODEL:-sonnet}"           # verification model (match-to-task: sonnet)
CLAUDE_ESCALATE="${CLAUDE_ESCALATE:-1}"          # 1 = re-judge the hard calls with the big model
CLAUDE_ESCALATE_MODEL="${CLAUDE_ESCALATE_MODEL:-opus}"  # the "hard call" model
CLAUDE_ESCALATE_CONF="${CLAUDE_ESCALATE_CONF:-0.75}"    # also escalate a real/fp call below this confidence
# CONSENSUS PANEL — the FP-elimination engine. A finding heading toward 'real' (or any
# uncertain call) must survive a panel of independent ADVERSARIAL lenses, each trying to
# REFUTE it from a distinct angle. 'real' requires UNANIMOUS confirm; a majority refute ->
# fp; otherwise needs-human. Cheap confident fps skip the panel (bulk noise dies in 1 pass).
CONSENSUS_ENABLED="${CONSENSUS_ENABLED:-1}"
CONSENSUS_MODEL="${CONSENSUS_MODEL:-${CLAUDE_ESCALATE_MODEL:-opus}}"  # the panel uses the strong model
CONSENSUS_LENSES="${CONSENSUS_LENSES:-exploitability scope-reward evidence-repro}"
FP_FAST_CONF="${FP_FAST_CONF:-0.85}"             # primary fp at/above this conf skips the panel
VERIFY_VISION="${VERIFY_VISION:-1}"              # 1 = feed the asset screenshot to Claude (multimodal)
SAFE_PROBE_ENABLED="${SAFE_PROBE_ENABLED:-1}"    # 1 = Claude may REQUEST safe probes; the HARNESS runs them
PROBE_ROUNDS="${PROBE_ROUNDS:-2}"                # max re-probe rounds per finding
PROBE_BUDGET="${PROBE_BUDGET:-6}"                # max total probes per finding (anti-runaway)
SAFE_PROBE="${SAFE_PROBE:-$SCRIPT_DIR/recon_safe_probe.sh}"
AI_REVIEW_BATCH="${AI_REVIEW_BATCH:-15}"         # findings per cycle (quota-bounded)
# INTAKE NOISE PRE-SCREEN (1A, 2026-07-24): documented structural-noise classes (shared-tenant
# per-customer consoles / third-party-repo secrets / SPA-shell-200) are 100%-fp'd by the reviewer
# anyway and were FLOODING the queue post the 06-17/06-18 lane additions — starving genuine
# candidates of the per-cycle review budget. Auto-dismiss them here (still a recorded ai_verdict,
# so no gate bypass) WITHOUT spending a Claude pass. Uses tools/brief_filter.py as the single
# source of truth. Reversible: INTAKE_PRESCREEN=0.
INTAKE_PRESCREEN="${INTAKE_PRESCREEN:-1}"
BRIEF_FILTER="${BRIEF_FILTER:-$SCRIPT_DIR/../tools/brief_filter.py}"
CLAUDE_TIMEOUT="${CLAUDE_TIMEOUT:-180}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"
INDEX_NAME="${INDEX_NAME:-recon_alive}"
NETRC="${NETRC:-$HOME/.recon_es_netrc}"          # ES verdict-mirror + context is best-effort (skipped if absent)
KB_CONTEXT="${KB_CONTEXT:-3}"                     # prior KB lessons injected into the prompt
es() { curl -fsS -m 20 --netrc-file "$NETRC" -H 'Content-Type: application/json' "$@"; }

# Strict structured-output contract — validated by the CLI, returned in
# .structured_output. screen_assessment is optional (only set when a shot is viewed).
VERDICT_SCHEMA='{"type":"object","additionalProperties":false,"properties":{"verdict":{"type":"string","enum":["real","fp","needs-human","need-probe"]},"confidence":{"type":"number","minimum":0,"maximum":1},"reason":{"type":"string"},"screen_assessment":{"type":"string"},"probe_requests":{"type":"array","maxItems":6,"items":{"type":"object","additionalProperties":false,"properties":{"url":{"type":"string"},"method":{"type":"string","enum":["GET","HEAD","OPTIONS"]},"why":{"type":"string"}},"required":["url","method"]}}},"required":["verdict","confidence","reason"]}'

mkdir -p "$STATE_DIR"
exec 9>"$STATE_DIR/ai_review.lock"; flock -n 9 || { warn "ai-review already running"; exit 0; }
[[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down — skipping"; exit 0; }
[[ -n "$CLAUDE_BIN" && -x "$CLAUDE_BIN" ]] || { warn "claude CLI not found ($CLAUDE_BIN) — skipping (deterministic confidence stands)"; exit 0; }
command -v python3 >/dev/null 2>&1 || { warn "python3 missing"; exit 0; }
command -v jq      >/dev/null 2>&1 || { warn "jq missing"; exit 0; }
[[ -f "$STATE_PY" ]] || { warn "state.py missing"; exit 0; }

# one-time headless sanity (cheap) — bail quietly if auth/headless is broken
timeout 60 "$CLAUDE_BIN" -p "Reply with exactly: OK" 2>/dev/null | grep -q "OK" \
  || { warn "claude headless not responding (auth?) — skipping"; exit 0; }

pending="$(V3_DB="$V3_DB" python3 "$STATE_PY" ai-pending "$AI_REVIEW_BATCH" 2>/dev/null)"
n="$(printf '%s' "$pending" | jq 'length' 2>/dev/null || echo 0)"
[[ "${n:-0}" -gt 0 ]] || { log "no confirmed findings pending validation"; exit 0; }
log "🧠 ─── CLAUDE VERIFY ─── $n confirmed finding(s) · model=$CLAUDE_MODEL · vision=$VERIFY_VISION · probe=$SAFE_PROBE_ENABLED (Max, no API) ───"

# ---- prompt (globals: HAS_SHOT, SHOT_AT) -----------------------------------
_prompt() {
  local f="$1" kb="$2" probe_results="${3:-}" shot_block="" probe_block="" results_block=""
  if [[ "$HAS_SHOT" == "1" ]]; then
    shot_block="A SCREENSHOT of this asset is saved as ./screenshot.jpg in your working
directory (captured ${SHOT_AT:-unknown}). READ and VIEW it — it is PRIMARY evidence.
What is actually on screen is decisive: a genuinely exposed admin panel / dashboard /
directory listing / unauthenticated app looks nothing like a login wall, a marketing or
parking page, or a CDN/WAF/404 error. If the screenshot contradicts the finding (e.g.
it is just a marketing page or a login wall with nothing exposed) that is strong fp
evidence. Record a one-line screen_assessment of what you actually saw.
"
  fi
  if [[ "$SAFE_PROBE_ENABLED" == "1" ]]; then
    probe_block="ACTIVE VERIFICATION — you may run SAFE tests. If you cannot decide from the
evidence and need to see whether the finding actually responds/leaks WITHOUT
authentication, set verdict=\"need-probe\" and list probe_requests (each: a url + method
GET/HEAD/OPTIONS, up to 6). A TRUSTED HARNESS — not you — executes them safely:
unauthenticated, non-destructive, scope-checked, NO redirect-follow, NO internal/metadata
targets, rate-limited, Mullvad-only — and returns the real responses for your final
verdict. Use it e.g. to GET the matched URL and see if the sensitive surface is genuinely
reachable unauthenticated vs. a login wall / 404 / marketing page. Do NOT request a probe
if the screenshot + evidence already settle it; when you have enough, return real/fp/needs-human.
If a probe RESULT is a refusal (ok=false: rate-limited / host-cooldown / global-pause /
out-of-scope / budget), do NOT repeat it — judge from what you already have, or return
needs-human. Be economical: request only the few probes that would actually change the verdict.
"
  fi
  [[ -n "$probe_results" ]] && results_block="PROBE RESULTS (real responses from the safe harness — base your verdict on these):
$probe_results
"
  cat <<EOF
You are an adversarial bug-bounty VALIDATION analyst. Judge the finding below using the
evidence provided (the finding JSON, the asset context, the past outcomes, the screenshot
if present, and any probe results). Your job is to DISPROVE it: treat it as a false
positive until the evidence proves a genuine, reportable, in-scope security issue.

Mark "real" ONLY for an actually exploitable/exposed primitive (e.g. an unauthenticated
admin surface genuinely reachable, a confirmed credential/data leak, a working
access-control bypass). Mark "fp" for noise: version/banner-only detections,
informational/cosmetic nuclei hits, CORS/security-header niggles with no impact,
reflected-but-encoded values, a marketing/login page behind a scary-sounding template,
anything not exploitable as described. Mark "needs-human" ONLY if genuinely ambiguous AND
a safe probe cannot resolve it.

SUBDOMAIN TAKEOVER — special rule: mark "real" ONLY when the CNAME target genuinely NXDOMAINs
(the backing resource is gone and the name is freely registerable). An HTTP fingerprint while
the target still RESOLVES is NOT confirmable — Heroku "No such app", Fastly "unknown domain", a
provider 404, an Azure app that still resolves: these mean *possibly* unclaimed, NOT takeable.
Real claimability requires REGISTERING the name (which we never do) and most providers now
verify ownership or reserve old names. Default such cases to "needs-human", never "real".

${shot_block}${probe_block}${results_block}
PAST OUTCOMES on similar stacks (lessons — if a similar case was fp, lean fp; if real,
that raises plausibility; reason for yourself, do not blindly copy):
${kb:-  (none yet)}

FINDING + ASSET CONTEXT (JSON):
$f

Give: verdict, confidence 0.0-1.0, one specific-sentence reason, a one-line
screen_assessment if you viewed a screenshot, and probe_requests if verdict=need-probe.
EOF
}

# judge <model> -> "verdict<TAB>confidence<TAB>reason" via a bounded SAFE-PROBE loop.
# Globals: f, kb, EV_DIR, HAS_SHOT. Claude only ever gets Read (the screenshot, path-
# confined). It REQUESTS probes via structured output; the trusted HARNESS runs them
# through the guarded recon_safe_probe.sh — Claude has NO execution capability.
judge() {
  local model="$1" out so v c r sa reqs nreq pr_results="" round=0
  local -a targs
  if [[ "$HAS_SHOT" == "1" ]]; then
    targs=(--tools Read --add-dir "$EV_DIR" --permission-mode dontAsk)   # screenshot only; path-confined
  else
    targs=(--tools "")   # no tools at all — pure reasoning (probes are harness-run, never a Claude tool)
  fi
  local ledger="$EV_DIR/probes.log"; : > "$ledger"
  while : ; do
    out="$( cd "${EV_DIR:-/tmp}" && timeout "$CLAUDE_TIMEOUT" "$CLAUDE_BIN" -p "$(_prompt "$f" "$kb" "$pr_results")" \
            --model "$model" "${targs[@]}" --no-session-persistence \
            --json-schema "$VERDICT_SCHEMA" --output-format json </dev/null 2>/dev/null )"
    so="$(printf '%s' "$out" | jq -c '.structured_output // empty' 2>/dev/null)"
    if [[ -z "$so" || "$so" == "null" ]]; then
      so="$(printf '%s' "$out" | jq -r '.result // empty' 2>/dev/null | grep -oE '\{.*"verdict".*\}' | head -1)"
    fi
    v="$(printf '%s'  "$so" | jq -r '.verdict // empty' 2>/dev/null)"
    c="$(printf '%s'  "$so" | jq -r '(.confidence // 0.5)|tostring' 2>/dev/null)"
    r="$(printf '%s'  "$so" | jq -r '.reason // "no reason"' 2>/dev/null)"
    sa="$(printf '%s' "$so" | jq -r '.screen_assessment // empty' 2>/dev/null)"
    # ACTIVE VERIFICATION: run requested probes through the guarded harness, then re-judge
    if [[ "$v" == "need-probe" && "$SAFE_PROBE_ENABLED" == "1" && "$round" -lt "$PROBE_ROUNDS" ]]; then
      reqs="$(printf '%s' "$so" | jq -c '.probe_requests // []' 2>/dev/null)"
      nreq="$(printf '%s' "$reqs" | jq 'length' 2>/dev/null || echo 0)"
      if [[ "${nreq:-0}" -gt 0 ]]; then
        round=$((round+1)); local got="" pi purl pm pres
        for ((pi=0; pi<nreq; pi++)); do
          purl="$(printf '%s' "$reqs" | jq -r ".[$pi].url // empty" 2>/dev/null)"
          pm="$(printf  '%s' "$reqs" | jq -r ".[$pi].method // \"GET\"" 2>/dev/null)"
          [[ -z "$purl" ]] && continue
          pres="$(SAFE_PROBE_LEDGER="$ledger" SAFE_PROBE_BUDGET="$PROBE_BUDGET" bash "$SAFE_PROBE" "$purl" "$pm" 2>/dev/null)"
          [[ -n "$pres" ]] || pres='{"ok":false,"error":"no-output"}'
          got+="$(jq -nc --arg u "$purl" --arg m "$pm" --argjson res "$pres" '{url:$u,method:$m,result:$res}' 2>/dev/null)"$'\n'
        done
        pr_results+="$got"
        log "   🔍 probe round $round ($nreq req): $(printf '%s' "$reqs" | jq -r '[.[].url]|join(", ")' 2>/dev/null | cut -c1-90)"
        continue   # re-judge with the real responses
      fi
    fi
    break
  done
  printf '%s' "$pr_results" > "$EV_DIR/pr.txt" 2>/dev/null || true   # hand probe evidence to the panel (judge runs in a subshell)
  [[ -n "$sa" && "$sa" != "null" ]] && r="$r [screen: $sa]"
  case "$v" in
    real|fp|needs-human) ;;
    need-probe) v="needs-human"; r="$r (active-probe budget/rounds exhausted)" ;;
    *) v="needs-human"; c="0.3"; r="claude verdict unparseable — defaulting to human review" ;;
  esac
  printf '%s\t%s\t%s' "$v" "$c" "$r"
}

# ---- CONSENSUS PANEL: independent adversarial lenses (the FP-elimination engine) -------
LENS_SCHEMA='{"type":"object","additionalProperties":false,"properties":{"vote":{"type":"string","enum":["confirm","refute","unsure"]},"confidence":{"type":"number","minimum":0,"maximum":1},"reason":{"type":"string"}},"required":["vote","reason"]}'

_lens_prompt() {   # lens, f, kb, pr  (globals: HAS_SHOT, SHOT_AT)
  local lens="$1" f="$2" kb="$3" pr="$4" mandate="" shot=""
  case "$lens" in
    exploitability) mandate="LENS = EXPLOITABILITY. Try to REFUTE that this is an actually
exploitable / exposed UNAUTHENTICATED security primitive. Vote 'refute' if it is only
informational, version/banner-only, a cosmetic security-header/CORS nit, a login wall with
nothing behind it, reflected-but-encoded, a parking/marketing page, or otherwise not
exploitable as described. Vote 'confirm' ONLY if a concrete unauth primitive is genuinely
present and reachable." ;;
    scope-reward)   mandate="LENS = SCOPE & REWARD. Try to REFUTE that a bug-bounty program
would actually PAY for this. Vote 'refute' if it is out-of-scope, non-paying, a likely
DUPLICATE, a known-accepted-risk / best-practice / informational class that programs close
as N/A or Informative, or severity too low to reward. Vote 'confirm' ONLY if it is in-scope,
reward-eligible, and not an obvious duplicate." ;;
    evidence-repro) mandate="LENS = EVIDENCE & REPRODUCIBILITY. Try to REFUTE that the concrete
evidence here actually PROVES the issue is real and reproducible RIGHT NOW. Weigh the probe
responses and the screenshot. Vote 'refute' if the evidence is stale, ambiguous, circumstantial,
or does not actually demonstrate the claimed issue. Vote 'confirm' ONLY if the evidence
concretely demonstrates it." ;;
    *) mandate="LENS = GENERAL. Adversarially try to REFUTE that this is a real, reportable,
in-scope security finding. Confirm only if it clearly is." ;;
  esac
  [[ "$HAS_SHOT" == "1" ]] && shot="A screenshot ./screenshot.jpg is in your working directory — READ and VIEW it as evidence."
  cat <<EOF
You are ONE adversarial reviewer on a CONSENSUS PANEL deciding whether a bug-bounty finding
is REAL and report-worthy. Judge ONLY through your assigned lens; be skeptical and try to
DISPROVE. A wrong 'confirm' wastes a researcher's signal on an N/A report — so default to
'refute' unless your lens is genuinely satisfied.

$mandate
$shot

PROBE EVIDENCE already gathered (real responses):
${pr:-  (none)}
PAST OUTCOMES (KB):
${kb:-  (none yet)}
FINDING + ASSET CONTEXT (JSON):
$f

Output your vote (confirm | refute | unsure) for YOUR lens only, a confidence 0-1, and a
one-sentence reason.
EOF
}

# lens_vote <model> <lens> -> "vote<TAB>conf<TAB>reason". Globals: f, kb, EV_DIR, HAS_SHOT, PR_LAST
lens_vote() {
  local model="$1" lens="$2" out so v c r pr
  pr="$(cat "$EV_DIR/pr.txt" 2>/dev/null || true)"
  local -a targs
  if [[ "$HAS_SHOT" == "1" ]]; then targs=(--tools Read --add-dir "$EV_DIR" --permission-mode dontAsk); else targs=(--tools ""); fi
  out="$( cd "${EV_DIR:-/tmp}" && timeout "$CLAUDE_TIMEOUT" "$CLAUDE_BIN" -p "$(_lens_prompt "$lens" "$f" "$kb" "$pr")" \
          --model "$model" "${targs[@]}" --no-session-persistence --json-schema "$LENS_SCHEMA" --output-format json </dev/null 2>/dev/null )"
  so="$(printf '%s' "$out" | jq -c '.structured_output // empty' 2>/dev/null)"
  v="$(printf '%s' "$so" | jq -r '.vote // "unsure"' 2>/dev/null)"
  c="$(printf '%s' "$so" | jq -r '(.confidence // 0.5)|tostring' 2>/dev/null)"
  r="$(printf '%s' "$so" | jq -r '.reason // ""' 2>/dev/null)"
  case "$v" in confirm|refute|unsure) ;; *) v="unsure" ;; esac
  printf '%s\t%s\t%s' "$v" "$c" "$r"
}

# ---- needs-human escalation guard (restored 2026-07-24) --------------------------------
# A confident primary `fp` that CONCEDES the finding is technically genuine/real but killed
# ONLY on scope / duplicate / compliance / venue grounds is NOT bulk noise — it is a borderline
# the operator should SEE (scope changes; a "dup" call can be wrong; an OOS-but-real bug may have
# a VDP path). Route those to needs-human (batched into the nightly briefing) instead of a silent
# cheap-fp kill. Pure noise (scan-artifact / shared-tenant / by-design / regex-misfire) still dies
# cheaply. Env-overridable so the operator can retune/disable.
NH_ESCALATE_ENABLED="${NH_ESCALATE_ENABLED:-1}"
NH_GENUINE_RE="${NH_GENUINE_RE:-(\b(genuine|genuinely|actually (exposed|reachable|claimable|vulnerable|present|works)|is a real|really is|valid (bug|finding|primitive|issue)|legit(imate)?|claimable|confirmed (unauth|primitive|exposure)|exploitable (primitive|unauth))\b|\breal (\w+ ){0,3}(primitive|bug|finding|exposure|issue|vuln|takeover|endpoint|exposed|leak))}"
NH_SCOPEKILL_RE="${NH_SCOPEKILL_RE:-\b(out[- ]?of[- ]?scope|non-?paying|not[^.]{0,8}paying|no bounty|duplicate|\bdup\b|compliance|dead[- ]?zone|unreportable|not eligible|ineligible|wrong venue|carve-?out|already reported)\b}"
NH_PIVOT_RE="${NH_PIVOT_RE:-\b(but|however|though|yet)\b}"
NH_PURE_NOISE_RE="${NH_PURE_NOISE_RE:-scan[- ]?artifact|shared[- ]?tenant|per-customer tenant|regex (misfire|misread|misfires)|by[- ]?design|zero values|spa[- ]?shell|acks every port|not a real finding|schema keys|marketing (page|site)|parking page}"

# consensus -> sets globals FINAL_V / FINAL_C / FINAL_R / model_used / RAN_PANEL.
# Claude is the brain: the PRIMARY pass investigates (multimodal + probe); a confident fp
# dies cheaply; everything heading toward 'real' (or uncertain) is adjudicated by the panel.
consensus() {
  RAN_PANEL=0
  IFS=$'\t' read -r FINAL_V FINAL_C FINAL_R <<<"$(judge "$CLAUDE_MODEL")"; model_used="$CLAUDE_MODEL"
  # real-but-unreportable -> escalate to human instead of a silent confident-fp cheap-kill
  if [[ "$NH_ESCALATE_ENABLED" == "1" && "$FINAL_V" == "fp" ]] && ! _lt "${FINAL_C:-0}" "$FP_FAST_CONF" \
     && printf '%s' "$FINAL_R" | grep -qiE "$NH_GENUINE_RE" \
     && printf '%s' "$FINAL_R" | grep -qiE "$NH_SCOPEKILL_RE" \
     && printf '%s' "$FINAL_R" | grep -qiE "$NH_PIVOT_RE" \
     && ! printf '%s' "$FINAL_R" | grep -qiE "$NH_PURE_NOISE_RE"; then
    FINAL_V="needs-human"; FINAL_C="0.5"
    FINAL_R="ESCALATED real-but-unreportable → operator eyeball (scope/dup/compliance may change). [orig-fp: $FINAL_R]"
    log "        ↳ 🟡 escalated real-but-unreportable fp → needs-human"
    return
  fi
  # cheap kill: a confident fp does not need the panel (bulk noise)
  if [[ "$FINAL_V" == "fp" ]] && ! _lt "${FINAL_C:-0}" "$FP_FAST_CONF"; then return; fi
  if [[ "$CONSENSUS_ENABLED" != "1" ]]; then
    # consensus off -> fall back to single escalation on ambiguity / low-confidence
    if [[ -n "$CLAUDE_ESCALATE_MODEL" && "$CLAUDE_ESCALATE_MODEL" != "$CLAUDE_MODEL" ]]; then
      if [[ "$FINAL_V" == "needs-human" ]] || { [[ "$FINAL_V" == "real" || "$FINAL_V" == "fp" ]] && _lt "${FINAL_C:-0}" "$CLAUDE_ESCALATE_CONF"; }; then
        IFS=$'\t' read -r FINAL_V FINAL_C FINAL_R <<<"$(judge "$CLAUDE_ESCALATE_MODEL")"
        FINAL_R="$FINAL_R (escalated:$CLAUDE_ESCALATE_MODEL)"; model_used="$CLAUDE_ESCALATE_MODEL"; RAN_PANEL=1
      fi
    fi
    return
  fi
  # PANEL: independent adversarial lenses try to refute
  RAN_PANEL=1
  local confirms=0 refutes=0 unsures=0 nlens=0 lens lvote lconf lr notes=""
  local -a LENS_ARR; IFS=' ' read -ra LENS_ARR <<< "$CONSENSUS_LENSES"   # split on space (global IFS lacks it)
  for lens in "${LENS_ARR[@]}"; do
    nlens=$((nlens+1))
    IFS=$'\t' read -r lvote lconf lr <<<"$(lens_vote "$CONSENSUS_MODEL" "$lens")"
    case "$lvote" in confirm) confirms=$((confirms+1)) ;; refute) refutes=$((refutes+1)) ;; *) unsures=$((unsures+1)) ;; esac
    notes+="[$lens:$lvote] $lr | "
    log "      🔬 $lens → $lvote (${lconf})"
  done
  local refute_majority=$(( (nlens/2) + 1 ))
  model_used="${CLAUDE_MODEL}+panel($CONSENSUS_MODEL×$nlens)"
  if [[ "$confirms" -eq "$nlens" && "$nlens" -gt 0 ]]; then
    FINAL_V="real"; FINAL_C="0.95"; FINAL_R="CONSENSUS REAL ($confirms/$nlens unanimous). $notes"
  elif [[ "$refutes" -ge "$refute_majority" ]]; then
    FINAL_V="fp"; FINAL_C="0.9"; FINAL_R="CONSENSUS FP ($refutes/$nlens refuted). $notes"
  else
    FINAL_V="needs-human"; FINAL_C="0.5"; FINAL_R="CONSENSUS SPLIT (confirm=$confirms refute=$refutes unsure=$unsures). $notes"
  fi
}

# ---- Claude-AUTHORED report (quality -> reports -> rewards) -----------------------------
REPORT_SCHEMA='{"type":"object","additionalProperties":false,"properties":{"title":{"type":"string"},"severity":{"type":"string","enum":["Critical","High","Medium","Low","Informational"]},"cvss_score":{"type":"number","minimum":0,"maximum":10},"cvss_vector":{"type":"string"},"impact":{"type":"string"},"poc_steps":{"type":"array","maxItems":10,"items":{"type":"string"}},"dedup_assessment":{"type":"string"},"reward_likelihood":{"type":"number","minimum":0,"maximum":1},"recommended_action":{"type":"string","enum":["submit","hold-needs-more"]}},"required":["title","severity","impact","poc_steps","recommended_action"]}'

# author_report <model> -> JSON report packet (or empty). Globals: f, EV_DIR, HAS_SHOT, FINAL_R
author_report() {
  local model="$1" out pr shotline=""
  pr="$(cat "$EV_DIR/pr.txt" 2>/dev/null || true)"
  local -a targs
  if [[ "$HAS_SHOT" == "1" ]]; then targs=(--tools Read --add-dir "$EV_DIR" --permission-mode dontAsk); shotline="A screenshot ./screenshot.jpg is in your working dir — view it as evidence."; else targs=(--tools ""); fi
  out="$( cd "${EV_DIR:-/tmp}" && timeout "$CLAUDE_TIMEOUT" "$CLAUDE_BIN" -p "$(cat <<EOF
You are writing a bug-bounty report for a CONFIRMED, panel-validated finding. Produce a
high-quality, HONEST report packet. CRITICAL: do NOT overclaim severity — an overclaimed
report gets closed N/A and damages researcher signal. Rate severity to what a triager would
ACTUALLY accept given ONLY the evidence below. PoC steps must be reproducible and read-only
(the PoC is "this responds/leaks without auth", never a data harvest). Assess duplicate and
reward likelihood honestly; set recommended_action='submit' only if genuinely report-worthy,
else 'hold-needs-more'.

$shotline
PROBE EVIDENCE (real responses):
${pr:-  (none)}
FINDING + ASSET CONTEXT (JSON):
$f
PANEL VERDICT + REASONING: $FINAL_R
EOF
)" --model "$model" "${targs[@]}" --no-session-persistence --json-schema "$REPORT_SCHEMA" --output-format json </dev/null 2>/dev/null )"
  printf '%s' "$out" | jq -c '.structured_output // empty' 2>/dev/null
}

_lt() { awk "BEGIN{exit !(($1)<($2))}"; }   # float less-than (exit 0 if $1<$2)

reviewed=0; real=0; fp=0; human=0; escalated=0; withshot=0; prefiltered=0
while IFS= read -r fjson; do
  [[ -z "$fjson" ]] && continue
  [[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down mid-run — stopping"; break; }
  fid="$(printf '%s' "$fjson" | jq -r '.id')"
  host="$(printf '%s' "$fjson" | jq -r '.host')"
  vclass="$(printf '%s' "$fjson" | jq -r '.vuln_class // ""')"
  sclass="$(printf '%s' "$fjson" | jq -r '.signal_class // ""')"
  program="$(printf '%s' "$fjson" | jq -r '.program // ""')"

  # ---- INTAKE NOISE PRE-SCREEN (1A): auto-dismiss documented structural noise before any
  # Claude pass (frees the per-cycle budget for genuine candidates). Two probes, both via
  # brief_filter.py: (a) --host flags a shared-tenant per-customer console (unifi-hosting UUID
  # etc. = third-party data, hard line); (b) --noise flags third-party-repo secrets / SPA-shell
  # / >6-port scan-artifacts that fire on the finding's own fields. Degrades safely (ES down =>
  # no shared-tenant hit => normal review). Still records a real ai_verdict (fp) — no gate bypass.
  if [[ "$INTAKE_PRESCREEN" == "1" && -n "$host" && "$host" != "null" && -f "$BRIEF_FILTER" ]]; then
    ps_reason=""
    if [[ "$(python3 "$BRIEF_FILTER" --host "$host" 2>/dev/null | jq -r '.shared_tenant // false' 2>/dev/null)" == "true" ]]; then
      ps_reason="shared-tenant per-customer console (third-party data, hard line)"
    else
      pf="$(printf '[%s]' "$fjson" | python3 "$BRIEF_FILTER" --noise 2>/dev/null | jq -r '.suppressed[0]._noise_class // empty' 2>/dev/null)"
      case "$pf" in
        ">6-critical-ports-scan-artifact"|third-party-repo-secret|spa-shell-200-all-routes) ps_reason="$pf" ;;
      esac
    fi
    if [[ -n "$ps_reason" ]]; then
      V3_DB="$V3_DB" python3 "$STATE_PY" ai-verdict "$fid" "fp" "0.9" \
        "structural-prefilter: $ps_reason — documented noise class, auto-dismissed without a review pass" >/dev/null 2>&1 || true
      prefiltered=$((prefiltered+1)); reviewed=$((reviewed+1)); fp=$((fp+1))
      log "   ⏭  prefilter fp: $host · $ps_reason"
      continue
    fi
  fi

  # enrich from ES: asset context + screenshot path (one fetch, best-effort)
  ctx='{}'; tech=""; shot=""; SHOT_AT=""
  if [[ -f "$NETRC" ]]; then
    src="$(es "$ES_URL/$INDEX_NAME/_source/$host" 2>/dev/null || echo '{}')"
    ctx="$(printf '%s' "$src" | jq -c '{tech:(.tech//[]),title:(.title//""),webserver:(.webserver//""),status_code:(.status_code//0),content_type:(.content_type//""),final_url:(.final_url//""),gate_evidence:(.triage_gate_evidence//{}),screenshot_at:(.screenshot_at//"")}' 2>/dev/null || echo '{}')"
    [[ -z "$ctx" || "$ctx" == "null" ]] && ctx='{}'
    tech="$(printf '%s' "$ctx" | jq -r '(.tech//[])|join(",")' 2>/dev/null)"
    SHOT_AT="$(printf '%s' "$ctx" | jq -r '.screenshot_at // ""' 2>/dev/null)"
    shot="$(printf '%s' "$src" | jq -r '.screenshot_path // empty' 2>/dev/null)"
  fi

  kb="$(V3_DB="$V3_DB" python3 "$STATE_PY" kb-lookup "$tech" "$vclass" "$host" "$KB_CONTEXT" 2>/dev/null \
        | jq -r '.[]? | "  * [\(.verdict)] \(.host) (\(.tech // "?")) \(.vuln_class // "?"): \(.reason // "")"' 2>/dev/null)"

  # enriched finding packet for the prompt
  f="$(jq -nc --argjson fnd "$fjson" --argjson c "$ctx" '$fnd + {asset_context:$c}' 2>/dev/null || printf '%s' "$fjson")"

  # per-finding evidence dir — contains ONLY this finding's screenshot (nothing sensitive)
  EV_DIR="$(mktemp -d "${TMPDIR:-/tmp}/claude_verify.XXXXXX")"; HAS_SHOT=0
  if [[ "$VERIFY_VISION" == "1" && -n "$shot" && -f "$shot" ]]; then
    cp -f "$shot" "$EV_DIR/screenshot.jpg" 2>/dev/null && { HAS_SHOT=1; withshot=$((withshot+1)); }
  fi

  consensus    # Claude is the brain: primary investigates (multimodal+probe) -> adversarial panel adjudicates
  v="$FINAL_V"; c="$FINAL_C"; r="$FINAL_R"
  [[ "${RAN_PANEL:-0}" == "1" ]] && escalated=$((escalated+1))

  # ---- TAKEOVER GUARD (doctrine): never auto-`real` unless the CNAME target NXDOMAINs ----
  # A takeover is only confirmable when the backing resource is GONE -> the CNAME target
  # NXDOMAINs -> the name is freely registerable. An HTTP fingerprint while the target still
  # RESOLVES (Heroku "No such app", Fastly "unknown domain", a provider 404) is NOT a confirmed
  # takeover: claimability requires REGISTERING the name (unprovable without exploitation; many
  # providers now block it / verify ownership). Cap those at needs-human so the operator checks
  # registerability by hand. (proven FP: railing.meraki.com Heroku "No such app", conf 0.95.)
  if [[ "$sclass" == "takeover" && "$v" == "real" ]]; then
    tcname="$(dig +short CNAME "$host" 2>/dev/null | head -1)"
    if [[ -n "$tcname" ]]; then
      tstat="$(dig "${tcname%.}" 2>/dev/null | grep -oE 'status: [A-Z]+' | head -1)"
      if [[ "$tstat" != *NXDOMAIN* ]]; then
        v="needs-human"; c="0.5"
        r="TAKEOVER GUARD: CNAME target ${tcname%.} RESOLVES (not NXDOMAIN) — HTTP fingerprint ≠ registerable; claimability needs a human registerability check, not auto-real. [orig: ${r}]"
        log "        ↳ ⚠ takeover capped real→needs-human (${tcname%.} resolves, not NXDOMAIN)"
      fi
    fi
  fi
  # Claude AUTHORS the report for a real finding (quality -> rewards), before evidence is cleaned
  if [[ "$v" == "real" ]]; then
    rep="$(author_report "$CONSENSUS_MODEL")"
    if [[ -n "$rep" && "$rep" != "null" ]]; then
      V3_DB="$V3_DB" python3 "$STATE_PY" set-report "$fid" "$rep" >/dev/null 2>&1 || true
      log "        ↳ 📝 report authored ($(printf '%s' "$rep" | jq -r '"\(.severity) · \(.recommended_action) · reward~\(.reward_likelihood // "?")"' 2>/dev/null))"
    fi
  fi
  rm -rf "$EV_DIR" 2>/dev/null || true

  V3_DB="$V3_DB" python3 "$STATE_PY" ai-verdict "$fid" "$v" "$c" "$r" >/dev/null 2>&1 || true
  # learn: append the outcome to the knowledge base (the RAG-lite corpus the agents query)
  V3_DB="$V3_DB" python3 "$STATE_PY" kb-record "$host" "$program" "$tech" "$sclass" "$vclass" "$v" "$c" "ai-verify" "$r" >/dev/null 2>&1 || true
  # mirror Claude's verdict into ES (asset truth) so dashboards/queries/dedup see it
  if [[ -f "$NETRC" ]]; then
    doc="$(jq -nc --arg v "$v" --arg c "$c" --arg r "$r" --arg t "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" --arg m "$model_used" \
            '{claude_verdict:$v, claude_confidence:($c|tonumber? // 0.5), claude_reason:$r, claude_reviewed_at:$t, claude_verify_model:$m}')"
    es -X POST "$ES_URL/$INDEX_NAME/_update/$host" -d "$(jq -nc --argjson d "$doc" '{doc:$d}')" >/dev/null 2>&1 || true
  fi
  # v3 Discord: ping #review LIVE only on a CONFIRMED `real` verdict — the rare,
  # actionable "review & submit" event worth interrupting the operator. `fp` is
  # auto-dismissed silently; `needs-human` is no longer a live ping (it's a "maybe",
  # not actionable right now) — it's batched into the nightly briefing instead. This
  # keeps real-time #review reserved for things that actually warrant attention now.
  if [[ "$v" == "real" ]]; then
    rh="$(discord_hook review 2>/dev/null || true)"
    if [[ -n "$rh" ]]; then
      tag="✅ REAL — review & submit"
      discord_post "$rh" "$(jq -nc --arg t "$tag" --arg h "$host" --arg vc "${vclass:-?}" --arg c "$c" --arg m "$model_used" --arg r "$r" \
        '{content:("**"+$t+"**\n`"+$h+"`  ["+$vc+"]  conf="+$c+"  ("+$m+")\n"+$r+"\n→ APPROVE / DISMISS / INVESTIGATE — human-gated, never auto-submitted")}')" >/dev/null 2>&1 || true
    fi
  fi
  case "$v" in real) vi="🟢 REAL " ;; fp) vi="🔴 FP   " ;; needs-human) vi="🟡 HUMAN" ;; *) vi="·   ?  " ;; esac
  sh=""; [[ "$HAS_SHOT" == "1" ]] && sh=" 📸"
  log "   $vi $host · conf=$c · $model_used$sh"
  log "        ↳ 💬 $r"
  reviewed=$((reviewed+1)); [[ "$v" == real ]] && real=$((real+1)); [[ "$v" == fp ]] && fp=$((fp+1)); [[ "$v" == needs-human ]] && human=$((human+1))
done < <(printf '%s' "$pending" | jq -c '.[]' 2>/dev/null)

log "🧠 verify done · 🟢 $real real · 🔴 $fp fp (⏭ $prefiltered prefiltered) · 🟡 $human human · 🔬 $escalated panel · 📸 $withshot with-shot  (of $reviewed)"

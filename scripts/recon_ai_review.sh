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
VERIFY_VISION="${VERIFY_VISION:-1}"              # 1 = feed the asset screenshot to Claude (multimodal)
SAFE_PROBE_ENABLED="${SAFE_PROBE_ENABLED:-1}"    # 1 = Claude may REQUEST safe probes; the HARNESS runs them
PROBE_ROUNDS="${PROBE_ROUNDS:-2}"                # max re-probe rounds per finding
PROBE_BUDGET="${PROBE_BUDGET:-6}"                # max total probes per finding (anti-runaway)
SAFE_PROBE="${SAFE_PROBE:-$SCRIPT_DIR/recon_safe_probe.sh}"
AI_REVIEW_BATCH="${AI_REVIEW_BATCH:-15}"         # findings per cycle (quota-bounded)
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
  [[ -n "$sa" && "$sa" != "null" ]] && r="$r [screen: $sa]"
  case "$v" in
    real|fp|needs-human) ;;
    need-probe) v="needs-human"; r="$r (active-probe budget/rounds exhausted)" ;;
    *) v="needs-human"; c="0.3"; r="claude verdict unparseable — defaulting to human review" ;;
  esac
  printf '%s\t%s\t%s' "$v" "$c" "$r"
}

_lt() { awk "BEGIN{exit !(($1)<($2))}"; }   # float less-than (exit 0 if $1<$2)

reviewed=0; real=0; fp=0; human=0; escalated=0; withshot=0
while IFS= read -r fjson; do
  [[ -z "$fjson" ]] && continue
  [[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down mid-run — stopping"; break; }
  fid="$(printf '%s' "$fjson" | jq -r '.id')"
  host="$(printf '%s' "$fjson" | jq -r '.host')"
  vclass="$(printf '%s' "$fjson" | jq -r '.vuln_class // ""')"
  sclass="$(printf '%s' "$fjson" | jq -r '.signal_class // ""')"
  program="$(printf '%s' "$fjson" | jq -r '.program // ""')"

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

  IFS=$'\t' read -r v c r <<<"$(judge "$CLAUDE_MODEL")"; model_used="$CLAUDE_MODEL"
  # escalate to the big model on genuine ambiguity OR a low-confidence real/fp call
  if [[ "$CLAUDE_ESCALATE" == "1" && -n "$CLAUDE_ESCALATE_MODEL" && "$CLAUDE_ESCALATE_MODEL" != "$CLAUDE_MODEL" ]]; then
    do_esc=0
    [[ "$v" == "needs-human" ]] && do_esc=1
    { [[ "$v" == "real" || "$v" == "fp" ]] && _lt "${c:-0}" "$CLAUDE_ESCALATE_CONF"; } && do_esc=1
    if [[ "$do_esc" == "1" ]]; then
      IFS=$'\t' read -r v c r <<<"$(judge "$CLAUDE_ESCALATE_MODEL")"
      r="$r (escalated:$CLAUDE_ESCALATE_MODEL)"; model_used="$CLAUDE_ESCALATE_MODEL"; escalated=$((escalated+1))
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
  # v3 Discord: ping the human ONLY on a verdict that needs a decision (real /
  # needs-human). fp is auto-dismissed silently. This is THE human-review trigger.
  if [[ "$v" == "real" || "$v" == "needs-human" ]]; then
    rh="$(discord_hook review 2>/dev/null || true)"
    if [[ -n "$rh" ]]; then
      [[ "$v" == "real" ]] && tag="✅ REAL — review & submit" || tag="🔍 NEEDS-HUMAN — investigate"
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

log "🧠 verify done · 🟢 $real real · 🔴 $fp fp · 🟡 $human human · ↑ $escalated escalated · 📸 $withshot with-shot  (of $reviewed)"

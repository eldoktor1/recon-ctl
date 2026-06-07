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
# This is the article's "validation agent" — but on Max, not the API. The legacy
# Ollama pre-scorer was retired (v3.1): the deterministic EVIDENCE GATE is the cheap
# pre-filter now, and Claude validates the confirmed survivors for accuracy/relevancy.
#
# Runs as the daemon user (d0k) — Claude Code auth (~/.claude/.credentials.json) is
# per-user. NOT target-facing (pure reasoning over stored evidence), so no Mullvad
# requirement, but we still honour vpn_down to stay quiet during incidents.
# =============================================================================
set -uo pipefail
IFS=$'\n\t'

log()  { printf '[%s AI-REVIEW] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s AI-REVIEW WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
V3_DB="${V3_DB:-$BASE_DIR/v3/findings.db}"
STATE_PY="${STATE_PY:-$SCRIPT_DIR/../v3/state.py}"
# absolute path — claude is a native install in ~/.local/bin (not always on PATH)
CLAUDE_BIN="${CLAUDE_BIN:-$HOME/.local/bin/claude}"; [[ -x "$CLAUDE_BIN" ]] || CLAUDE_BIN="$(command -v claude 2>/dev/null || echo '')"
CLAUDE_MODEL="${CLAUDE_MODEL:-sonnet}"          # fast+cheap on quota; override to opus for hard calls
AI_REVIEW_BATCH="${AI_REVIEW_BATCH:-15}"        # findings per cycle (quota-bounded)
CLAUDE_TIMEOUT="${CLAUDE_TIMEOUT:-120}"

mkdir -p "$STATE_DIR"
exec 9>"$STATE_DIR/ai_review.lock"; flock -n 9 || { warn "ai-review already running"; exit 0; }
[[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down — skipping"; exit 0; }
[[ -n "$CLAUDE_BIN" && -x "$CLAUDE_BIN" ]] || { warn "claude CLI not found ($CLAUDE_BIN) — skipping (deterministic confidence stands)"; exit 0; }
command -v python3 >/dev/null 2>&1 || { warn "python3 missing"; exit 0; }
[[ -f "$STATE_PY" ]] || { warn "state.py missing"; exit 0; }

# one-time headless sanity (cheap) — bail quietly if auth/headless is broken
timeout 60 "$CLAUDE_BIN" -p "Reply with exactly: OK" 2>/dev/null | grep -q "OK" \
  || { warn "claude headless not responding (auth?) — skipping"; exit 0; }

pending="$(V3_DB="$V3_DB" python3 "$STATE_PY" ai-pending "$AI_REVIEW_BATCH" 2>/dev/null)"
n="$(printf '%s' "$pending" | jq 'length' 2>/dev/null || echo 0)"
[[ "${n:-0}" -gt 0 ]] || { log "no confirmed findings pending validation"; exit 0; }
log "validating $n confirmed finding(s) with Claude ($CLAUDE_MODEL, Max headless)"

_prompt() {  # finding-json -> adversarial validation prompt
  local f="$1"
  cat <<EOF
You are an adversarial bug-bounty VALIDATION analyst. Judge the finding below using
ONLY the evidence provided. Do NOT make any network request or assume facts not in
the evidence. Your job is to DISPROVE it: treat it as a false positive until the
evidence proves a genuine, reportable, in-scope security issue.

Mark "real" ONLY for an actually exploitable/exposed primitive (e.g. unauth admin
surface reachable, confirmed credential leak, working access-control bypass). Mark
"fp" for noise: version/banner-only detections, informational/cosmetic nuclei hits,
CORS/security-header niggles with no impact, reflected-but-encoded values, anything
not exploitable as described. Mark "needs-human" only if the evidence is genuinely
ambiguous.

FINDING (JSON):
$f

Output ONLY a single-line JSON object — no markdown, no prose, no code fence:
{"verdict":"real|fp|needs-human","confidence":0.0,"reason":"one specific sentence"}
EOF
}

reviewed=0; real=0; fp=0; human=0
while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  [[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down mid-run — stopping"; break; }
  fid="$(printf '%s' "$f" | jq -r '.id')"
  host="$(printf '%s' "$f" | jq -r '.host')"
  out="$(timeout "$CLAUDE_TIMEOUT" "$CLAUDE_BIN" -p "$(_prompt "$f")" --model "$CLAUDE_MODEL" --output-format json </dev/null 2>/dev/null \
         | jq -r '.result // empty' 2>/dev/null)"
  # robust extraction: pull the JSON object even if wrapped in stray text
  verdict_json="$(printf '%s' "$out" | grep -oE '\{[^{}]*"verdict"[^{}]*\}' | head -1)"
  v="$(printf '%s' "$verdict_json" | jq -r '.verdict // empty' 2>/dev/null)"
  c="$(printf '%s' "$verdict_json" | jq -r '(.confidence // 0.5)|tostring' 2>/dev/null)"
  r="$(printf '%s' "$verdict_json" | jq -r '.reason // "no reason"' 2>/dev/null)"
  case "$v" in
    real|fp|needs-human) ;;
    *) v="needs-human"; c="0.3"; r="claude verdict unparseable — defaulting to human review" ;;
  esac
  V3_DB="$V3_DB" python3 "$STATE_PY" ai-verdict "$fid" "$v" "$c" "$r" >/dev/null 2>&1 || true
  log "  $host [$fid] -> $v (conf=$c) $r"
  reviewed=$((reviewed+1)); [[ "$v" == real ]] && real=$((real+1)); [[ "$v" == fp ]] && fp=$((fp+1)); [[ "$v" == needs-human ]] && human=$((human+1))
done < <(printf '%s' "$pending" | jq -c '.[]' 2>/dev/null)

log "ai-review done — reviewed=$reviewed real=$real fp=$fp needs-human=$human"

#!/usr/bin/env bash
# Optional local AI review scorer for already-prioritized triage targets.
set -Eeuo pipefail
IFS=$'\n\t'

log()  { printf '[%s AI] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s AI WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="${BASE_DIR:-$HOME/recon}"
AI_DIR="${AI_DIR:-$BASE_DIR/ai_review}"
IN="${1:-$BASE_DIR/triage/agent_targets.jsonl}"
OUT="$AI_DIR/ai_scored.jsonl"
TMP_DIR="$AI_DIR/tmp"

OLLAMA_URL="${OLLAMA_URL:-http://127.0.0.1:11434}"
OLLAMA_MODEL_LEAD="${OLLAMA_MODEL_LEAD:-llama3.1:8b-instruct-q4_K_M}"
AI_MAX_LEADS="${AI_MAX_LEADS:-25}"
AI_MIN_SCORE="${AI_MIN_SCORE:-15}"

ES_URL="${ES_URL:-http://127.0.0.1:9200}"
INDEX_NAME="${INDEX_NAME:-recon_alive}"
ES_USER="${ES_USER:-elastic}"
ES_PASS="${ES_PASS:-$(tr -d '[:space:]' < "$HOME/.recon_es_pass" 2>/dev/null || true)}"

mkdir -p "$TMP_DIR"
: > "$OUT"

[[ -s "$IN" ]] || { log "no triage input"; exit 0; }
curl -fsS -m 3 "$OLLAMA_URL/api/tags" >/dev/null 2>&1 || {
  warn "Ollama not reachable at $OLLAMA_URL; skipping AI scoring"
  exit 0
}
curl -fsS -m 5 "$OLLAMA_URL/api/tags" \
  | jq -e --arg model "$OLLAMA_MODEL_LEAD" '.models[]?.name == $model' >/dev/null 2>&1 || {
    warn "Ollama model not installed: $OLLAMA_MODEL_LEAD; skipping AI scoring"
    exit 0
  }

updates_tmp="$(mktemp)"
trap "rm -f '$updates_tmp'" EXIT

jq -c --argjson min "$AI_MIN_SCORE" '
  select((.priority == "P0" or .priority == "P1") and (.score // 0) >= $min)
  | select((.out_of_scope // false) == false)
  | select((.payout_tier // "none") != "none")
  | select(((.signals // []) | length) > 0)
' "$IN" | head -n "$AI_MAX_LEADS" | while IFS= read -r lead; do
  host="$(jq -r '.host' <<< "$lead")"
  prompt="$TMP_DIR/${host//[^a-zA-Z0-9_.-]/_}.prompt"

  jq -r '
    "Assess this already-filtered bug bounty recon lead.\n\n" +
    "Return strict JSON with keys: ai_relevance_score, confidence, recommendation, route, reason, safe_checks, risk_flags.\n" +
    "Allowed recommendations: skip, watch, manual_review, test_now.\n" +
    "Allowed routes: none, codex, claude, human.\n" +
    "Only low-impact verification is allowed.\n\nLead JSON:\n" +
    tostring
  ' <<< "$lead" > "$prompt"

  raw="$(bash "$SCRIPT_DIR/recon_ollama.sh" "$OLLAMA_MODEL_LEAD" "$prompt" 2>/dev/null || true)"
  if ! jq -e . >/dev/null 2>&1 <<< "$raw"; then
    warn "invalid AI JSON for $host"
    continue
  fi

  enriched="$(jq -c --argjson ai "$raw" --arg model "$OLLAMA_MODEL_LEAD" '
    . + {ai: ($ai + {model:$model})}
  ' <<< "$lead")"
  printf '%s\n' "$enriched" >> "$OUT"

  jq -c --arg idx "$INDEX_NAME" --arg model "$OLLAMA_MODEL_LEAD" '
    {"update":{"_index":$idx,"_id":.host}},
    {"doc":{
      ai_relevance_score:(.ai.ai_relevance_score // 0),
      ai_confidence:(.ai.confidence // "low"),
      ai_recommendation:(.ai.recommendation // "watch"),
      ai_route:(.ai.route // "human"),
      ai_reason:(.ai.reason // ""),
      ai_safe_checks:(.ai.safe_checks // []),
      ai_risk_flags:(.ai.risk_flags // []),
      ai_model:$model,
      ai_reviewed_at:(now | strftime("%Y-%m-%dT%H:%M:%SZ"))
    }}
  ' <<< "$enriched" >> "$updates_tmp"
done

if [[ -s "$updates_tmp" && -n "$ES_PASS" ]]; then
  curl -fsS -m 30 -u "$ES_USER:$ES_PASS" -H 'Content-Type: application/x-ndjson' \
    -X POST "$ES_URL/_bulk" --data-binary @"$updates_tmp" >/dev/null 2>&1 \
    || warn "AI ES writeback failed"
fi

log "AI-scored $(wc -l < "$OUT" | tr -d ' ') lead(s): $OUT"

#!/usr/bin/env bash
# Build human/Codex/Claude review packets from AI-scored leads.
set -Eeuo pipefail
IFS=$'\n\t'

BASE_DIR="${BASE_DIR:-$HOME/recon}"
AI_DIR="${AI_DIR:-$BASE_DIR/ai_review}"
IN="${1:-$AI_DIR/ai_scored.jsonl}"
PENDING="$AI_DIR/pending"
MIN_AI_RELEVANCE="${MIN_AI_RELEVANCE:-7}"

mkdir -p "$PENDING" "$AI_DIR/codex" "$AI_DIR/claude" "$AI_DIR/done" "$AI_DIR/skipped"
[[ -s "$IN" ]] || exit 0

jq -c --argjson min "$MIN_AI_RELEVANCE" '
  select((.ai.ai_relevance_score // 0) >= $min)
  | select((.ai.recommendation // "skip") != "skip")
' "$IN" | while IFS= read -r lead; do
  host="$(jq -r '.host' <<< "$lead")"
  score="$(jq -r '.ai.ai_relevance_score' <<< "$lead")"
  route="$(jq -r '.ai.route // "human"' <<< "$lead")"
  file="$PENDING/${score}_${route}_${host//[^a-zA-Z0-9_.-]/_}.md"

  jq -r '
    "# AI Review Packet\n\n" +
    "## Target\n" +
    "- Host: " + (.host // "") + "\n" +
    "- URL: " + (.url // "n/a") + "\n" +
    "- Program: " + (.program // "unknown") + "\n" +
    "- Payout tier: " + (.payout_tier // "none") + "\n" +
    "- Priority: " + (.priority // "n/a") + "\n" +
    "- Score: " + ((.score // 0)|tostring) + "\n\n" +
    "## Signals\n" +
    ((.signals // []) | map("- " + .) | join("\n")) + "\n\n" +
    "## AI Judgment\n" +
    "- AI relevance: " + ((.ai.ai_relevance_score // 0)|tostring) + "\n" +
    "- Confidence: " + (.ai.confidence // "low") + "\n" +
    "- Recommendation: " + (.ai.recommendation // "watch") + "\n" +
    "- Route: " + (.ai.route // "human") + "\n\n" +
    "Reason:\n" + (.ai.reason // "") + "\n\n" +
    "## Safe Checks\n" +
    ((.ai.safe_checks // []) | map("- " + .) | join("\n")) + "\n\n" +
    "## Risk Flags\n" +
    ((.ai.risk_flags // []) | map("- " + .) | join("\n")) + "\n\n" +
    "## Instruction\n" +
    "Review this lead. Do not exploit. Decide go/no-go and suggest only low-impact verification.\n"
  ' <<< "$lead" > "$file"
done

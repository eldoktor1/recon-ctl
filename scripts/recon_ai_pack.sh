#!/usr/bin/env bash
# Build human/Codex/Claude review packets from AI-scored leads.
# v2.1: Discord notification for test_now leads with score >= AI_DISCORD_MIN_SCORE.
set -Eeuo pipefail
IFS=$'\n\t'

BASE_DIR="${BASE_DIR:-$HOME/recon}"
AI_DIR="${AI_DIR:-$BASE_DIR/ai_review}"
IN="${1:-$AI_DIR/ai_scored.jsonl}"
PENDING="$AI_DIR/pending"
MIN_AI_RELEVANCE="${MIN_AI_RELEVANCE:-7}"
AI_DISCORD_MIN_SCORE="${AI_DISCORD_MIN_SCORE:-50}"
AI_DISCORD_SEEN="${AI_DISCORD_SEEN:-$AI_DIR/.ai_discord_seen}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Source Discord helpers (discord_hook, discord_post) from recon_net.sh.
# Silently disabled if the file is absent — Discord is optional here.
# shellcheck disable=SC1090
[[ -f "$SCRIPT_DIR/recon_net.sh" ]] && source "$SCRIPT_DIR/recon_net.sh" 2>/dev/null || true

mkdir -p "$PENDING" "$AI_DIR/codex" "$AI_DIR/claude" "$AI_DIR/done" "$AI_DIR/skipped"
[[ -s "$IN" ]] || exit 0

# ---------------------------------------------------------------------------
# Phase 1: generate review packets (unchanged behaviour)
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# Phase 2: Discord alerts for test_now leads
#
# Fires only when:
#   - recon_net.sh was sourced (discord_hook / discord_post available)
#   - ~/.recon_discord_fresh contains a live webhook URL
#   - recommendation == "test_now" AND ai_relevance_score >= AI_DISCORD_MIN_SCORE
#   - host not already in .ai_discord_seen (de-dup across cycles)
#
# Gated by set -e: discord_post failures don't prevent packet generation
# (Phase 1 already completed). The seen file is only updated on confirmed
# delivery so a failed POST retries next cycle.
# ---------------------------------------------------------------------------
if declare -f discord_hook >/dev/null 2>&1 && declare -f discord_post >/dev/null 2>&1; then
  _ai_wh="$(discord_hook fresh 2>/dev/null || true)"
  if [[ -n "$_ai_wh" ]]; then
    touch "$AI_DISCORD_SEEN" 2>/dev/null || true
    _alert_count=0
    while IFS= read -r lead; do
      host="$(jq -r '.host' <<< "$lead")"
      if grep -qxF "$host" "$AI_DISCORD_SEEN" 2>/dev/null; then continue; fi

      payload="$(jq -rc '{
        content: ("🤖 **AI PRIORITY** — " + (.ai.ai_relevance_score|tostring) + "/100 · " + (.ai.confidence // "?") + " confidence · test now"),
        embeds: [{
          title: ("[AI·" + (.ai.ai_relevance_score|tostring) + "·" + (.payout_tier // "none") + "] " + (.host | .[0:230])),
          url: (if (.url // "") != "" then .url else null end),
          color: 16744448,
          description: (
            "**Route: " + (.ai.route // "human") + " | Rec: test_now**\n" +
            (.ai.reason // "no reason provided")
          ),
          fields: ([
            {name:"Program",      value:((.program // "?") + " · " + (.platform // "?") + " · payout=" + (.payout_tier // "none")), inline:false},
            {name:"Triage score", value:((.score // 0)|tostring) + " (" + (.priority // "?") + ")", inline:true},
            {name:"AI score",     value:(.ai.ai_relevance_score|tostring) + " / 100", inline:true},
            (if ((.signals // []) | length) > 0 then
              {name:"Signals", value:((.signals // []) | map(select(startswith("penalty:")|not)) | join(" · ") | .[0:300]), inline:false}
            else empty end),
            (if ((.ai.safe_checks // []) | length) > 0 then
              {name:"Safe checks (passive only)",
               value:((.ai.safe_checks // []) | map("• " + .) | join("\n") | .[0:900]),
               inline:false}
            else empty end),
            (if ((.ai.risk_flags // []) | length) > 0 then
              {name:"Risk flags",
               value:((.ai.risk_flags // []) | map("⚠ " + .) | join("\n") | .[0:400]),
               inline:false}
            else empty end)
          ] | map(select(. != null))),
          footer: {text: ("ai_pack · " + (.root_domain // "?") + " · route=" + (.ai.route // "human"))}
        }]
      }' <<< "$lead" 2>/dev/null || true)"

      [[ -z "$payload" ]] && continue
      if discord_post "$_ai_wh" "$payload" 2>/dev/null; then
        echo "$host" >> "$AI_DISCORD_SEEN"
        _alert_count=$(( _alert_count + 1 ))
      fi
    done < <(jq -c --argjson min "$AI_DISCORD_MIN_SCORE" '
      select((.ai.ai_relevance_score // 0) >= $min)
      | select((.ai.recommendation // "skip") == "test_now")
    ' "$IN" 2>/dev/null)

    if [[ "$_alert_count" -gt 0 ]]; then
      printf '[%s AI_PACK] Discord: %s AI priority lead(s) alerted\n' \
        "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$_alert_count" >&2
    fi

    # Trim seen file to last 5000 entries so it never grows unbounded
    if [[ -f "$AI_DISCORD_SEEN" ]]; then
      tail -n 5000 "$AI_DISCORD_SEEN" > "$AI_DISCORD_SEEN.tmp" 2>/dev/null \
        && mv "$AI_DISCORD_SEEN.tmp" "$AI_DISCORD_SEEN" 2>/dev/null \
        || rm -f "$AI_DISCORD_SEEN.tmp" 2>/dev/null
    fi
  fi
fi

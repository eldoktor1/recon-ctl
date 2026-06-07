#!/usr/bin/env bash
# =============================================================================
# recon_briefing.sh — the 6:30pm "TONIGHT" worklist for a part-time hunter.
#
# Turns 24h of machine work into one ranked, actionable card delivered when you get home:
#   1. BAC/IDOR leads to TEST tonight (endpoint + the exact two-account test)  ← the money
#   2. Verified LIVE secrets + Claude-validated findings ready to SUBMIT
# Runs hourly; compiles + posts ONCE per day at/after BRIEFING_HOUR (local). Writes a
# durable .md too. Read-only; no target traffic.
# =============================================================================
set -uo pipefail
IFS=$'\n\t'
log() { printf '[%s BRIEFING] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/recon_net.sh" 2>/dev/null || true
BASE_DIR="${BASE_DIR:-$HOME/recon}"; STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
V3_DB="${V3_DB:-$BASE_DIR/v3/findings.db}"
WORKLIST="${IDOR_WORKLIST:-$BASE_DIR/idor_worklist.jsonl}"
BRIEF_DIR="${BRIEF_DIR:-$BASE_DIR/briefings}"
BRIEFING_HOUR="${BRIEFING_HOUR:-18}"     # local hour to deliver (default 6pm)
FORCE="${BRIEFING_FORCE:-0}"

mkdir -p "$STATE_DIR" "$BRIEF_DIR"
exec 9>"$STATE_DIR/briefing.lock"; flock -n 9 || exit 0
command -v jq >/dev/null 2>&1 || exit 0
today="$(date '+%Y-%m-%d')"; hour="$(date '+%H')"; sent="$STATE_DIR/briefing_sent_$today"
if [[ "$FORCE" != "1" ]]; then
  [[ "$((10#$hour))" -ge "$BRIEFING_HOUR" ]] || exit 0   # not yet the briefing hour
  [[ -f "$sent" ]] && exit 0                              # already delivered today
fi

# --- 1) IDOR/BAC worklist: top leads to test (rank = impact weight + confidence) ---
leads="$(grep -aE '"status":"to-test"' "$WORKLIST" 2>/dev/null \
  | jq -c '. ' 2>/dev/null \
  | jq -s 'unique_by(.host+.endpoint)
           | map(. + {rank: (({"critical":4,"high":3,"medium":2,"low":1}[.impact]) // 0) + (.confidence // 0)})
           | sort_by(-.rank) | .[0:12]' 2>/dev/null || echo '[]')"
nlead="$(printf '%s' "$leads" | jq 'length' 2>/dev/null || echo 0)"

# --- 2) findings ready to SUBMIT: Claude-real + verified-live-secrets ---
subs="[]"
if [[ -f "$V3_DB" ]]; then
  subs="$(V3_DB="$V3_DB" python3 - <<'PY' 2>/dev/null || echo '[]'
import os,sqlite3,json
try:
    c=sqlite3.connect(os.environ["V3_DB"]); c.row_factory=sqlite3.Row
    rows=[dict(r) for r in c.execute(
      "SELECT host,vuln_class,signal_class,COALESCE(ai_confidence,confidence) cf,COALESCE(ai_reason,'') reason "
      "FROM findings WHERE (ai_verdict='real' OR signal_class='verified-secret') "
      "AND state IN ('confirmed','reported') ORDER BY cf DESC LIMIT 15")]
    print(json.dumps(rows))
except Exception: print('[]')
PY
)"
fi
[[ -n "$subs" ]] || subs="[]"
nsub="$(printf '%s' "$subs" | jq 'length' 2>/dev/null || echo 0)"

if [[ "${nlead:-0}" -eq 0 && "${nsub:-0}" -eq 0 ]]; then
  log "nothing actionable to brief today"; touch "$sent"; exit 0
fi

# --- compile the card + durable .md ---
md="$BRIEF_DIR/tonight_$today.md"
{
  printf '# 🌙 TONIGHT — %s\n\n' "$today"
  printf '## 🎯 Test these (BAC/IDOR — the money class) — %s lead(s)\n' "$nlead"
  printf '%s' "$leads" | jq -r '.[] | "\n### [\(.impact|ascii_upcase) · conf \(.confidence)] \(.vuln_type) — `\(.host)\(.endpoint)`\n- **why:** \(.why)\n- **test:** \(.test)\n- program: \(.program // "?")"' 2>/dev/null
  printf '\n\n## ✅ Ready to submit (validated) — %s\n' "$nsub"
  printf '%s' "$subs" | jq -r '.[] | "- **\(.vuln_class)** on `\(.host)` (conf \(.cf)) — \(.reason[0:140])"' 2>/dev/null
  printf '\n\n_Test BAC/IDOR with your own two accounts. Submission is always your call._\n'
} > "$md" 2>/dev/null

log "🌙 briefing compiled · 🎯 $nlead IDOR lead(s) · ✅ $nsub to-submit → $md"

# --- deliver to Discord (#review) ---
rh="$(discord_hook review 2>/dev/null || true)"
if [[ -n "$rh" ]]; then
  card="$(printf '🌙 **TONIGHT — %s**\n\n🎯 **Test these (BAC/IDOR):**\n' "$today")"
  card+="$(printf '%s' "$leads" | jq -r '.[] | "• **\(.impact)** \(.vuln_type) `\(.host)\(.endpoint)` (c\(.confidence))\n   test: \(.test)"' 2>/dev/null | head -c 1300)"
  card+="$(printf '\n\n✅ **Ready to submit (%s):**\n' "$nsub")"
  card+="$(printf '%s' "$subs" | jq -r '.[] | "• \(.vuln_class) `\(.host)` (c\(.cf))"' 2>/dev/null | head -c 400)"
  discord_post "$rh" "$(jq -nc --arg c "${card:0:1950}" '{content:$c}')" >/dev/null 2>&1 \
    && log "🌙 briefing posted to #review" || log "discord post failed (card saved to $md)"
fi
touch "$sent"

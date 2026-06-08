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
ES_URL="${ES_URL:-http://127.0.0.1:9200}"; INDEX_NAME="${INDEX_NAME:-recon_alive}"
V3_DB="${V3_DB:-$BASE_DIR/v3/findings.db}"
WORKLIST="${IDOR_WORKLIST:-$BASE_DIR/idor_worklist.jsonl}"
BRIEF_FILTER="${BRIEF_FILTER:-$REPO_DIR/tools/brief_filter.py}"
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

# --- 1) IDOR/BAC worklist: rank then feed a WIDE pool to the filter. We must filter
# BEFORE capping — if 88% of the worklist is product-class/shared-tenant noise, a
# pre-filter .[0:12] would be all noise and crowd out the genuine leads ranked #13+. -->
leads="$(grep -aE '"status":"to-test"' "$WORKLIST" 2>/dev/null \
  | jq -c '. ' 2>/dev/null \
  | jq -s 'unique_by(.host+.endpoint)
           | map(. + {rank: (({"critical":4,"high":3,"medium":2,"low":1}[.impact]) // 0) + (.confidence // 0)})
           | sort_by(-.rank) | .[0:80]' 2>/dev/null || echo '[]')"
nlead="$(printf '%s' "$leads" | jq 'length' 2>/dev/null || echo 0)"

# --- 1b) dup-risk + shared-tenant SAFETY triage (promote / hold / suppress) ---
# Collapses product-class repeats (same endpoint on N hosts = standard shipped API
# = dup) and suppresses shared-tenant landmines (cross-tenant test on a per-customer
# console you don't own = third-party data). Keeps winnable, SAFE leads on top.
show="$leads"; nsupp=0; supp_reasons=""; held="[]"
if [[ -f "$BRIEF_FILTER" ]] && [[ "${nlead:-0}" -gt 0 ]]; then
  filtered="$(printf '%s' "$leads" \
    | EP_STORE="$BASE_DIR/js_recon/endpoints.jsonl" ES_URL="$ES_URL" INDEX_NAME="$INDEX_NAME" \
      python3 "$BRIEF_FILTER" 2>/dev/null || echo '')"
  if [[ -n "$filtered" ]] && printf '%s' "$filtered" | jq -e . >/dev/null 2>&1; then
    show="$(printf '%s' "$filtered" | jq -c '.promote | .[0:12]')"
    held="$(printf '%s' "$filtered" | jq -c '.hold | .[0:8]')"
    nsupp="$(printf '%s' "$filtered" | jq -r '.suppressed_count // 0')"
    supp_reasons="$(printf '%s' "$filtered" | jq -r '(.suppressed_reasons // {}) | to_entries | map("\(.value)× \(.key)") | join(", ")')"
  fi
fi
nshow="$(printf '%s' "$show" | jq 'length' 2>/dev/null || echo 0)"
nheld="$(printf '%s' "$held" | jq 'length' 2>/dev/null || echo 0)"

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

if [[ "${nshow:-0}" -eq 0 && "${nheld:-0}" -eq 0 && "${nsub:-0}" -eq 0 ]]; then
  [[ "${nsupp:-0}" -gt 0 ]] && log "all $nlead lead(s) suppressed ($supp_reasons); nothing to submit" \
                            || log "nothing actionable to brief today"
  touch "$sent"; exit 0
fi

# --- compile the card + durable .md ---
md="$BRIEF_DIR/tonight_$today.md"
{
  printf '# 🌙 TONIGHT — %s\n\n' "$today"
  printf '## 🎯 Test these (BAC/IDOR — the money class) — %s winnable lead(s)\n' "$nshow"
  printf '%s' "$show" | jq -r '.[] | "\n### [\(.impact|ascii_upcase) · conf \(.confidence)] \(.vuln_type) — `\(.host)\(.endpoint)`\n- **why:** \(.why)\n- **test:** \(.test)\n- program: \(.program // "?")"' 2>/dev/null
  if [[ "${nheld:-0}" -gt 0 ]]; then
    printf '\n\n## 🟡 If time (medium dup-risk) — %s\n' "$nheld"
    printf '%s' "$held" | jq -r '.[] | "- [\(.impact)] \(.vuln_type) `\(.host)\(.endpoint)` — \(.hold_reason // "")"' 2>/dev/null
  fi
  if [[ "${nsupp:-0}" -gt 0 ]]; then
    printf '\n\n## 🔕 Suppressed — %s lead(s): %s\n' "$nsupp" "$supp_reasons"
    printf '_(product-class duplicates and shared-tenant/third-party-data landmines — not worth your evening, kept here for audit)_\n'
  fi
  printf '\n\n## ✅ Ready to submit (validated) — %s\n' "$nsub"
  printf '%s' "$subs" | jq -r '.[] | "- **\(.vuln_class)** on `\(.host)` (conf \(.cf)) — \(.reason[0:140])"' 2>/dev/null
  printf '\n\n_Test BAC/IDOR with your own two accounts. Submission is always your call._\n'
} > "$md" 2>/dev/null

log "🌙 briefing compiled · 🎯 $nshow winnable · 🟡 $nheld hold · 🔕 $nsupp suppressed ($supp_reasons) · ✅ $nsub to-submit → $md"

# --- deliver to Discord (#review) ---
rh="$(discord_hook review 2>/dev/null || true)"
if [[ -n "$rh" ]]; then
  card="$(printf '🌙 **TONIGHT — %s**\n\n🎯 **Test these (BAC/IDOR — %s winnable):**\n' "$today" "$nshow")"
  card+="$(printf '%s' "$show" | jq -r '.[] | "• **\(.impact)** \(.vuln_type) `\(.host)\(.endpoint)` (c\(.confidence))\n   test: \(.test)"' 2>/dev/null | head -c 1200)"
  [[ "${nsupp:-0}" -gt 0 ]] && card+="$(printf '\n\n🔕 _%s suppressed: %s_' "$nsupp" "$supp_reasons")"
  card+="$(printf '\n\n✅ **Ready to submit (%s):**\n' "$nsub")"
  card+="$(printf '%s' "$subs" | jq -r '.[] | "• \(.vuln_class) `\(.host)` (c\(.cf))"' 2>/dev/null | head -c 400)"
  discord_post "$rh" "$(jq -nc --arg c "${card:0:1950}" '{content:$c}')" >/dev/null 2>&1 \
    && log "🌙 briefing posted to #review" || log "discord post failed (card saved to $md)"
fi
touch "$sent"

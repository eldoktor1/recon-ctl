#!/usr/bin/env bash
# =============================================================================
# recon_ai_idor.sh — the MONEY pillar's brain: JS-extracted endpoints -> ranked
# BAC/IDOR worklist for the human to exploit (2 accounts, in the evening).
#
# Broken access control / IDOR is ~half of all high+critical findings and the single
# most consistently rewarded class — and commodity scanners are blind to it because it
# is CONTEXTUAL. Claude reads the hidden API surface (from recon_jsintel) and reasons
# about which endpoints likely lack authorization — "good guesses at scale" — and writes
# the exact two-account test. This is the unique edge: understanding, not signatures.
#
# REASONING ONLY — issues NO target traffic. It surfaces leads; the HUMAN runs the test
# with their OWN two accounts (the hard line: IDOR/BOLA is human-in-the-loop, never
# autonomous, never third-party IDs). Output -> worklist + #review for the 6:30pm briefing.
# Runs as d0k (Claude auth). On Max, headless, no API key.
# =============================================================================
set -uo pipefail
IFS=$'\n\t'
log()  { printf '[%s AI-IDOR] %s\n'      "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s AI-IDOR WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/recon_net.sh" 2>/dev/null || true
BASE_DIR="${BASE_DIR:-$HOME/recon}"; STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"; INDEX_NAME="${INDEX_NAME:-recon_alive}"
BRIEF_FILTER="${BRIEF_FILTER:-$REPO_DIR/tools/brief_filter.py}"
EP_STORE="${JS_ENDPOINT_STORE:-$BASE_DIR/js_recon/endpoints.jsonl}"
WORKLIST="${IDOR_WORKLIST:-$BASE_DIR/idor_worklist.jsonl}"
SEEN="${IDOR_SEEN:-$STATE_DIR/idor_analyzed_hosts.txt}"
CLAUDE_BIN="${CLAUDE_BIN:-$HOME/.local/bin/claude}"; [[ -x "$CLAUDE_BIN" ]] || CLAUDE_BIN="$(command -v claude 2>/dev/null || echo '')"
CLAUDE_MODEL="${CLAUDE_IDOR_MODEL:-opus}"        # deep reasoning for the money class
CLAUDE_TIMEOUT="${CLAUDE_TIMEOUT:-180}"
IDOR_HOSTS="${IDOR_HOSTS:-8}"                     # hosts per cycle
IDOR_EP_CAP="${IDOR_EP_CAP:-120}"                # endpoints shown to Claude per host
IDOR_MIN_EP="${IDOR_MIN_EP:-4}"                  # skip hosts with too few endpoints

mkdir -p "$STATE_DIR" "$(dirname "$WORKLIST")"; touch "$SEEN"
exec 9>"$STATE_DIR/ai_idor.lock"; flock -n 9 || { warn "already running"; exit 0; }
[[ -n "$CLAUDE_BIN" && -x "$CLAUDE_BIN" ]] || { warn "claude CLI not found — skipping"; exit 0; }
command -v jq >/dev/null 2>&1 || { warn "jq missing"; exit 0; }
[[ -s "$EP_STORE" ]] || { log "no endpoint feedstock yet ($EP_STORE)"; exit 0; }

SCHEMA='{"type":"object","additionalProperties":false,"properties":{"candidates":{"type":"array","maxItems":12,"items":{"type":"object","additionalProperties":false,"properties":{"endpoint":{"type":"string"},"vuln_type":{"type":"string","enum":["broken-access-control","idor","privilege-escalation","info-disclosure","none"]},"why":{"type":"string"},"test":{"type":"string"},"impact":{"type":"string","enum":["critical","high","medium","low"]},"confidence":{"type":"number","minimum":0,"maximum":1}},"required":["endpoint","vuln_type","why","test","impact","confidence"]}}},"required":["candidates"]}'

# hosts with endpoints, freshest first, not yet analyzed
mapfile -t hosts < <(jq -r '.host // empty' "$EP_STORE" 2>/dev/null | awk 'NF && !s[$0]++' \
  | grep -vxF -f "$SEEN" 2>/dev/null | head -n "$IDOR_HOSTS")
[[ "${#hosts[@]}" -gt 0 ]] || { log "no un-analyzed hosts with endpoints"; exit 0; }
log "🧠 ─── CLAUDE IDOR ─── ${#hosts[@]} host(s) · reasoning over JS API surface → BAC/IDOR worklist ───"

# one-time headless sanity
timeout 60 "$CLAUDE_BIN" -p "Reply with exactly: OK" 2>/dev/null | grep -q "OK" \
  || { warn "claude headless not responding — skipping"; exit 0; }

total_leads=0
for host in "${hosts[@]}"; do
  # ---- SHARED-TENANT SAFETY GATE (source-level) ----
  # Skip per-customer tenant consoles (UUID label + many siblings under one wildcard,
  # e.g. <uuid>.unifi-hosting.ui.com — 4600+ of them). Each is a different owner, so any
  # BAC/IDOR test = third-party data (over the hard line). Don't spend Claude on them,
  # don't worklist them, don't post them. The operator can test consoles they own by hand.
  if [[ -f "$BRIEF_FILTER" ]]; then
    hv="$(ES_URL="$ES_URL" INDEX_NAME="$INDEX_NAME" python3 "$BRIEF_FILTER" --host "$host" 2>/dev/null)"
    if [[ -n "$hv" ]] && [[ "$(printf '%s' "$hv" | jq -r '.shared_tenant // false' 2>/dev/null)" == "true" ]]; then
      sib="$(printf '%s' "$hv" | jq -r '.siblings // 0' 2>/dev/null)"
      printf '%s\n' "$host" >> "$SEEN"
      log "   🔕 $host — shared-tenant console (1 of ~$sib under one wildcard); skipped (third-party data, not safely testable)"
      continue
    fi
  fi
  prog="$(jq -r --arg h "$host" 'select(.host==$h)|.program' "$EP_STORE" 2>/dev/null | awk 'NF{print;exit}')"
  eps="$(jq -r --arg h "$host" 'select(.host==$h)|.endpoint' "$EP_STORE" 2>/dev/null | awk 'NF && !s[$0]++' | head -n "$IDOR_EP_CAP")"
  necount="$(printf '%s' "$eps" | grep -c . 2>/dev/null)"
  printf '%s\n' "$host" >> "$SEEN"
  [[ "${necount:-0}" -lt "$IDOR_MIN_EP" ]] && { log "   · $host — only ${necount:-0} endpoints, skipped"; continue; }

  prompt="$(cat <<EOF
You are an access-control specialist. Below are API endpoints extracted from the
JavaScript of host '$host' (program: ${prog:-unknown}). They are the app's HIDDEN
surface — actions the front-end can call.

Identify the endpoints MOST likely to have BROKEN ACCESS CONTROL or IDOR — i.e. that a
low-privilege user, a different user, or an unauthenticated request could reach when they
should not. Favour: admin/privileged ACTIONS (approve, ban, bulk-update, delete, export,
impersonate, refund), object-reference fetches (by id/uuid/user/account/order), and
internal/management routes. IGNORE static pages, public marketing, and login/signup.

For each genuine candidate give: the endpoint, vuln_type, a one-line WHY it's likely
missing authz, the exact TWO-ACCOUNT TEST a human should run (what to send as a low-priv
or second user, and what response proves the bug), an impact rating, and a confidence.
Be selective — only real candidates. If none look promising, return an empty list.

ENDPOINTS:
$eps
EOF
)"
  out="$(timeout "$CLAUDE_TIMEOUT" "$CLAUDE_BIN" -p "$prompt" --model "$CLAUDE_MODEL" --tools "" \
         --no-session-persistence --json-schema "$SCHEMA" --output-format json </dev/null 2>/dev/null)"
  cands="$(printf '%s' "$out" | jq -c '.structured_output.candidates // empty' 2>/dev/null)"
  [[ -z "$cands" || "$cands" == "null" ]] && { log "   · $host — no candidates"; continue; }
  n="$(printf '%s' "$cands" | jq 'length' 2>/dev/null || echo 0)"
  [[ "${n:-0}" -gt 0 ]] || { log "   · $host — clean (no BAC/IDOR candidates)"; continue; }

  ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf '%s' "$cands" | jq -c --arg h "$host" --arg p "${prog:-}" --arg t "$ts" \
    '.[] | {host:$h,program:$p,endpoint,vuln_type,why,test,impact,confidence,at:$t,status:"to-test"}' \
    >> "$WORKLIST" 2>/dev/null
  total_leads=$((total_leads+n))
  log "   🎯 $host — $n BAC/IDOR lead(s) → worklist"
  printf '%s' "$cands" | jq -r '.[] | "        ↳ [\(.impact)|\(.confidence)] \(.vuln_type): \(.endpoint)"' 2>/dev/null \
    | while IFS= read -r l; do log "$l"; done

  # NO live ping. IDOR leads are SPECULATIVE (conf~0.6 guesses needing a 2-account
  # test) — they accumulate in the worklist and are filtered + ranked into the SINGLE
  # nightly briefing. A part-time hunter reads ONE card at 6:30pm, not a live drip of
  # maybes. Real-time #review is reserved for CONFIRMED (Claude-`real`) findings only.
done
tail -n 5000 "$SEEN" > "$SEEN.tmp" 2>/dev/null && mv "$SEEN.tmp" "$SEEN" 2>/dev/null || true
log "🧠 ai-idor done · 🎯 $total_leads BAC/IDOR lead(s) → $WORKLIST (your evening worklist)"

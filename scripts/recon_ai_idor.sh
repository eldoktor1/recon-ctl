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
source "$SCRIPT_DIR/recon_net.sh" 2>/dev/null || true
BASE_DIR="${BASE_DIR:-$HOME/recon}"; STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
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

  # high-value leads -> #review for tonight
  hot="$(printf '%s' "$cands" | jq -c '[.[]|select((.impact=="critical" or .impact=="high") and .confidence>=0.6)]' 2>/dev/null)"
  if [[ "$(printf '%s' "$hot" | jq 'length' 2>/dev/null || echo 0)" -gt 0 ]]; then
    rh="$(discord_hook review 2>/dev/null || true)"
    if [[ -n "$rh" ]]; then
      msg="$(printf '%s' "$hot" | jq -r --arg h "$host" --arg p "${prog:-?}" \
        '"🎯 **BAC/IDOR leads — \($h)** ['+'"'+'$p'+'"'+']\n" + ([.[]|"• **\(.impact)** \(.vuln_type) `\(.endpoint)` (conf \(.confidence))\n   why: \(.why)\n   test: \(.test)"]|join("\n"))' 2>/dev/null)"
      [[ -n "$msg" ]] && discord_post "$rh" "$(jq -nc --arg c "${msg:0:1900}" '{content:$c}')" >/dev/null 2>&1 || true
    fi
  fi
done
tail -n 5000 "$SEEN" > "$SEEN.tmp" 2>/dev/null && mv "$SEEN.tmp" "$SEEN" 2>/dev/null || true
log "🧠 ai-idor done · 🎯 $total_leads BAC/IDOR lead(s) → $WORKLIST (your evening worklist)"

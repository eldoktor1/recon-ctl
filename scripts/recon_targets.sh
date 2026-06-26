#!/usr/bin/env bash
# recon_targets.sh — the Under-Hunted Target Board lane.
#
# Re-aims the funnel at the RIGHT question (selection, not coverage): scores every
# bug-bounty PROGRAM by Under-Hunted EV (engine/target_board.py) and emits a ranked
# MENU of options. Auto-onboards the top N (a POOL, never just one) into the validator
# queue so enumeration starts on fresh under-hunted surface — and you can hand-pick any.
#
#   recon-targets               show the latest board (default)
#   recon-targets score         (daemon) regenerate the board + auto-onboard top N
#   recon-targets onboard <key> seed a specific program's in-scope roots into the queue
#
# Pure data (no target traffic) -> runs as d0k. Killswitch: state/kill/v2_targets.
set -uo pipefail
RECON_DIR="${RECON_DIR:-$HOME/recon}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENGINE_DIR="$(cd "$SCRIPT_DIR/../engine" && pwd)"
BRIEF="$RECON_DIR/briefings"
STATE="$RECON_DIR/state"
INBOX="$RECON_DIR/queue/inbox"
LATEST_JSON="$BRIEF/targets_latest.json"
ONBOARDED="$STATE/targets_onboarded.txt"
KILL="$STATE/kill/v2_targets"
N="${TARGETS_ONBOARD_N:-3}"               # size of the auto-onboarded pool
INBOX_CAP="${TARGETS_INBOX_CAP:-180}"     # don't pile onto an already-backed-up validator queue

log(){ printf '[targets] %s\n' "$*"; }

# emit a program's in-scope web/api root hosts (one per line) from the board JSON
_roots_for(){
  python3 - "$LATEST_JSON" "$1" <<'PY'
import json,sys
try: data=json.load(open(sys.argv[1]))
except Exception: sys.exit(2)
key=sys.argv[2]
p=next((x for x in data.get("programs",[]) if x.get("key")==key or str(x.get("rank"))==key),None)
if not p: sys.exit(3)
for h in p.get("roots",[]):
    if h: print(h)
PY
}

cmd_onboard(){
  local key="$1"
  mkdir -p "$STATE" "$INBOX"; touch "$ONBOARDED"
  grep -qxF "$key" "$ONBOARDED" 2>/dev/null && { log "already onboarded: $key"; return 0; }
  local roots; roots="$(_roots_for "$key")" || { log "no such program / no roots: $key"; return 1; }
  [ -z "${roots// /}" ] && { log "no web/api roots for: $key"; return 1; }
  local nq; nq="$(find "$INBOX" -maxdepth 1 -name '*.txt' ! -name 'restale_*' ! -name 'bulk_*' 2>/dev/null | wc -l | tr -d ' ')"
  [ "${nq:-0}" -ge "$INBOX_CAP" ] && { log "validator queue full ($nq) — defer onboard of $key"; return 0; }
  local safe; safe="$(printf '%s' "$key" | tr -c 'a-zA-Z0-9' '_' | cut -c1-40)"
  local f="$INBOX/01_$(date -u +%Y%m%dT%H%M%SZ)_targets_${safe}.txt"
  printf '%s\n' "$roots" > "$f"
  echo "$key" >> "$ONBOARDED"
  log "onboarded $key -> $(printf '%s\n' "$roots" | grep -c .) roots -> $(basename "$f")"
}

cmd_score(){
  [ -f "$KILL" ] && { log "killswitch v2_targets set; skip"; return 0; }
  RECON_DIR="$RECON_DIR" python3 "$ENGINE_DIR/target_board.py" || { log "scorer failed"; return 1; }
  mkdir -p "$STATE"; touch "$ONBOARDED"
  # auto-onboard the top N options (a rotating POOL of fresh under-hunted targets)
  local keys; keys="$(python3 - "$LATEST_JSON" "$N" <<'PY'
import json,sys
try: data=json.load(open(sys.argv[1]))
except Exception: sys.exit(0)
for p in data.get("programs",[])[:int(sys.argv[2])]: print(p["key"])
PY
)"
  while IFS= read -r k; do [ -n "$k" ] && cmd_onboard "$k"; done <<< "$keys"
}

case "${1:-show}" in
  score)     cmd_score ;;
  onboard)   shift; [ -n "${1:-}" ] || { echo "usage: recon-targets onboard <key|rank>"; exit 1; }; cmd_onboard "$1" ;;
  show|list) cat "$BRIEF/targets_latest.md" 2>/dev/null || echo "no board yet — run: recon-targets score" ;;
  *)         echo "usage: recon-targets {show|score|onboard <key>}"; exit 1 ;;
esac

#!/usr/bin/env bash
# =============================================================================
# recon_schedule.sh - Automatic mode switching based on Pacific time
#
# Weekdays (Mon-Fri):
#   05:30 PM - 11:30 PM  -> browse
#   all other hours      -> boost
#
# Weekends (Sat-Sun):
#   03:00 AM - 10:00 AM  -> boost
#   all other hours      -> preserve manual mode
#
# Called by:
#   - recon_daemon.sh supervise_loop every SCHEDULE_SLEEP seconds
#   - recon_ctl schedule-check
# =============================================================================

set -uo pipefail

MODE_FILE="${MODE_FILE:-$HOME/.recon_mode}"
SCHEDULE_LOG="${SCHEDULE_LOG:-$HOME/recon/logs/recon_daemon.log}"
TZ="America/Los_Angeles"
export TZ

mkdir -p "$(dirname "$MODE_FILE")" "$(dirname "$SCHEDULE_LOG")" 2>/dev/null || true

log() { printf '[%s SCHED] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >> "$SCHEDULE_LOG" 2>/dev/null || true; }

DOW="$(date +%u)"   # 1=Mon ... 7=Sun
HOUR="$(date +%H)"  # 00-23
MIN="$(date +%M)"   # 00-59
TIME_MINS=$(( 10#$HOUR * 60 + 10#$MIN ))

BROWSE_START=1050        # 5:30 PM
BROWSE_END=1410          # 11:30 PM
WEEKEND_BOOST_START=180  # 3:00 AM
WEEKEND_BOOST_END=600    # 10:00 AM

read_mode() {
  tr -d '[:space:]' < "$MODE_FILE" 2>/dev/null || echo browse
}

write_if_changed() {
  local target="$1" reason="$2"
  local current
  current="$(read_mode)"
  if [[ "$current" != "$target" ]]; then
    if echo "$target" > "$MODE_FILE"; then
      log "$reason: $current -> $target (DOW=$DOW TIME=$(date +%H:%M)PT)"
    else
      log "$reason: could not write mode file $MODE_FILE"
    fi
  fi
}

if [[ "$DOW" -ge 6 ]]; then
  if [[ "$TIME_MINS" -ge "$WEEKEND_BOOST_START" && "$TIME_MINS" -lt "$WEEKEND_BOOST_END" ]]; then
    write_if_changed "boost" "Weekend boost"
  else
    log "Weekend outside boost window - preserving manual mode: $(read_mode)"
  fi
  exit 0
fi

if [[ "$TIME_MINS" -ge "$BROWSE_START" && "$TIME_MINS" -lt "$BROWSE_END" ]]; then
  write_if_changed "browse" "Weekday browse window"
else
  write_if_changed "boost" "Weekday boost window"
fi

exit 0

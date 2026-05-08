#!/usr/bin/env bash
# =============================================================================
# recon_schedule.sh — Automatic mode switching based on time of day
#
# Schedule (Pacific Time):
#   Weekdays (Mon-Fri):
#     05:30 PM - 11:30 PM  → browse   (you're home, using the computer)
#     all other hours      → night    (you're at work or asleep)
#   Weekends (Sat-Sun):
#     Controlled separately by recon_ctl mode browse|night
#     This script does NOT override on weekends.
#
# Mechanism:
#   - Runs as a sub-loop inside recon_daemon.sh (checked every 5 minutes)
#   - Writes to ~/.recon_mode
#   - Battery check still applies on top of this (daemon does it in load_profile)
#   - Weekend mode is preserved (whatever you last set manually)
#
# Called by:
#   - recon_daemon.sh supervise_loop every SCHEDULE_SLEEP seconds
#   - recon_ctl schedule-check (manual trigger)
# =============================================================================

set -uo pipefail

MODE_FILE="${MODE_FILE:-$HOME/.recon_mode}"
SCHEDULE_LOG="${SCHEDULE_LOG:-$HOME/recon/logs/recon_daemon.log}"
TZ="America/Los_Angeles"
export TZ

log() { printf '[%s SCHED] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >> "$SCHEDULE_LOG" 2>/dev/null || true; }

# Current local time components
DOW="$(date +%u)"   # 1=Mon ... 7=Sun
HOUR="$(date +%H)"  # 00-23
MIN="$(date +%M)"   # 00-59
TIME_MINS=$(( 10#$HOUR * 60 + 10#$MIN ))

# Window: 17:30 = 1050 mins, 23:30 = 1410 mins
BROWSE_START=1050   # 5:30 PM
BROWSE_END=1410     # 11:30 PM

# Determine target mode
TARGET_MODE=""
if [[ "$DOW" -ge 6 ]]; then
  # Weekend — preserve whatever was manually set, don't touch
  CURRENT="$(cat "$MODE_FILE" 2>/dev/null | tr -d '[:space:]' || echo browse)"
  log "Weekend — preserving manual mode: $CURRENT"
  exit 0
fi

# Weekday logic
if [[ "$TIME_MINS" -ge "$BROWSE_START" && "$TIME_MINS" -lt "$BROWSE_END" ]]; then
  TARGET_MODE="browse"
else
  TARGET_MODE="night"
fi

# Only write if changed (avoids unnecessary disk writes + daemon log spam)
CURRENT="$(cat "$MODE_FILE" 2>/dev/null | tr -d '[:space:]' || echo "")"
if [[ "$CURRENT" != "$TARGET_MODE" ]]; then
  echo "$TARGET_MODE" > "$MODE_FILE"
  log "Mode switched: $CURRENT → $TARGET_MODE (DOW=$DOW TIME=$(date +%H:%M)PT)"
fi

exit 0

#!/usr/bin/env bash
# One-shot: wait for any in-progress triage to finish, then run a forced
# full retriage so every ES doc gets rescored with the current scoring logic.
# Safe to run while the daemon is active — the triage lock prevents collision.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="${STATE_DIR:-$HOME/recon/state}"
TRIAGE_SCRIPT="$SCRIPT_DIR/../scripts/triage.sh"
LOCK_FILE="$STATE_DIR/triage.lock"
LAST_FULL_FILE="${LAST_FULL_FILE:-$STATE_DIR/.triage_last_full}"
LOG="$HOME/recon/logs/retriage_full.log"

log() { printf '[%s RETRIAGE] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" | tee -a "$LOG" >&2; }

log "Waiting for triage lock to be free (max 60 min)..."
timeout 3600 flock "$LOCK_FILE" true 2>/dev/null || true

log "Lock free — resetting LAST_FULL_FILE to force full mode"
echo 0 > "$LAST_FULL_FILE"

log "Starting full retriage of all ES data..."
TRIAGE_MODE=full LOOKBACK_DAYS=365 bash "$TRIAGE_SCRIPT"
log "Full retriage complete."

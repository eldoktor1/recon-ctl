#!/usr/bin/env bash
# Continuous overnight driver: runs recon_cognito_nighthunt cycles back-to-back
# until a STOP file appears. Sends a startup ping to #ops and relies on the cycle
# script to ping #review on any REAL finding. Idempotent/resumable via the cursor.
set -uo pipefail
SD="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SD/recon_net.sh" 2>/dev/null || true
DIR="$HOME/recon/cognito"; mkdir -p "$DIR"
STOP="$DIR/STOP"; LOG="$DIR/nighthunt.log"
export BATCH="${BATCH:-1500}" PAR="${PAR:-14}"

startup_ping(){
  local hook; hook="$(discord_hook ops 2>/dev/null || true)"
  [ -z "$hook" ] && { echo "no ops webhook" >&2; return; }
  discord_post "$hook" "$(jq -nc '{content:"🌙 Cognito night-hunt STARTED — walking in-scope+paying Amplify SPAs. Will ping #review ONLY on a REAL unauth-Cognito finding (issued creds + role with real permissions). RUM/zero-perm/denied pools are auto-suppressed as FP."}')" >/dev/null 2>&1 && echo "startup ping sent" >&2
}

startup_ping
cyc=0
while [ ! -f "$STOP" ]; do
  cyc=$((cyc+1))
  printf '[%s NIGHTLOOP] cycle %d\n' "$(date -u +%FT%TZ)" "$cyc" | tee -a "$LOG" >&2
  bash "$SD/recon_cognito_nighthunt.sh" || true
  [ -f "$STOP" ] && break
  sleep 15
done
printf '[%s NIGHTLOOP] STOP file seen — halted after %d cycles\n' "$(date -u +%FT%TZ)" "$cyc" | tee -a "$LOG" >&2

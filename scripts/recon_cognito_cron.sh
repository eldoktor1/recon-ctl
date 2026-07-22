#!/usr/bin/env bash
# Durable watchdog for the cognito hunt — run by WSL cron every 10 min, INDEPENDENT
# of any Claude session. Relaunches either prong if it died (unless STOPped/finished).
# Fully reversible: `crontab -e` remove the line, or `touch ~/recon/cognito/STOP*`.
export HOME=/home/d0k
export PATH="/home/d0k/.cargo/bin:/home/d0k/go/bin:/usr/local/bin:/usr/bin:/bin:$PATH"
DIR="$HOME/recon/cognito"; S="$HOME/recon-pipeline/scripts"
mkdir -p "$DIR"
exec 9>"$DIR/cron.lock"; flock -n 9 || exit 0     # no overlapping runs

# fail-closed: never launch target-facing work while VPN is down
[ -f "$HOME/recon/state/vpn_down" ] && exit 0

# --- web loop ---
if ! pgrep -f 'recon_cognito_nightloop.sh' >/dev/null 2>&1 && [ ! -f "$DIR/STOP" ]; then
  BATCH=1200 PAR=16 setsid bash "$S/recon_cognito_nightloop.sh" >>"$DIR/nightloop.out" 2>&1 </dev/null &
  echo "[$(date -u +%FT%TZ)] cron relaunched web loop" >> "$DIR/cron.log"
fi

# --- mobile prong (relaunch only if not running, not stopped, not finished) ---
scanned=$(cut -f1 "$DIR/apk_scanned.txt" 2>/dev/null | sort -u | grep -c . || echo 0)
if ! pgrep -f 'recon_cognito_mobile.sh' >/dev/null 2>&1 && [ ! -f "$DIR/STOP_MOBILE" ] && [ "${scanned:-0}" -lt 640 ]; then
  setsid bash "$S/recon_cognito_mobile.sh" 650 >>"$DIR/mobile.out" 2>&1 </dev/null &
  echo "[$(date -u +%FT%TZ)] cron relaunched mobile ($scanned/647 done)" >> "$DIR/cron.log"
fi

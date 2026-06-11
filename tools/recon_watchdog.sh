#!/usr/bin/env bash
# =============================================================================
# recon_watchdog.sh — called hourly + on logon from Windows Task Scheduler
# Checks daemon health, VPN, ES; restarts daemon if conditions are met.
# Logs to ~/recon/logs/watchdog.log (auto-rotated at 5 MB).
# =============================================================================
set -uo pipefail

BASE_DIR="${BASE_DIR:-$HOME/recon}"
LOG_DIR="$BASE_DIR/logs"
STATE_DIR="$BASE_DIR/state"
CTL="/home/d0k/recon-pipeline/scripts/recon_ctl.sh"
SAFE_START="/home/d0k/recon-pipeline/tools/start_recon_safe.sh"
WDOG_LOG="$LOG_DIR/watchdog.log"

mkdir -p "$LOG_DIR"
ts()  { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
log() { printf '[%s WDOG] %s\n' "$(ts)" "$*" | tee -a "$WDOG_LOG"; }

# Auto-rotate log at 5 MB
if [[ -f "$WDOG_LOG" ]]; then
  sz="$(du -sm "$WDOG_LOG" 2>/dev/null | awk '{print $1}')"
  [[ "${sz:-0}" -gt 5 ]] && tail -n 1000 "$WDOG_LOG" > "$WDOG_LOG.tmp" && mv "$WDOG_LOG.tmp" "$WDOG_LOG"
fi

log "=== watchdog start ==="

# ── 1. Daemon check ────────────────────────────────────────────────────────
PID_FILE="$STATE_DIR/recon_daemon.pid"
daemon_running=0
if [[ -s "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE" 2>/dev/null)" 2>/dev/null; then
  pid="$(cat "$PID_FILE")"
  uptime="$(ps -o etime= -p "$pid" 2>/dev/null | tr -d ' ')"
  log "daemon OK (pid=$pid uptime=$uptime)"
  daemon_running=1
else
  log "daemon DOWN — pid missing or stale"
fi

# ── 2. VPN check (cached multi-method egress check — does NOT hammer am.i.mullvad) ──
# Routes through the ONE cached checker (recon_vpn_check.sh): a known exit IP confirms from
# the local cache with zero external Mullvad calls (vpnguard refreshes vpn_status.json ~20s).
vpn_ok=0
_wdog_vpn="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../scripts/recon_vpn_check.sh"
if [[ -f "$_wdog_vpn" ]]; then
  vpn_word="$(STATE_DIR="$STATE_DIR" bash "$_wdog_vpn" --cached 2>/dev/null)"; vpn_rc=$?
else
  vpn_word="no-checker"; vpn_rc=2
fi
if [[ "$vpn_rc" -eq 0 ]]; then
  log "VPN OK ($vpn_word)"
  vpn_ok=1
else
  log "VPN DOWN/UNCONFIRMED — egress not confirmed on Mullvad ($vpn_word)"
fi

# ── 3. ES check (ES lives in Windows Docker Desktop — read-only check) ────
es_ok=0
_wdog_net="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../scripts/recon_net.sh"
# shellcheck source=../scripts/recon_net.sh
[[ -f "$_wdog_net" ]] && source "$_wdog_net" && setup_es_netrc 2>/dev/null || true
es_status="$(curl -fsS -m5 --netrc-file "$HOME/.recon_es_netrc" http://127.0.0.1:9200/_cluster/health 2>/dev/null \
  | jq -r '.status // "unreachable"' 2>/dev/null || echo "unreachable")"
if [[ "$es_status" == "green" || "$es_status" == "yellow" ]]; then
  log "ES OK (status=$es_status)"
  es_ok=1
else
  log "ES unreachable — start from Windows Docker Desktop"
fi

# ── 4. Restart daemon if all conditions met ────────────────────────────────
if [[ "$daemon_running" -eq 0 ]]; then
  if [[ "$vpn_ok" -eq 0 ]]; then
    log "NOT restarting — connect Mullvad first"
  elif [[ "$es_ok" -eq 0 ]]; then
    log "NOT restarting — start ES from Docker Desktop first"
  else
    log "Restarting daemon..."
    bash "$SAFE_START" >> "$WDOG_LOG" 2>&1 \
      && log "daemon restarted OK" \
      || log "daemon restart FAILED — check $LOG_DIR/recon_daemon.log"
  fi
fi

# ── 5. Queue sanity check ─────────────────────────────────────────────────
inbox="$(find "$BASE_DIR/queue/inbox"      -maxdepth 1 -name '*.txt' 2>/dev/null | wc -l | tr -d ' ')"
proc="$(find  "$BASE_DIR/queue/processing" -maxdepth 1 -name '*.txt' 2>/dev/null | wc -l | tr -d ' ')"
log "queue inbox=$inbox processing=$proc"
if [[ "${inbox:-0}" -gt 150 ]]; then
  log "WARN: inbox backlog high ($inbox files ≥150) — validate may be stuck"
fi

# ── 6. Disk check ─────────────────────────────────────────────────────────
avail_gb="$(df -BG "$BASE_DIR" 2>/dev/null | awk 'NR==2 {gsub("G",""); print $4}')"
if [[ "${avail_gb:-999}" -lt 20 ]]; then
  log "WARN: disk low (${avail_gb}GB free) — run recon-clean"
else
  log "disk OK (${avail_gb}GB free)"
fi

# ── 7. Discord bot check ──────────────────────────────────────────────────
bot_pid_file="$STATE_DIR/discord_bot.pid"
if [[ -s "$bot_pid_file" ]] && kill -0 "$(cat "$bot_pid_file" 2>/dev/null)" 2>/dev/null; then
  log "discord-bot OK (pid=$(cat "$bot_pid_file"))"
else
  # Bot is supervised by the daemon — if daemon is up it will restart it.
  [[ "$daemon_running" -eq 1 ]] && log "discord-bot not running (daemon will restart it)" \
                                || log "discord-bot down (daemon is also down)"
fi

log "=== watchdog done ==="

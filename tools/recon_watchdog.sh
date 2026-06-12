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

# ── 8. 2IC routine liveness — the EXTERNAL watchdog the routine can't be ──────
# The 2IC scheduled agent (cron 0 0-18 * * *) is the ONLY producer of reporter-gated
# `real` rows (reporter.py gates state='confirmed' AND ai_verdict='real'). Its own
# self-MONITOR runs INSIDE the routine, so it cannot detect its own host dying or being
# unscheduled — then the reporter silently starves. This daemon-side check is that
# independent watchdog: if the routine has gone SILENT (no run-marker) OR the
# confirmed-pending backlog has built up, fire #ops ONCE (action-only, cooled down —
# no health spam, per the CLAUDE.md notification policy).
TWOIC_HUNT_LOG="$STATE_DIR/2ic_hunt_log.jsonl"
TWOIC_BRIEF_DIR="$BASE_DIR/briefings"
TWOIC_MAX_AGE_H="${WATCHDOG_2IC_MAX_AGE_H:-24}"      # silent this long => routine likely dead/unscheduled
TWOIC_PENDING_MAX="${WATCHDOG_PENDING_MAX:-25}"      # confirmed-but-unjudged backlog ceiling
TWOIC_REALERT_H="${WATCHDOG_2IC_REALERT_H:-6}"       # min hours between repeat #ops alerts (anti-spam)
TWOIC_ALERT_MARK="$STATE_DIR/.watchdog_2ic_alerted"
TWOIC_DB="${V3_DB:-$BASE_DIR/v3/findings.db}"
now_s="$(date +%s)"

# last 2IC activity = newest of the hunt log or any tonight-card (each run writes both)
last_2ic=0
for _f in "$TWOIC_HUNT_LOG" "$TWOIC_BRIEF_DIR"/2IC_tonight_*.md; do
  [[ -f "$_f" ]] || continue
  _m="$(stat -c %Y "$_f" 2>/dev/null || echo 0)"
  [[ "$_m" -gt "$last_2ic" ]] && last_2ic="$_m"
done
age_h=$(( last_2ic > 0 ? (now_s - last_2ic) / 3600 : 9999 ))

# confirmed-pending backlog: findings confirmed by the daemon but never AI-judged
# (the 2IC verify drains these → 'real'/'fp'/'needs-human'); growth = verify not running.
pending=0
if [[ -f "$TWOIC_DB" ]] && command -v sqlite3 >/dev/null 2>&1; then
  pending="$(sqlite3 "$TWOIC_DB" "SELECT COUNT(*) FROM findings WHERE state='confirmed' AND ai_verdict IS NULL;" 2>/dev/null || echo 0)"
fi
[[ "$pending" =~ ^[0-9]+$ ]] || pending=0

twoic_reason=""
[[ "$age_h" -ge "$TWOIC_MAX_AGE_H" ]] && twoic_reason="2IC routine SILENT ${age_h}h (no run-marker; reporter starves — check the scheduled agent host + cron 0 0-18 * * *)"
if [[ "$pending" -ge "$TWOIC_PENDING_MAX" ]]; then
  [[ -n "$twoic_reason" ]] && twoic_reason="$twoic_reason; "
  twoic_reason="${twoic_reason}confirmed-pending backlog=${pending} (>=${TWOIC_PENDING_MAX} awaiting AI verdict — 2IC verify not draining the ai-pending queue)"
fi

if [[ -n "$twoic_reason" ]]; then
  log "2IC-LIVENESS ALERT: $twoic_reason"
  last_alert="$(cat "$TWOIC_ALERT_MARK" 2>/dev/null || echo 0)"; [[ "$last_alert" =~ ^[0-9]+$ ]] || last_alert=0
  if (( now_s - last_alert >= TWOIC_REALERT_H * 3600 )); then
    ops_hook=""
    command -v discord_hook >/dev/null 2>&1 && ops_hook="$(discord_hook ops 2>/dev/null || true)"
    if [[ -n "$ops_hook" ]] && command -v discord_post >/dev/null 2>&1; then
      twoic_msg="🚨 **2IC / REPORTER WATCHDOG** — $twoic_reason"
      if discord_post "$ops_hook" "$(jq -nc --arg c "${twoic_msg:0:1900}" '{content:$c}')" >/dev/null 2>&1; then
        echo "$now_s" > "$TWOIC_ALERT_MARK"; log "2IC-liveness alert posted to #ops"
      else
        log "2IC-liveness #ops post FAILED (will retry next cycle)"
      fi
    else
      log "2IC-liveness: #ops webhook unset — alert not delivered (set ~/recon/state/discord/ops)"
    fi
  else
    log "2IC-liveness alert suppressed (cooldown — last alert $(( (now_s - last_alert) / 3600 ))h ago, re-alert every ${TWOIC_REALERT_H}h)"
  fi
else
  # healthy → clear the cooldown so the NEXT real outage alerts immediately
  rm -f "$TWOIC_ALERT_MARK" 2>/dev/null || true
  log "2IC-liveness OK (last run ${age_h}h ago, pending=$pending)"
fi

log "=== watchdog done ==="

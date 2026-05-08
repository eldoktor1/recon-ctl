#!/usr/bin/env bash
# =============================================================================
# recon_ctl.sh — Control interface for the recon daemon
#
# You normally don't need this. The daemon runs automatically.
# Use this only when you want to:
#   - Check status
#   - Switch between browse/night mode
#   - Tail the logs
#   - Stop the daemon (it will auto-restart on next WSL session)
# =============================================================================

set -u

BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="$BASE_DIR/state"
LOG_DIR="$BASE_DIR/logs"
PID_FILE="$STATE_DIR/recon_daemon.pid"
MODE_FILE="$HOME/.recon_mode"

DAEMON="${DAEMON:-$HOME/recon_daemon.sh}"
DAEMON_LOG="$LOG_DIR/recon_daemon.log"
RECON_LOG="$LOG_DIR/auto_recon.log"

usage() {
  cat <<EOF
Usage: $(basename "$0") <command>

Commands:
  status        Show daemon + ES + last cycle info
  mode browse   Polite mode — low rate, won't impact browsing (default)
  mode night    Aggressive mode — high rate, for when AFK
  mode show     Show current mode
  logs          Tail daemon log (Ctrl+C to exit)
  logs recon    Tail auto_recon log
  logs triage   Tail triage log
  start         Start daemon (normally auto-started; use after manual stop)
  stop          Stop daemon (will auto-restart next WSL session)
  restart       Soft restart — finishes current cycle, exits, you start again
  top           Show top 10 P0/P1 from latest triage
  health        Full self-check
  clean         Free disk space (logs, archives, spool) — safe during active run
  space         Show disk usage breakdown
EOF
  exit 2
}

is_running() {
  [[ -s "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null
}

cmd_status() {
  if is_running; then
    local pid; pid="$(cat "$PID_FILE")"
    echo "Daemon: running (pid $pid)"
    local started
    started="$(ps -o lstart= -p "$pid" 2>/dev/null | xargs)"
    [[ -n "$started" ]] && echo "Started: $started"
  else
    echo "Daemon: NOT running"
  fi

  local mode; mode="$(cat "$MODE_FILE" 2>/dev/null | tr -d '[:space:]')"
  echo "Mode: ${mode:-browse (default)}"

  if curl -fsS -m 3 -u "elastic:$(cat "$HOME/.recon_es_pass" 2>/dev/null)" \
       "http://127.0.0.1:9200" >/dev/null 2>&1; then
    local count
    count="$(curl -fsS -m 3 -u "elastic:$(cat "$HOME/.recon_es_pass" 2>/dev/null)" \
            "http://127.0.0.1:9200/recon_alive/_count" 2>/dev/null \
            | jq -r '.count // 0' 2>/dev/null || echo "?")"
    echo "ES: reachable, $count docs in recon_alive"
  else
    echo "ES: UNREACHABLE (is the Docker stack up on Windows?)"
  fi

  if [[ -f "$DAEMON_LOG" ]]; then
    echo ""
    echo "Recent daemon activity (last 5 lines):"
    tail -n 5 "$DAEMON_LOG"
  fi
}

cmd_mode() {
  local m="${1:-show}"
  case "$m" in
    browse|night)
      echo "$m" > "$MODE_FILE"
      chmod 600 "$MODE_FILE"
      echo "Mode set: $m (takes effect on next cycle)"
      ;;
    show)
      local cur; cur="$(cat "$MODE_FILE" 2>/dev/null | tr -d '[:space:]')"
      echo "${cur:-browse (default)}"
      ;;
    *) echo "mode: browse|night|show"; exit 2 ;;
  esac
}

cmd_logs() {
  local what="${1:-daemon}"
  case "$what" in
    daemon|"") tail -F "$DAEMON_LOG" ;;
    recon)     tail -F "$RECON_LOG" ;;
    triage)
      local latest
      latest="$(ls -t "$BASE_DIR/triage/report_"*.md 2>/dev/null | head -1)"
      [[ -z "$latest" ]] && { echo "No triage reports yet"; exit 0; }
      cat "$latest"
      ;;
    *) echo "Unknown log type: $what. Use: daemon|recon|triage"; exit 2 ;;
  esac
}

cmd_start() {
  if is_running; then
    echo "Already running (pid $(cat "$PID_FILE"))"
    exit 0
  fi
  rm -f "$PID_FILE"
  nohup bash "$DAEMON" >/dev/null 2>&1 &
  sleep 1
  if is_running; then
    echo "Started (pid $(cat "$PID_FILE"))"
  else
    echo "Failed to start. Check $DAEMON_LOG"
    exit 1
  fi
}

cmd_stop() {
  if ! is_running; then
    echo "Not running"
    rm -f "$PID_FILE"
    exit 0
  fi
  local pid; pid="$(cat "$PID_FILE")"
  echo "Sending SIGTERM to pid $pid (will exit after current cycle finishes)"
  kill -TERM "$pid" 2>/dev/null || true

  # Wait up to 60s for clean exit
  local i=0
  while is_running && [[ $i -lt 60 ]]; do
    sleep 1; i=$((i+1))
  done

  if is_running; then
    echo "Daemon still running after 60s — current cycle still in progress"
    echo "It will exit cleanly when the cycle completes"
  else
    echo "Stopped"
    rm -f "$PID_FILE"
  fi
}

cmd_restart() {
  cmd_stop
  sleep 2
  cmd_start
}

cmd_top() {
  local f="$BASE_DIR/triage/agent_targets.jsonl"
  [[ ! -s "$f" ]] && { echo "No triage output yet"; exit 0; }
  echo "Top 10 by score (latest triage):"
  echo ""
  head -10 "$f" | jq -r '
    [.priority, .score, .host, (.tech|join(",")|.[0:40]), (.vuln_classes|join(","))]
    | @tsv'
}

cmd_health() {
  echo "==== Health check ===="
  echo ""
  echo "[Scripts]"
  for f in auto_recon.sh triage.sh recon_daemon.sh recon_ctl.sh; do
    if [[ -x "$HOME/$f" ]]; then
      echo "  ✓ ~/$f"
    else
      echo "  ✗ ~/$f (missing or not executable)"
    fi
  done

  echo ""
  echo "[Credentials]"
  if [[ -f "$HOME/.recon_es_pass" ]]; then
    local perms
    perms="$(stat -c '%a' "$HOME/.recon_es_pass")"
    if [[ "$perms" == "600" ]]; then
      echo "  ✓ ~/.recon_es_pass (chmod 600)"
    else
      echo "  ⚠ ~/.recon_es_pass (chmod $perms — should be 600)"
    fi
  else
    echo "  ✗ ~/.recon_es_pass missing"
  fi
  if [[ -f "$HOME/.recon_discord" ]]; then
    echo "  ✓ ~/.recon_discord configured"
  else
    echo "  ⚠ ~/.recon_discord missing (Discord notifications disabled)"
  fi

  echo ""
  echo "[Dependencies]"
  for c in curl jq httpx wget unzip flock; do
    command -v "$c" >/dev/null 2>&1 \
      && echo "  ✓ $c" \
      || echo "  ✗ $c (REQUIRED, missing)"
  done
  for c in subfinder assetfinder acpi; do
    command -v "$c" >/dev/null 2>&1 \
      && echo "  ✓ $c (optional)" \
      || echo "  ⚠ $c (optional, missing)"
  done

  echo ""
  echo "[ES connectivity]"
  if curl -fsS -m 3 -u "elastic:$(cat "$HOME/.recon_es_pass" 2>/dev/null)" \
       "http://127.0.0.1:9200/_cluster/health" 2>/dev/null \
       | jq -r '"  ✓ ES reachable, status: \(.status), nodes: \(.number_of_nodes)"' 2>/dev/null; then
    :
  else
    echo "  ✗ ES not reachable. Start Docker on Windows: docker compose up -d"
  fi

  echo ""
  cmd_status
}


cmd_space() {
  echo "==== Disk usage ===="
  echo ""
  echo "[Recon directories]"
  du -sh "$BASE_DIR/archive"  2>/dev/null | awk '{printf "  archive:   %s\n", $1}'
  du -sh "$BASE_DIR/runs"     2>/dev/null | awk '{printf "  runs:      %s\n", $1}'
  du -sh "$BASE_DIR/logs"     2>/dev/null | awk '{printf "  logs:      %s\n", $1}'
  du -sh "$BASE_DIR/cache"    2>/dev/null | awk '{printf "  cache:     %s\n", $1}'
  du -sh "$BASE_DIR/spool"    2>/dev/null | awk '{printf "  spool:     %s\n", $1}'
  du -sh "$BASE_DIR/triage"   2>/dev/null | awk '{printf "  triage:    %s\n", $1}'
  echo ""
  du -sh "$BASE_DIR" 2>/dev/null | awk '{printf "  TOTAL:     %s\n", $1}'
  echo ""
  echo "[Available disk space]"
  df -h "$HOME" | awk 'NR==2 {printf "  Used: %s / %s (%s full)\n", $3, $2, $5}'
}

cmd_clean() {
  echo "==== Cleaning disk space ===="
  echo "(Safe to run during active scans — never touches live run data)"
  echo ""

  local freed=0

  # 1. Archive runs older than 3 days
  local old_runs
  old_runs="$(find "$BASE_DIR/archive" -maxdepth 1 -type d -name 'run_*' -mtime +3 2>/dev/null | wc -l | tr -d ' ')"
  if [[ "$old_runs" -gt 0 ]]; then
    local before; before="$(du -sb "$BASE_DIR/archive" 2>/dev/null | awk '{print $1}')"
    find "$BASE_DIR/archive" -maxdepth 1 -type d -name 'run_*' -mtime +3 -exec rm -rf {} + 2>/dev/null || true
    local after; after="$(du -sb "$BASE_DIR/archive" 2>/dev/null | awk '{print $1}')"
    local diff=$(( (before - after) / 1024 / 1024 ))
    echo "  ✓ Pruned $old_runs old archive runs (freed ~${diff}MB)"
    freed=$((freed + diff))
  else
    echo "  ✓ Archive: nothing to prune (all runs < 3 days old)"
  fi

  # 2. Rotate daemon log if > 50MB
  if [[ -f "$DAEMON_LOG" ]]; then
    local logsize; logsize="$(du -sm "$DAEMON_LOG" 2>/dev/null | awk '{print $1}')"
    if [[ "$logsize" -gt 50 ]]; then
      tail -n 10000 "$DAEMON_LOG" > "$DAEMON_LOG.tmp" && mv "$DAEMON_LOG.tmp" "$DAEMON_LOG"
      echo "  ✓ Rotated daemon log (was ${logsize}MB, kept last 10k lines)"
      freed=$((freed + logsize - 1))
    else
      echo "  ✓ Daemon log: ${logsize}MB (no rotation needed)"
    fi
  fi

  # 3. Clean sent spool older than 7 days
  local old_spool
  old_spool="$(find "$BASE_DIR/spool/sent" -type f -mtime +7 2>/dev/null | wc -l | tr -d ' ')"
  if [[ "$old_spool" -gt 0 ]]; then
    find "$BASE_DIR/spool/sent" -type f -mtime +7 -delete 2>/dev/null || true
    echo "  ✓ Cleaned $old_spool old spool files"
  else
    echo "  ✓ Spool: nothing to clean"
  fi

  # 4. Clean old triage reports (keep last 10)
  local triage_count
  triage_count="$(ls -t "$BASE_DIR/triage/report_"*.md 2>/dev/null | wc -l | tr -d ' ')"
  if [[ "$triage_count" -gt 10 ]]; then
    local to_delete=$(( triage_count - 10 ))
    ls -t "$BASE_DIR/triage/report_"*.md 2>/dev/null | tail -n "$to_delete" | xargs rm -f 2>/dev/null || true
    echo "  ✓ Pruned $to_delete old triage reports (kept 10 most recent)"
  else
    echo "  ✓ Triage reports: $triage_count (no pruning needed)"
  fi

  # 5. Clean httpx part files from any interrupted runs in archive
  local stale_parts
  stale_parts="$(find "$BASE_DIR/archive" -name "*.jsonl" -mtime +1 2>/dev/null | wc -l | tr -d ' ')"
  if [[ "$stale_parts" -gt 0 ]]; then
    find "$BASE_DIR/archive" -name "*.jsonl" -mtime +1 -delete 2>/dev/null || true
    echo "  ✓ Cleaned $stale_parts stale httpx part files from archive"
  fi

  echo ""
  echo "Space after clean:"
  cmd_space
}

# ---- Dispatch -------------------------------------------------------------
case "${1:-}" in
  status)   cmd_status ;;
  mode)     shift; cmd_mode "${1:-show}" ;;
  logs)     shift; cmd_logs "${1:-daemon}" ;;
  start)    cmd_start ;;
  stop)     cmd_stop ;;
  restart)  cmd_restart ;;
  top)      cmd_top ;;
  health)   cmd_health ;;
  clean)    cmd_clean ;;
  space)    cmd_space ;;
  *)        usage ;;
esac

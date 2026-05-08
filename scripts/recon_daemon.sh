#!/usr/bin/env bash
# =============================================================================
# recon_daemon.sh — Persistent loop that runs auto_recon.sh forever
#
# - Reads ~/.recon_mode each cycle (browse|night) — adjusts rate/threads/cap
# - Calls auto_recon.sh, which auto-chains to triage.sh
# - Sleeps based on mode (browse=longer pause, night=shorter)
# - One PID, one log, graceful shutdown via SIGTERM
# - Auto-detects laptop battery → forces browse mode if unplugged
# - Proxy: set USE_PROXYCHAINS=1 to route external traffic via proxychains4
#
# Started by Windows Task Scheduler on user logon. Never run manually.
# =============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

# ---- Repo-relative paths --------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="$BASE_DIR/state"
LOG_DIR="$BASE_DIR/logs"
PID_FILE="$STATE_DIR/recon_daemon.pid"
LOG_FILE="$LOG_DIR/recon_daemon.log"
MODE_FILE="$HOME/.recon_mode"

AUTO_RECON="${AUTO_RECON:-$REPO_ROOT/scripts/auto_recon.sh}"

# Proxychains — set USE_PROXYCHAINS=1 to route scan traffic via proxy
# Requires: localnet 127.0.0.0/255.0.0.0 in /etc/proxychains4.conf
USE_PROXYCHAINS="${USE_PROXYCHAINS:-0}"
if [[ "$USE_PROXYCHAINS" == "1" ]] && ! command -v proxychains4 >/dev/null 2>&1; then
  echo "WARNING: proxychains4 not found — running unproxied" >&2
  USE_PROXYCHAINS=0
fi

# ---- Proxychains ----------------------------------------------------------
# Wraps all external traffic (httpx, subfinder, curl to targets) through proxy.
# ES/localhost traffic bypassed automatically via proxychains4.conf localnet rule.
#
# Setup:
#   1. Add to /etc/proxychains4.conf:  localnet 127.0.0.0/255.0.0.0
#   2. Configure your proxy list in /etc/proxychains4.conf
#   3. Enable: export USE_PROXYCHAINS=1  (or set in Task Scheduler env)
USE_PROXYCHAINS="${USE_PROXYCHAINS:-0}"
if [[ "$USE_PROXYCHAINS" == "1" ]] && ! command -v proxychains4 >/dev/null 2>&1; then
  echo "WARNING: USE_PROXYCHAINS=1 but proxychains4 not found — running unproxied" >&2
  USE_PROXYCHAINS=0
fi

mkdir -p "$STATE_DIR" "$LOG_DIR"

log() { printf '[%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"; }

# ---- Single instance enforcement ------------------------------------------
if [[ -s "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  log "Daemon already running (pid $(cat "$PID_FILE")), exiting" >> "$LOG_FILE"
  exit 0
fi
echo $$ > "$PID_FILE"

# ---- Graceful shutdown ----------------------------------------------------
SHUTDOWN=0
shutdown_handler() {
  log "Shutdown signal received, will exit after current cycle" >> "$LOG_FILE"
  SHUTDOWN=1
}
trap shutdown_handler TERM INT
trap "rm -f '$PID_FILE'" EXIT

# ---- Mode profile loader --------------------------------------------------
load_profile() {
  local mode=""
  [[ -f "$MODE_FILE" ]] && mode="$(tr -d '[:space:]' < "$MODE_FILE" 2>/dev/null || true)"
  mode="${mode:-browse}"

  if [[ "$mode" == "night" ]] && command -v acpi >/dev/null 2>&1; then
    if acpi -a 2>/dev/null | grep -qi 'off-line'; then
      log "On battery — forcing browse mode this cycle" >> "$LOG_FILE"
      mode="browse"
    fi
  fi

  case "$mode" in
    night)
      export HTTPX_JOBS=2
      export HTTPX_THREADS=80
      export HTTPX_RATE=100
      export HTTPX_TIMEOUT=10
      export CHUNK_LINES=10000
      export MAX_HTTPX_INPUT_PER_RUN=150000
      SLEEP_SECS=1800
      ;;
    browse|*)
      export HTTPX_JOBS=1
      export HTTPX_THREADS=15
      export HTTPX_RATE=15
      export HTTPX_TIMEOUT=10
      export CHUNK_LINES=5000
      export MAX_HTTPX_INPUT_PER_RUN=20000
      SLEEP_SECS=3600
      ;;
  esac

  CURRENT_MODE="$mode"
}

# ---- Silent background cleanup --------------------------------------------
auto_cleanup() {
  find "$BASE_DIR/archive" -maxdepth 1 -type d -name 'run_*' -mtime +3 -exec rm -rf {} + 2>/dev/null || true

  if [[ -f "$LOG_FILE" ]]; then
    local logsize; logsize="$(du -sm "$LOG_FILE" 2>/dev/null | awk '{print $1}')"
    if [[ "${logsize:-0}" -gt 50 ]]; then
      tail -n 10000 "$LOG_FILE" > "$LOG_FILE.tmp" && mv "$LOG_FILE.tmp" "$LOG_FILE"
    fi
  fi

  find "$BASE_DIR/spool/sent" -type f -mtime +7 -delete 2>/dev/null || true

  local triage_count
  triage_count="$(ls -t "$BASE_DIR/triage/report_"*.md 2>/dev/null | wc -l | tr -d ' ')"
  if [[ "${triage_count:-0}" -gt 10 ]]; then
    ls -t "$BASE_DIR/triage/report_"*.md 2>/dev/null | tail -n +11 | xargs rm -f 2>/dev/null || true
  fi
}

# ---- Pass-throughs --------------------------------------------------------
export ES_URL="${ES_URL:-http://127.0.0.1:9200}"
export ES_USER="${ES_USER:-elastic}"
export INDEX_NAME="${INDEX_NAME:-recon_alive}"
export RUN_TRIAGE="${RUN_TRIAGE:-1}"
export TRIAGE_SCRIPT="${TRIAGE_SCRIPT:-$REPO_ROOT/scripts/triage.sh}"
export PATH="$PATH:$HOME/go/bin:/usr/local/bin:/usr/local/go/bin"

# ---- Proxy wrapper --------------------------------------------------------
# All child processes spawned by auto_recon.sh (httpx, subfinder, assetfinder,
# curl to external targets) inherit the proxychains wrapper.
# ES bulk ingest to 127.0.0.1 is bypassed via the localnet directive in
# /etc/proxychains4.conf — it never touches the proxy.
run_auto_recon() {
  if [[ "$USE_PROXYCHAINS" == "1" ]]; then
    log "Proxy: enabled via proxychains4"
    proxychains4 -q bash "$AUTO_RECON"
  else
    bash "$AUTO_RECON"
  fi
}

# ---- Main loop ------------------------------------------------------------
{
  log "===== recon_daemon started (pid $$) ====="
  log "auto_recon=$AUTO_RECON  mode_file=$MODE_FILE  proxy=${USE_PROXYCHAINS}"

  cycle=0
  while [[ "$SHUTDOWN" -eq 0 ]]; do
    cycle=$((cycle + 1))
    auto_cleanup
    load_profile
    log "----- Cycle $cycle  mode=$CURRENT_MODE  rate=$HTTPX_RATE  threads=$HTTPX_THREADS  cap=$MAX_HTTPX_INPUT_PER_RUN -----"

    if [[ -x "$AUTO_RECON" ]]; then
      run_auto_recon || log "auto_recon exited non-zero (will retry next cycle)"
    else
      log "ERROR: $AUTO_RECON not found or not executable"
      sleep 60
      continue
    fi

    log "Cycle $cycle done. Sleeping ${SLEEP_SECS}s"

    local_slept=0
    while [[ "$local_slept" -lt "$SLEEP_SECS" && "$SHUTDOWN" -eq 0 ]]; do
      sleep 5
      local_slept=$((local_slept + 5))
    done
  done

  log "===== recon_daemon shutting down ====="
} >> "$LOG_FILE" 2>&1

#!/usr/bin/env bash
# =============================================================================
# recon_daemon.sh — Single master supervisor. Replaces:
#   - recon_validation_guard.sh (gone — error isolation moved into validate.sh)
#   - recon_httpx_watchdog.sh   (gone — hard timeout in validate.sh)
#   - recon_firstblood_ctl.sh   (merged into recon_ctl.sh)
#
# DESIGN
#   - Owns a single PID
#   - Runs sub-supervisors as background jobs:
#       * validate-loop   (drains queue, ingests ES, calls takeover hunter, triages)
#       * discovery-loop  (refills queue from chaos/subfinder/assetfinder)
#       * hot-seed-loop   (taps live subfinder for instant first-blood material)
#       * scope-watch-loop (detects new bounty programs)
#       * takeover-watch  (long-running takeover hunter for re-checks)
#   - Each loop: backoff on failure, NEVER dies permanently
#   - Reads ~/.recon_mode each cycle for browse|night profile
#   - Auto-downgrades night→browse on battery (saves laptop)
# =============================================================================
set -uo pipefail
IFS=$'\n\t'

BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="$BASE_DIR/state"
LOG_DIR="$BASE_DIR/logs"
PID_FILE="$STATE_DIR/recon_daemon.pid"
LOG_FILE="$LOG_DIR/recon_daemon.log"
MODE_FILE="$HOME/.recon_mode"

VALIDATE="${VALIDATE:-$HOME/recon_validate.sh}"
DISCOVERY="${DISCOVERY:-$HOME/recon_discovery.sh}"
HOT_SEED="${HOT_SEED:-$HOME/recon_hot_seed.sh}"
SCOPE_WATCH="${SCOPE_WATCH:-$HOME/recon_scope_watch.sh}"
TAKEOVER="${TAKEOVER:-$HOME/recon_takeover_hunter.sh}"

mkdir -p "$STATE_DIR" "$LOG_DIR"

log() { printf '[%s DAEMON] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"; }

# ---- Single instance ----
if [[ -s "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  log "Daemon already running (pid $(cat "$PID_FILE"))" >> "$LOG_FILE"
  exit 0
fi
echo $$ > "$PID_FILE"

# ---- Shutdown handling ----
SHUTDOWN=0
shutdown_handler() { SHUTDOWN=1; log "Shutdown signal — propagating to children"; }
trap shutdown_handler TERM INT
cleanup_exit() {
  log "Cleaning up"
  jobs -p 2>/dev/null | xargs -r kill -TERM 2>/dev/null || true
  sleep 5
  jobs -p 2>/dev/null | xargs -r kill -KILL 2>/dev/null || true
  rm -f "$PID_FILE"
}
trap cleanup_exit EXIT

# ---- Mode profile loader ----
load_profile() {
  local mode=""
  [[ -f "$MODE_FILE" ]] && mode="$(tr -d '[:space:]' < "$MODE_FILE" 2>/dev/null || true)"
  mode="${mode:-browse}"

  # Auto-downgrade if on battery
  if [[ "$mode" == "night" ]] && command -v acpi >/dev/null 2>&1; then
    if acpi -a 2>/dev/null | grep -qi 'off-line'; then
      log "On battery — forcing browse mode"
      mode="browse"
    fi
  fi

  case "$mode" in
    night)
      # SAFE night profile (NOT the 4000rps catastrophe from prior build)
      export HTTPX_THREADS=120
      export HTTPX_RATE=200          # per worker; with parallelism ~600-800 rps total
      export HTTPX_TIMEOUT=10
      export HTTPX_MAX_RUNTIME=1500  # 25 min hard cap
      export BATCHES_PER_CYCLE=4
      export INBOX_FILE_CAP=200
      export BATCH_SIZE=2500
      VALIDATE_SLEEP=300        # 5 min between cycles
      DISCOVERY_SLEEP=900       # 15 min
      HOT_SEED_SLEEP=180        # 3 min
      SCOPE_SLEEP=3600          # 1h
      ;;
    browse|*)
      # Polite — won't impact your browsing
      export HTTPX_THREADS=15
      export HTTPX_RATE=15
      export HTTPX_TIMEOUT=10
      export HTTPX_MAX_RUNTIME=900   # 15 min hard cap
      export BATCHES_PER_CYCLE=2
      export INBOX_FILE_CAP=200
      export BATCH_SIZE=2500
      VALIDATE_SLEEP=900       # 15 min
      DISCOVERY_SLEEP=3600     # 1h
      HOT_SEED_SLEEP=600       # 10 min
      SCOPE_SLEEP=7200         # 2h
      ;;
  esac
  CURRENT_MODE="$mode"
}

# ---- Periodic cleanup ----
auto_cleanup() {
  # Prune archive runs
  find "$BASE_DIR/archive" -maxdepth 1 -type d -name 'run_*' -mtime +3 -exec rm -rf {} + 2>/dev/null || true
  # Rotate own log if > 50MB
  if [[ -f "$LOG_FILE" ]]; then
    local sz; sz="$(du -sm "$LOG_FILE" 2>/dev/null | awk '{print $1}')"
    if [[ "${sz:-0}" -gt 50 ]]; then
      tail -n 10000 "$LOG_FILE" > "$LOG_FILE.tmp" && mv "$LOG_FILE.tmp" "$LOG_FILE"
    fi
  fi
  # Clean sent spool > 7d
  find "$BASE_DIR/spool/sent" -type f -mtime +7 -delete 2>/dev/null || true
  # Prune old triage reports — keep 10
  local cnt; cnt="$(ls -t "$BASE_DIR/triage/report_"*.md 2>/dev/null | wc -l | tr -d ' ')"
  if [[ "${cnt:-0}" -gt 10 ]]; then
    ls -t "$BASE_DIR/triage/report_"*.md 2>/dev/null | tail -n +11 | xargs rm -f 2>/dev/null || true
  fi
}

# ---- Generic supervised loop runner ----
# Usage: supervise <name> <sleep_var_name> <command...>
supervise_loop() {
  local name="$1"; shift
  local sleep_var="$1"; shift
  local backoff=10 max_backoff=600

  while [[ "$SHUTDOWN" -eq 0 ]]; do
    load_profile  # so children always see fresh env
    local sleep_secs="${!sleep_var}"

    log "[$name] starting iteration (mode=$CURRENT_MODE)"
    if "$@"; then
      backoff=10
    else
      log "[$name] failed (rc=$?), backing off ${backoff}s"
      sleep "$backoff"
      backoff=$(( backoff * 2 )); [[ "$backoff" -gt "$max_backoff" ]] && backoff="$max_backoff"
      continue
    fi

    # Interruptible sleep
    local slept=0
    while [[ "$slept" -lt "$sleep_secs" && "$SHUTDOWN" -eq 0 ]]; do
      sleep 5; slept=$((slept + 5))
    done
  done
  log "[$name] exiting (shutdown)"
}

# ---- Wrappers (each isolates env + propagates Discord webhook) ----
DISCORD_WEBHOOK="${DISCORD_WEBHOOK:-}"
[[ -z "$DISCORD_WEBHOOK" && -f "$HOME/.recon_discord" ]] && \
  DISCORD_WEBHOOK="$(tr -d '[:space:]' < "$HOME/.recon_discord" 2>/dev/null || true)"
export DISCORD_WEBHOOK
export PATH="$PATH:$HOME/go/bin:/usr/local/bin:/usr/local/go/bin"


# V21_BLOCK_BEGIN — added by recon_v21 install (remove block to revert)
SCOPE_DB_INTERVAL=${SCOPE_DB_INTERVAL:-86400}
CVE_KEV_INTERVAL=${CVE_KEV_INTERVAL:-3600}
CVE_NVD_INTERVAL=${CVE_NVD_INTERVAL:-86400}
NUCLEI_INTERVAL=${NUCLEI_INTERVAL:-21600}

V21_SCOPE_DB="${V21_SCOPE_DB:-$HOME/recon_scope_db.sh}"
V21_CVE_INTEL="${V21_CVE_INTEL:-$HOME/recon_cve_intel.sh}"
V21_NUCLEI="${V21_NUCLEI:-$HOME/recon_nuclei.sh}"
V21_KILL="$HOME/recon/state/kill"

# V2.1 sub-loop wrappers — each respects killswitch
v21_killed() { [[ -f "$V21_KILL/v2_$1" ]]; }

run_scope_db()   { v21_killed scope  && return 0; bash "$V21_SCOPE_DB"; }
run_cve_kev()    { v21_killed cve    && return 0; bash "$V21_CVE_INTEL" kev; }
run_cve_nvd()    { v21_killed cve    && return 0; bash "$V21_CVE_INTEL" nvd; }
run_nuclei_v21() {
  v21_killed nuclei && return 0
  # Resource gate before nuclei (heaviest module)
  local ram_pct disk_gb
  ram_pct="$(free | awk '/^Mem:/ {printf "%.0f", ($3/$2)*100}')"
  disk_gb="$(df -BG "$HOME" | awk 'NR==2 {gsub("G",""); print $4}')"
  if [[ "${ram_pct:-0}" -gt 90 ]]; then
    log "[nuclei-v21] SKIP (RAM ${ram_pct}%)"; return 0
  fi
  if [[ "${disk_gb:-100}" -lt 5 ]]; then
    log "[nuclei-v21] SKIP (disk ${disk_gb}GB)"; return 0
  fi
  bash "$V21_NUCLEI"
}
# V21_BLOCK_END

# V214_SCHED_BEGIN — schedule-based mode switcher
SCHEDULE_SLEEP=${SCHEDULE_SLEEP:-300}   # check every 5 minutes
SCHEDULE_SCRIPT="${SCHEDULE_SCRIPT:-$HOME/recon_schedule.sh}"
run_schedule() {
  [[ -x "$SCHEDULE_SCRIPT" ]] && bash "$SCHEDULE_SCRIPT" || true
}
# V214_SCHED_END
run_validate()    { bash "$VALIDATE";    }
run_discovery()   { bash "$DISCOVERY";   }
run_hot_seed()    { bash "$HOT_SEED";    }
run_scope_watch() { bash "$SCOPE_WATCH"; }

# Takeover watch is long-running; supervise differently
run_takeover_watch() {
  log "[takeover-watch] launching watch mode"
  bash "$TAKEOVER" watch
}

BOT_SCRIPT="${BOT_SCRIPT:-$HOME/recon_discord_bot.sh}"
run_discord_bot() {
  [[ -x "$BOT_SCRIPT" ]] || { log "[bot] not found/executable, skipping"; return 0; }
  [[ -f "$HOME/.recon_discord_bot" && -f "$HOME/.recon_discord_allowed_uid" && -f "$HOME/.recon_discord_channel_id" ]] || {
    log "[bot] credentials not configured, skipping (see RUNBOOK.md setup)"
    return 0
  }
  log "[bot] launching"
  bash "$BOT_SCRIPT"
}

# ---- Master loop ----
{
  log "===== recon_daemon started (pid $$) ====="
  load_profile
  log "Initial mode: $CURRENT_MODE"

  last_cleanup=0

  # Launch all sub-loops as background jobs
  supervise_loop "validate"    "VALIDATE_SLEEP"  run_validate    &
  supervise_loop "discovery"   "DISCOVERY_SLEEP" run_discovery   &
  supervise_loop "hot-seed"    "HOT_SEED_SLEEP"  run_hot_seed    &
  supervise_loop "scope-watch" "SCOPE_SLEEP"     run_scope_watch &

  supervise_loop "schedule"   "SCHEDULE_SLEEP"    run_schedule   &

  # V21 sub-loops
  supervise_loop "scope-db"  "SCOPE_DB_INTERVAL" run_scope_db   &
  supervise_loop "cve-kev"   "CVE_KEV_INTERVAL"  run_cve_kev    &
  supervise_loop "cve-nvd"   "CVE_NVD_INTERVAL"  run_cve_nvd    &
  supervise_loop "nuclei-v21" "NUCLEI_INTERVAL"  run_nuclei_v21 &

    # Long-running — supervised with simple restart loops
  (
    while [[ "$SHUTDOWN" -eq 0 ]]; do
      run_takeover_watch || log "[takeover-watch] died, restarting in 30s"
      sleep 30
    done
  ) &
  (
    while [[ "$SHUTDOWN" -eq 0 ]]; do
      run_discord_bot || log "[bot] died, restarting in 60s"
      sleep 60
    done
  ) &

  # Master housekeeping loop
  while [[ "$SHUTDOWN" -eq 0 ]]; do
    now="$(date +%s)"
    if (( now - last_cleanup > 1800 )); then
      auto_cleanup
      last_cleanup="$now"
    fi
    sleep 30
  done

  log "===== recon_daemon shutting down ====="
} >> "$LOG_FILE" 2>&1

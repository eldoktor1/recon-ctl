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
#   - Reads ~/.recon_mode each cycle for browse|boost profile
#   - Auto-downgrades boost/night to browse on battery (saves laptop)
# =============================================================================
set -uo pipefail
IFS=$'\n\t'

BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="$BASE_DIR/state"
LOG_DIR="$BASE_DIR/logs"
PID_FILE="$STATE_DIR/recon_daemon.pid"
LOG_FILE="$LOG_DIR/recon_daemon.log"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

script_path() { printf '%s\n' "$SCRIPT_DIR/$1"; }

VALIDATE="${VALIDATE:-$(script_path recon_validate.sh)}"
DISCOVERY="${DISCOVERY:-$(script_path recon_discovery.sh)}"
HOT_SEED="${HOT_SEED:-$(script_path recon_hot_seed.sh)}"
SCOPE_WATCH="${SCOPE_WATCH:-$(script_path recon_scope_watch.sh)}"
TAKEOVER="${TAKEOVER:-$(script_path recon_takeover_hunter.sh)}"


SCANNER_USER="${SCANNER_USER:-reconrun}"
# v2.5.6: Tor / proxychains removed. Recon egress is now system-default
# (assumed Mullvad WG, enforced by nftables kill-switch on reconrun uid).
# These two env vars are kept as no-ops so existing call sites compile.
PROXY_URL="${PROXY_URL:-}"
USE_PROXYCHAINS="${USE_PROXYCHAINS:-0}"

prepare_scanner_dirs() {
  local shared_dirs=(
    "$BASE_DIR"
    "$STATE_DIR"
    "$STATE_DIR/kill"
    "$LOG_DIR"
    "$BASE_DIR/queue"
    "$BASE_DIR/queue/inbox"
    "$BASE_DIR/queue/processing"
    "$BASE_DIR/queue/done"
    "$BASE_DIR/spool"
    "$BASE_DIR/spool/pending"
    "$BASE_DIR/spool/sent"
    "$BASE_DIR/spool/failed"
    "$BASE_DIR/firstblood"
    "$BASE_DIR/triage"
    "$STATE_DIR/true_fresh"
    "$BASE_DIR/scope"
    "$BASE_DIR/scope/raw"
    "$BASE_DIR/cache"
    "$BASE_DIR/cache/programs"
    "$BASE_DIR/cve"
    "$BASE_DIR/cve/raw"
    "$BASE_DIR/vuln"
    "$BASE_DIR/vuln/raw"
    "$BASE_DIR/ai_review"
    "$BASE_DIR/ai_review/pending"
  )
  local scanner_dirs=(
    "$BASE_DIR/nuclei"
    "$BASE_DIR/nuclei/results"
    "$BASE_DIR/nuclei/fingerprints"
  )

  mkdir -p "${shared_dirs[@]}"

  [[ "$(id -un 2>/dev/null || true)" != "$SCANNER_USER" ]] || return 0
  id "$SCANNER_USER" >/dev/null 2>&1 || return 0

  sudo -n -u "$SCANNER_USER" env HOME="$HOME" BASE_DIR="$BASE_DIR" mkdir -p "${scanner_dirs[@]}" 2>/dev/null || true
  command -v setfacl >/dev/null 2>&1 || return 0

  local owner_user
  owner_user="$(id -un 2>/dev/null || true)"
  setfacl \
    -m "u:${SCANNER_USER}:rwx" \
    -m "d:u:${SCANNER_USER}:rwx" \
    -m "u:${owner_user}:rwx" \
    -m "d:u:${owner_user}:rwx" \
    "${shared_dirs[@]}" 2>/dev/null || true
}

run_scanner() {
  local env_args=(
    HOME="$HOME"
    BASE_DIR="$BASE_DIR"
    ES_URL="${ES_URL:-http://127.0.0.1:9200}"
    INDEX_NAME="${INDEX_NAME:-recon_alive}"
    USE_PROXYCHAINS="0"
    PROXY_URL=""
    HTTPX_THREADS="${HTTPX_THREADS:-15}"
    HTTPX_RATE="${HTTPX_RATE:-15}"
    HTTPX_TIMEOUT="${HTTPX_TIMEOUT:-10}"
    HTTPX_MAX_RUNTIME="${HTTPX_MAX_RUNTIME:-900}"
    BATCHES_PER_CYCLE="${BATCHES_PER_CYCLE:-2}"
    INBOX_FILE_CAP="${INBOX_FILE_CAP:-200}"
    BATCH_SIZE="${BATCH_SIZE:-2500}"
    ENABLE_OLLAMA_AI="${ENABLE_OLLAMA_AI:-1}"
    OLLAMA_URL="${OLLAMA_URL:-http://127.0.0.1:11434}"
    OLLAMA_MODEL_LEAD="${OLLAMA_MODEL_LEAD:-llama3.1:8b-instruct-q4_K_M}"
    AI_MAX_LEADS="${AI_MAX_LEADS:-50}"
    AI_MIN_SCORE="${AI_MIN_SCORE:-12}"
    MIN_AI_RELEVANCE="${MIN_AI_RELEVANCE:-7}"
    PATH="$PATH"
  )
  if [[ "$(id -un 2>/dev/null || true)" == "$SCANNER_USER" ]]; then
    env "${env_args[@]}" "$@"
  else
    sudo -n -u "$SCANNER_USER" env "${env_args[@]}" "$@"
  fi
}

prepare_scanner_dirs

log() { printf '[%s DAEMON] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"; }

archive_file() {
  local archive_root="$1" file="$2"
  [[ -f "$file" ]] || return 0
  local rel dest_dir
  rel="${file#$BASE_DIR/}"
  dest_dir="$archive_root/$(dirname "$rel")"
  mkdir -p "$dest_dir"
  mv "$file" "$dest_dir/" 2>/dev/null || true
}

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
  # Stop certstream listener (long-lived child of recon_true_fresh.sh)
  if [[ -s "$STATE_DIR/true_fresh/certstream.pid" ]]; then
    local cspid; cspid="$(cat "$STATE_DIR/true_fresh/certstream.pid" 2>/dev/null)"
    [[ -n "$cspid" ]] && kill "$cspid" 2>/dev/null || true
    rm -f "$STATE_DIR/true_fresh/certstream.pid"
  fi
  rm -f "$PID_FILE"
}
trap cleanup_exit EXIT

# ---- Runtime env loader (v2.5.2: single capable config, no mode toggle) ----
#
# One sane production profile: multi-worker + higher output, tempered for
# system-VPN egress (Mullvad WG). Without the Tor bottleneck, the practical
# limit becomes httpx-side concurrency vs. laptop CPU/network. 80 threads
# at 100 rps/worker keeps a typical residential gigabit link from
# saturating while still ~10-50x the old Tor-routed throughput.
#
# On-battery auto-throttle: halve concurrency + rate when AC is unplugged.
load_runtime_env() {
  export HTTPX_THREADS="${HTTPX_THREADS_OVERRIDE:-80}"
  export HTTPX_RATE="${HTTPX_RATE_OVERRIDE:-100}"   # per worker; Tor throttles total
  export HTTPX_TIMEOUT=10
  export HTTPX_MAX_RUNTIME=1200                      # 20 min hard cap
  export BATCHES_PER_CYCLE=8
  export INBOX_FILE_CAP=200
  export BATCH_SIZE=2500
  VALIDATE_SLEEP=120                                 # 2 min — responsive; was 7 min which caused 10hr backlogs
  DISCOVERY_SLEEP=1800                               # 30 min
  HOT_SEED_SLEEP=300                                 # 5 min
  SCOPE_SLEEP=5400                                   # 90 min

  if command -v acpi >/dev/null 2>&1 && acpi -a 2>/dev/null | grep -qi 'off-line'; then
    export HTTPX_THREADS=$(( HTTPX_THREADS / 2 ))
    export HTTPX_RATE=$(( HTTPX_RATE / 2 ))
    BATCHES_PER_CYCLE=3
    POWER_STATE="battery"
  else
    POWER_STATE="ac"
  fi
}

# ---- Periodic cleanup ----
auto_cleanup() {
  local archive_root="$BASE_DIR/archive/auto_cleanup_$(date -u +%Y%m%d)"
  # Prune archive runs
  find "$BASE_DIR/archive" -maxdepth 1 -type d -name 'run_*' -mtime +3 -exec rm -rf {} + 2>/dev/null || true
  # Rotate own log if > 50MB
  if [[ -f "$LOG_FILE" ]]; then
    local sz; sz="$(du -sm "$LOG_FILE" 2>/dev/null | awk '{print $1}')"
    if [[ "${sz:-0}" -gt 50 ]]; then
      tail -n 10000 "$LOG_FILE" > "$LOG_FILE.tmp" && mv "$LOG_FILE.tmp" "$LOG_FILE"
    fi
  fi
  # Archive sent spool > 7d
  local sent
  while IFS= read -r -d '' sent; do
    archive_file "$archive_root" "$sent"
  done < <(find "$BASE_DIR/spool/sent" -type f -mtime +7 -print0 2>/dev/null)
  # Prune old triage reports — keep 10
  local cnt; cnt="$(ls -t "$BASE_DIR/triage/report_"*.md 2>/dev/null | wc -l | tr -d ' ')"
  if [[ "${cnt:-0}" -gt 10 ]]; then
    local report
    while IFS= read -r report; do
      archive_file "$archive_root" "$report"
    done < <(ls -t "$BASE_DIR/triage/report_"*.md 2>/dev/null | tail -n +11)
  fi
}

# ---- Generic supervised loop runner ----
# Usage: supervise <name> <sleep_var_name> <command...>
supervise_loop() {
  local name="$1"; shift
  local sleep_var="$1"; shift
  local backoff=10 max_backoff=600

  while [[ "$SHUTDOWN" -eq 0 ]]; do
    load_runtime_env  # so children always see fresh env (re-checks AC/battery)
    local sleep_secs="${!sleep_var}"

    log "[$name] starting iteration (power=$POWER_STATE threads=$HTTPX_THREADS)"
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


SCOPE_DB_INTERVAL=${SCOPE_DB_INTERVAL:-86400}
CVE_KEV_INTERVAL=${CVE_KEV_INTERVAL:-3600}
CVE_NVD_INTERVAL=${CVE_NVD_INTERVAL:-86400}
VULN_FEED_INTERVAL=${VULN_FEED_INTERVAL:-3600}
NUCLEI_INTERVAL=${NUCLEI_INTERVAL:-21600}

V21_SCOPE_DB="${V21_SCOPE_DB:-$(script_path recon_scope_db.sh)}"
V21_CVE_INTEL="${V21_CVE_INTEL:-$(script_path recon_cve_intel.sh)}"
V21_VULN_FEED="${V21_VULN_FEED:-$(script_path recon_vuln_feed.sh)}"
V21_NUCLEI="${V21_NUCLEI:-$(script_path recon_nuclei.sh)}"
V21_KILL="$HOME/recon/state/kill"

# V2.1 sub-loop wrappers — each respects killswitch
v21_killed() { [[ -f "$V21_KILL/v2_$1" ]]; }

run_scope_db()   { v21_killed scope  && return 0; bash "$V21_SCOPE_DB"; }
run_cve_kev()    { v21_killed cve    && return 0; bash "$V21_CVE_INTEL" kev; }
run_cve_nvd()    { v21_killed cve    && return 0; bash "$V21_CVE_INTEL" nvd; }
run_vuln_feed()  { v21_killed vuln_feed && return 0; run_scanner bash "$V21_VULN_FEED" all; }
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
  run_scanner bash "$V21_NUCLEI"
}

# ---- True-Fresh engine (v2.5) ---------------------------------------------
# Passive (CT logs + crt.sh). Direct egress — does NOT run under reconrun/Tor.
TRUE_FRESH_SCRIPT="${TRUE_FRESH_SCRIPT:-$(script_path recon_true_fresh.sh)}"
TRUE_FRESH_SLEEP="${TRUE_FRESH_SLEEP:-120}"
run_true_fresh() { bash "$TRUE_FRESH_SCRIPT"; }

# ---- Bounty / deep / active / JS scan loops (v2.5) ------------------------
# All four are dispatched from a single script: recon_fresh_modules.sh <mode>.
BOUNTY_SCAN_INTERVAL="${BOUNTY_SCAN_INTERVAL:-1800}"
DEEP_SCAN_INTERVAL="${DEEP_SCAN_INTERVAL:-86400}"
ACTIVE_CHECKS_INTERVAL="${ACTIVE_CHECKS_INTERVAL:-600}"
JS_SCAN_INTERVAL="${JS_SCAN_INTERVAL:-1800}"

FRESH_MODULES_SCRIPT="${FRESH_MODULES_SCRIPT:-$(script_path recon_fresh_modules.sh)}"

run_smart_scan()    { v21_killed nuclei && return 0; [[ -f "$FRESH_MODULES_SCRIPT" ]] && run_scanner bash "$FRESH_MODULES_SCRIPT" smart-scan     || true; }
run_deep_scan()     { v21_killed nuclei && return 0; [[ -f "$FRESH_MODULES_SCRIPT" ]] && run_scanner bash "$FRESH_MODULES_SCRIPT" deep-scan      || true; }
run_active_checks() { [[ -f "$FRESH_MODULES_SCRIPT" ]] && run_scanner bash "$FRESH_MODULES_SCRIPT" active-checks || true; }
run_js_scanner()    { [[ -f "$FRESH_MODULES_SCRIPT" ]] && run_scanner bash "$FRESH_MODULES_SCRIPT" js-scan       || true; }

run_validate()        { run_scanner bash "$VALIDATE" --exclude-prefix 00_; }
run_validate_fast()   { run_scanner bash "$VALIDATE" --prefix 00_;          }
run_discovery()       { run_scanner bash "$DISCOVERY";                      }
run_hot_seed()        { bash "$HOT_SEED";                                   }
run_scope_watch()     { run_scanner bash "$SCOPE_WATCH";                    }
VALIDATE_FAST_SLEEP="${VALIDATE_FAST_SLEEP:-120}"

# Takeover watch is long-running; supervise differently
# v2.2: throttled — only log launches when state actually changes (avoid spam
# on benign lock-contention loops). Subsequent attempts are quiet until either
# the script stays up >60s (=actually running) or fails for a new reason.
TAKEOVER_LAST_STATE="${TAKEOVER_LAST_STATE:-unknown}"
run_takeover_watch() {
  local started=0 finished=0 dur state
  started="$(date +%s)"
  if run_scanner bash "$TAKEOVER" watch >/dev/null 2>&1; then
    finished="$(date +%s)"; dur=$(( finished - started ))
    if [[ "$dur" -ge 60 ]]; then
      state="ran-${dur}s"
    else
      state="lock-contention"
    fi
  else
    finished="$(date +%s)"; dur=$(( finished - started ))
    state="failed-${dur}s"
  fi
  if [[ "$state" != "$TAKEOVER_LAST_STATE" ]]; then
    log "[takeover-watch] state=$state"
    TAKEOVER_LAST_STATE="$state"
  fi
  return 0
}

BOT_SCRIPT="${BOT_SCRIPT:-$(script_path recon_discord_bot.sh)}"
run_discord_bot() {
  [[ -f "$BOT_SCRIPT" ]] || { log "[bot] not found, skipping"; return 0; }
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
  load_runtime_env
  log "Initial config: power=$POWER_STATE threads=$HTTPX_THREADS rate=$HTTPX_RATE batches=$BATCHES_PER_CYCLE"

  last_cleanup=0

  # Launch all sub-loops as background jobs
  supervise_loop "validate"      "VALIDATE_SLEEP"      run_validate      &
  supervise_loop "validate-fast" "VALIDATE_FAST_SLEEP" run_validate_fast &
  supervise_loop "discovery"     "DISCOVERY_SLEEP"     run_discovery     &
  supervise_loop "hot-seed"      "HOT_SEED_SLEEP"      run_hot_seed      &
  supervise_loop "scope-watch"   "SCOPE_SLEEP"         run_scope_watch   &

  supervise_loop "true-fresh" "TRUE_FRESH_SLEEP"  run_true_fresh &

  # V21 sub-loops
  supervise_loop "scope-db"  "SCOPE_DB_INTERVAL" run_scope_db   &
  supervise_loop "cve-kev"   "CVE_KEV_INTERVAL"  run_cve_kev    &
  supervise_loop "cve-nvd"   "CVE_NVD_INTERVAL"  run_cve_nvd    &
  supervise_loop "vuln-feed" "VULN_FEED_INTERVAL" run_vuln_feed &
  supervise_loop "nuclei-v21"     "NUCLEI_INTERVAL"        run_nuclei_v21     &
  supervise_loop "bounty-scan"    "BOUNTY_SCAN_INTERVAL"   run_smart_scan     &
  supervise_loop "deep-scan"      "DEEP_SCAN_INTERVAL"     run_deep_scan      &
  supervise_loop "active-checks"  "ACTIVE_CHECKS_INTERVAL" run_active_checks  &
  supervise_loop "js-scanner"     "JS_SCAN_INTERVAL"       run_js_scanner     &

    # Long-running — supervised with simple restart loops
  (
    # v2.2: 5-min retry interval (was 30s) — takeover_hunter holds its own
    # lock so a stuck/duplicate instance doesn't need fast-restart, and the
    # tighter cadence was burying real signal in the daemon log.
    while [[ "$SHUTDOWN" -eq 0 ]]; do
      run_takeover_watch || true
      sleep 300
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

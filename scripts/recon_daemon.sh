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
#   - Auto-throttles to 50% concurrency on battery (AC = full speed)
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

# ES connection globals used by auto_cleanup() scroll queries
ES_URL="${ES_URL:-http://127.0.0.1:9200}"
INDEX_NAME="${INDEX_NAME:-recon_alive}"
ALIVE_HOSTS="${ALIVE_HOSTS:-$STATE_DIR/alive_hosts.txt}"
source "$SCRIPT_DIR/recon_net.sh"
setup_es_netrc
ES_AUTH=(--netrc-file "$HOME/.recon_es_netrc")

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
    "$BASE_DIR/js_recon"
    "$BASE_DIR/js_recon/dump"
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

  # Default ACLs only propagate to NEW files — existing files that predate the
  # ACL setup (e.g. firstblood TSVs created before setfacl ran on the dir) need
  # to be fixed explicitly. reconrun owns these files so d0k cannot setfacl them
  # directly; run as reconrun (file owner) to grant d0k rw. Idempotent, ~ms.
  sudo -n -u "$SCANNER_USER" bash -c "
    find '$BASE_DIR/firstblood' -maxdepth 1 -type f 2>/dev/null \
      | xargs -r setfacl -m 'u:${owner_user}:rw' 2>/dev/null || true
  " 2>/dev/null || true
}

# ---- Global EGRESS GOVERNOR --------------------------------------------------
# Hard-cap concurrent target-facing scanners through the single Mullvad exit IP, so
# the aggregate egress can never spike no matter which loops align. Generous default
# (6) makes it a pure BACKSTOP: only the pathological "everything fires at once" case
# ever waits, and the wait is SOFT (after EGRESS_WAIT it proceeds — per-tool rate caps
# still bound egress), so steady-state throughput is never degraded.
EGRESS_SEM_DIR="${EGRESS_SEM_DIR:-$STATE_DIR/egress_sem}"
EGRESS_MAX="${EGRESS_MAX_SCANNERS:-6}"
EGRESS_WAIT="${EGRESS_WAIT:-900}"            # max wait for a slot, then proceed (soft cap)
EGRESS_SLOT_TTL="${EGRESS_SLOT_TTL:-2700}"  # reap a slot whose holder died/overran (45m)
_egress_reap() {
  local f now t; now="$(date +%s)"
  for f in "$EGRESS_SEM_DIR"/slot.*; do
    [[ -e "$f" ]] || continue
    t="$(awk '{print $1}' "$f" 2>/dev/null)"
    [[ -n "$t" && "$((now - t))" -lt "$EGRESS_SLOT_TTL" ]] || rm -f "$f" 2>/dev/null
  done
}
_egress_acquire() {   # prints the claimed slot path (or empty after soft-timeout)
  local label="${1:-scanner}" i deadline
  mkdir -p "$EGRESS_SEM_DIR" 2>/dev/null
  deadline="$(( $(date +%s) + EGRESS_WAIT ))"
  while :; do
    for ((i=1; i<=EGRESS_MAX; i++)); do
      if ( set -o noclobber; printf '%s %s\n' "$(date +%s)" "$label" > "$EGRESS_SEM_DIR/slot.$i" ) 2>/dev/null; then
        printf '%s' "$EGRESS_SEM_DIR/slot.$i"; return 0
      fi
    done
    _egress_reap
    [[ "$(date +%s)" -ge "$deadline" ]] && return 0   # soft cap: proceed ungoverned
    sleep "$(awk 'BEGIN{srand(); print 1+rand()*3}')"
  done
}
_egress_release() { [[ -n "${1:-}" ]] && rm -f "$1" 2>/dev/null || true; }

run_scanner() {
  # Hard VPN gate: never launch a target-facing scanner while egress is not on
  # Mullvad. recon_vpnguard maintains $STATE_DIR/vpn_down.
  if [[ -f "$STATE_DIR/vpn_down" ]]; then
    log "[run_scanner] BLOCKED — VPN down, refusing to launch: $*"
    return 0
  fi
  local _eslot; _eslot="$(_egress_acquire "${2##*/}")"   # global egress backstop (soft cap)
  local env_args=(
    HOME="$HOME"
    BASE_DIR="$BASE_DIR"
    ES_URL="${ES_URL:-http://127.0.0.1:9200}"
    INDEX_NAME="${INDEX_NAME:-recon_alive}"
    HTTPX_THREADS="${HTTPX_THREADS:-40}"     # balanced safe-max (aggregate; per-host stays 1 req)
    HTTPX_RATE="${HTTPX_RATE:-30}"
    HTTPX_TIMEOUT="${HTTPX_TIMEOUT:-10}"
    HTTPX_MAX_RUNTIME="${HTTPX_MAX_RUNTIME:-900}"
    BATCHES_PER_CYCLE="${BATCHES_PER_CYCLE:-2}"
    INBOX_FILE_CAP="${INBOX_FILE_CAP:-200}"
    BATCH_SIZE="${BATCH_SIZE:-2500}"
    # AI layer (v3.1+): Claude-Max validation agent (recon_ai_review.sh), config below.
    # The legacy Ollama pre-scorer (ENABLE_OLLAMA_AI/OLLAMA_*/AI_MAX_LEADS) was retired.
    CLAUDE_MODEL="${CLAUDE_MODEL:-sonnet}"
    AI_REVIEW_BATCH="${AI_REVIEW_BATCH:-15}"
    PATH="$PATH"
  )
  local rc
  if [[ "$(id -un 2>/dev/null || true)" == "$SCANNER_USER" ]]; then
    env "${env_args[@]}" "$@"; rc=$?
  else
    sudo -n -u "$SCANNER_USER" env "${env_args[@]}" "$@"; rc=$?
  fi
  _egress_release "$_eslot"
  return $rc
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

# ---- Single instance (atomic via flock on the PID file) ----
exec 8>"$PID_FILE"
if ! flock -n 8; then
  log "Daemon already running (pid $(cat "$PID_FILE" 2>/dev/null))" >> "$LOG_FILE"
  exit 0
fi
echo $$ >&8

# ---- Maintenance lock (fail-closed) ----
# Refuse to run while the pipeline is being rebuilt/upgraded. recon_ctl's cmd_start
# checks this too; this is the belt-and-suspenders guard for any direct daemon launch.
if [[ -f "$STATE_DIR/maintenance" ]]; then
  log "Maintenance lock set ($STATE_DIR/maintenance) — daemon refusing to start." >> "$LOG_FILE"
  exit 0
fi

# ---- CPU priority: deprioritize the whole daemon tree ----
# Every loop, scanner, triage run and jq worker is forked from this process and
# inherits its nice value (verified: the value survives fork, execve AND
# `sudo -u reconrun env …`). On WSL2 the Linux side shares CPU with the root
# /init that services `wsl.exe` session creation from Windows; at the default
# nice 0 a triage burst (up to 8 jq workers) competes EQUALLY with /init and
# starves it, so `wsl -d kali-linux -- …` from Windows times out (WSAETIMEDOUT
# / 0x8007274c). Renicing to 10 lets root's nice-0 /init preempt promptly while
# scans still get all otherwise-idle CPU. (IO scheduler is 'none' on WSL2, so
# ionice is a no-op — CPU nice is the only effective lever here.)
renice -n "${RECON_DAEMON_NICE:-10}" -p $$ >/dev/null 2>&1 || true

# ---- Shutdown handling ----
SHUTDOWN=0
shutdown_handler() { SHUTDOWN=1; log "Shutdown signal — propagating to children"; }
trap shutdown_handler TERM INT
cleanup_exit() {
  log "Cleaning up"
  jobs -p 2>/dev/null | xargs -r kill -TERM 2>/dev/null || true
  sleep 5
  jobs -p 2>/dev/null | xargs -r kill -KILL 2>/dev/null || true
  # Stop gungnir CT-log listener (long-lived child of recon_true_fresh.sh).
  # Started under setsid, so the pidfile holds a process-group leader — kill the
  # whole group to take down gungnir AND its flock-append reader together.
  if [[ -s "$STATE_DIR/true_fresh/gungnir.pid" ]]; then
    local gpid; gpid="$(cat "$STATE_DIR/true_fresh/gungnir.pid" 2>/dev/null)"
    if [[ -n "$gpid" ]]; then
      kill -TERM -- "-$gpid" 2>/dev/null || kill -TERM "$gpid" 2>/dev/null || true
    fi
    rm -f "$STATE_DIR/true_fresh/gungnir.pid"
  fi
  rm -f "$PID_FILE"
}
trap cleanup_exit EXIT

# ---- Runtime env loader ----
# Single production profile: 150 threads at 100 rps via Mullvad WG.
# httpx is a BREADTH tool (≈1-2 requests across many distinct hosts), so higher
# thread concurrency is safe — total request rate stays capped by HTTPX_RATE, so
# no single target is hammered. Local headroom is large (20 CPU, conntrack ~0%
# used); the binding constraint is tunnel reliability + per-target politeness,
# not threads. On-battery: auto-throttle to half concurrency.
load_runtime_env() {
  # FD headroom for high-concurrency scanners (hard limit is 1048576). Free, no
  # root. reconrun scanners run via sudo and may reset to their own limit, but
  # at this concurrency (~150 sockets) the 10240 default is already ample.
  ulimit -n 65536 2>/dev/null || true
  export HTTPX_THREADS="${HTTPX_THREADS_OVERRIDE:-150}"
  export HTTPX_RATE="${HTTPX_RATE_OVERRIDE:-100}"
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

  # Live rate override — written by `recon_ctl rate` / `recon-rate` alias.
  # Applied AFTER battery check so the value is exact (not further halved).
  local _rf="$STATE_DIR/rate_override"
  if [[ -f "$_rf" ]]; then
    local _ot _or
    _ot="$(grep '^THREADS=' "$_rf" 2>/dev/null | cut -d= -f2 | tr -d '[:space:]')"
    _or="$(grep '^RATE='   "$_rf" 2>/dev/null | cut -d= -f2 | tr -d '[:space:]')"
    [[ "$_ot" =~ ^[0-9]+$ ]] && export HTTPX_THREADS="$_ot"
    [[ "$_or" =~ ^[0-9]+$ ]] && export HTTPX_RATE="$_or"
    POWER_STATE="${POWER_STATE}+rate(${HTTPX_THREADS}t/${HTTPX_RATE}rps)"
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
  # Prune failed spool entries > 14d (poisoned bulk batches that will never succeed)
  local failed_dir="$BASE_DIR/spool/failed"
  if [[ -d "$failed_dir" ]]; then
    local pruned_failed=0 _ff
    while IFS= read -r -d '' _ff; do
      rm -f "$_ff" && pruned_failed=$(( pruned_failed + 1 )) || true
    done < <(find "$failed_dir" -maxdepth 1 -type f -mtime +14 -print0 2>/dev/null)
    [[ "$pruned_failed" -gt 0 ]] && log "auto_cleanup: pruned $pruned_failed stale failed spool entries (>14d)"
  fi
  # Rebuild alive_hosts.txt daily — removes offline hosts never seen in ES for 30+ days.
  # Runs async inside cleanup so it never blocks validate. Uses ES scroll to handle >10k results.
  local _prune_marker="$STATE_DIR/.alive_hosts_pruned"
  local _prune_age=$(( $(date -u +%s) - $(cat "$_prune_marker" 2>/dev/null || echo 0) ))
  if [[ "$_prune_age" -gt 86400 ]]; then
    local _alive_tmp; _alive_tmp="$(mktemp)"
    local _scroll_id="" _batch _count=0
    _batch="$(curl -fsS -m 30 "${ES_AUTH[@]}" -H 'Content-Type: application/json' \
      -X POST "$ES_URL/$INDEX_NAME/_search?scroll=1m" \
      -d '{"size":5000,"_source":["host"],"query":{"range":{"last_seen":{"gte":"now-30d/d"}}}}' \
      2>/dev/null)" || _batch=""
    if [[ -n "$_batch" ]]; then
      printf '%s' "$_batch" | jq -r '.hits.hits[]._source.host // empty' 2>/dev/null >> "$_alive_tmp"
      _scroll_id="$(printf '%s' "$_batch" | jq -r '._scroll_id // empty' 2>/dev/null)"
      _count=$(( _count + $(printf '%s' "$_batch" | jq '.hits.hits | length' 2>/dev/null || echo 0) ))
      while [[ -n "$_scroll_id" ]]; do
        _batch="$(curl -fsS -m 30 "${ES_AUTH[@]}" -H 'Content-Type: application/json' \
          -X POST "$ES_URL/_search/scroll" \
          -d "{\"scroll\":\"1m\",\"scroll_id\":\"$_scroll_id\"}" 2>/dev/null)" || break
        local _hits; _hits="$(printf '%s' "$_batch" | jq '.hits.hits | length' 2>/dev/null || echo 0)"
        [[ "$_hits" -eq 0 ]] && break
        printf '%s' "$_batch" | jq -r '.hits.hits[]._source.host // empty' 2>/dev/null >> "$_alive_tmp"
        _scroll_id="$(printf '%s' "$_batch" | jq -r '._scroll_id // empty' 2>/dev/null)"
        _count=$(( _count + _hits ))
      done
      [[ -n "$_scroll_id" ]] && curl -fsS -m 10 "${ES_AUTH[@]}" -X DELETE \
        "$ES_URL/_search/scroll" -H 'Content-Type: application/json' \
        -d "{\"scroll_id\":\"$_scroll_id\"}" >/dev/null 2>&1 || true
    fi
    if [[ -s "$_alive_tmp" ]]; then
      local _before; _before="$(wc -l < "$ALIVE_HOSTS" 2>/dev/null | tr -d ' ')"
      sort -u "$_alive_tmp" -o "$_alive_tmp"
      mv "$_alive_tmp" "$ALIVE_HOSTS"
      # reconrun (recon_validate.sh) also touches/appends this file every cycle —
      # grant rw, not r, or the next validate gets "touch: Permission denied" and
      # the scanner can no longer update the alive-host list after a daemon rebuild.
      command -v setfacl >/dev/null 2>&1 && setfacl -m u:reconrun:rw "$ALIVE_HOSTS" 2>/dev/null || true
      local _after; _after="$(wc -l < "$ALIVE_HOSTS" | tr -d ' ')"
      date -u +%s > "$_prune_marker"
      log "auto_cleanup: alive_hosts rebuilt $_before → $_after lines (30d window, $INDEX_NAME)"
    else
      rm -f "$_alive_tmp"
      log "auto_cleanup: alive_hosts rebuild failed (ES unreachable?) — keeping existing"
    fi
  fi
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
    # VPN gate: if recon_vpnguard tripped the vpn_down flag (egress not on
    # Mullvad), EVERY loop except the guard itself pauses — no scanner or feed
    # runs until Mullvad is reconfirmed and the guard clears the flag. This is
    # what stops the pipeline from scanning over the real IP if the VPN drops.
    if [[ "$name" != "vpnguard" && -f "$STATE_DIR/vpn_down" ]]; then
      log "[$name] paused — VPN down (vpn_down set); not running until VPN restored"
      sleep 15
      continue
    fi
    load_runtime_env  # so children always see fresh env (re-checks AC/battery)
    local sleep_secs="${!sleep_var}"

    # vpnguard logs its own state changes; logging every 20s here is pure noise.
    # Scanner loops get threads/rate context; lightweight loops get nothing extra.
    case "$name" in
      validate|validate-fast|discovery|scope-watch|nuclei-v21|bounty-scan|deep-scan|active-checks|js-scanner|cloudrecon|dast|params|vuln-feed)
        log "[$name] starting (power=$POWER_STATE threads=$HTTPX_THREADS rate=$HTTPX_RATE)" ;;
      vpnguard) ;;
      *) log "[$name] starting" ;;
    esac

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

# ---- Wrappers (each isolates env) ----
# Discord delivery is per-channel via discord_hook() in recon_net.sh, which
# reads ~/.recon_discord_<channel> at call time. No global webhook env is
# exported here anymore (the old ~/.recon_discord / _kev scheme is retired).
export PATH="$PATH:$HOME/go/bin:/usr/local/bin:/usr/local/go/bin"


SCOPE_DB_INTERVAL=${SCOPE_DB_INTERVAL:-86400}
CVE_KEV_INTERVAL=${CVE_KEV_INTERVAL:-3600}
CVE_NVD_INTERVAL=${CVE_NVD_INTERVAL:-86400}
VULN_FEED_INTERVAL=${VULN_FEED_INTERVAL:-3600}

V21_SCOPE_DB="${V21_SCOPE_DB:-$(script_path recon_scope_db.sh)}"
V21_CVE_INTEL="${V21_CVE_INTEL:-$(script_path recon_cve_intel.sh)}"
V21_VULN_FEED="${V21_VULN_FEED:-$(script_path recon_vuln_feed.sh)}"
V21_KILL="$HOME/recon/state/kill"

# V2.1 sub-loop wrappers — each respects killswitch
v21_killed() { [[ -f "$V21_KILL/v2_$1" ]]; }

run_scope_db()   { v21_killed scope  && return 0; bash "$V21_SCOPE_DB"; }
run_cve_kev()    { v21_killed cve    && return 0; bash "$V21_CVE_INTEL" kev; }
run_cve_nvd()    { v21_killed cve    && return 0; bash "$V21_CVE_INTEL" nvd; }
run_vuln_feed()  { v21_killed vuln_feed && return 0; run_scanner bash "$V21_VULN_FEED" all; }

# ---- True-Fresh engine (CT logs + crt.sh) ---------------------------------
# Passive feeds — runs as d0k, not reconrun (no scanning, no target traffic).
TRUE_FRESH_SCRIPT="${TRUE_FRESH_SCRIPT:-$(script_path recon_true_fresh.sh)}"
TRUE_FRESH_SLEEP="${TRUE_FRESH_SLEEP:-120}"
run_true_fresh() { bash "$TRUE_FRESH_SCRIPT"; }

# ---- Bounty / deep / active / JS scan loops (v2.5) ------------------------
# All four are dispatched from a single script: recon_fresh_modules.sh <mode>.
ACTIVE_CHECKS_INTERVAL="${ACTIVE_CHECKS_INTERVAL:-600}"
JS_SCAN_INTERVAL="${JS_SCAN_INTERVAL:-1800}"

FRESH_MODULES_SCRIPT="${FRESH_MODULES_SCRIPT:-$(script_path recon_fresh_modules.sh)}"

run_active_checks() { [[ -f "$FRESH_MODULES_SCRIPT" ]] && run_scanner bash "$FRESH_MODULES_SCRIPT" active-checks || true; }
run_js_scanner()    { [[ -f "$FRESH_MODULES_SCRIPT" ]] && run_scanner bash "$FRESH_MODULES_SCRIPT" js-scan       || true; }

# ---- Cloud cert-recon (Caduceus) + DAST param-fuzz (v2.8) -----------------
# Both target-facing -> run as reconrun via run_scanner. cloudrecon neighbor-
# scans known in-scope IPs for co-hosted certs; dast crawls+fuzzes fresh-first
# in-scope-paying hosts. Gated by the killswitch (v2_cloudrecon / v2_dast).
CLOUDRECON_SCRIPT="${CLOUDRECON_SCRIPT:-$(script_path recon_cloudrecon.sh)}"
CLOUDRECON_INTERVAL="${CLOUDRECON_INTERVAL:-3600}"
run_cloudrecon() { v21_killed cloudrecon && return 0; [[ -f "$CLOUDRECON_SCRIPT" ]] && run_scanner bash "$CLOUDRECON_SCRIPT" || true; }

# sus_params targeting catalog (recon_params.sh collect): crawls in-scope-paying
# hosts fresh-first, gf-classifies params, builds the recon_params ES index +
# per-class files for `recon_ctl params <class>`. Target-facing → run_scanner.
PARAMS_SCRIPT="${PARAMS_SCRIPT:-$(script_path recon_params.sh)}"
PARAMS_INTERVAL="${PARAMS_INTERVAL:-1800}"
PARAMS_VERIFY_INTERVAL="${PARAMS_VERIFY_INTERVAL:-3600}"
run_params() { v21_killed params && return 0; [[ -f "$PARAMS_SCRIPT" ]] && run_scanner bash "$PARAMS_SCRIPT" collect || true; }
# Active-probe the catalog for canary REFLECTION -> writes params/verify_xss.jsonl, the leads
# xss-confirm consumes (headless marker-exec). Without this the catalog fills but xss-confirm
# starves. Only `verify xss` here: param-confirm already does the SQLi/SSTI/redirect probes
# directly off the catalog (and db_confirms), so `verify sqli` would duplicate that work and
# orphan verify_sqli.jsonl. Safe primitive (canary GET), pays-gated + paced, Mullvad-gated.
run_params_verify() {
  v21_killed params && return 0
  [[ -f "$PARAMS_SCRIPT" ]] || return 0
  run_scanner bash "$PARAMS_SCRIPT" verify xss || true
}

# ---- Port scanner (recon_portscan.sh) ----------------------------------------
# Targeted sweep of ~120 purposeful ports on P1+ in-scope paying hosts that
# are not CDN-fronted and have not been scanned in the last 7 days.
# 90-min interval: processes 50 hosts/cycle → full P1+ pool scanned weekly.
PORTSCAN_SCRIPT="${PORTSCAN_SCRIPT:-$(script_path recon_portscan.sh)}"
PORTSCAN_INTERVAL="${PORTSCAN_INTERVAL:-5400}"   # 90 minutes
run_portscan() { v21_killed portscan && return 0; [[ -f "$PORTSCAN_SCRIPT" ]] && run_scanner bash "$PORTSCAN_SCRIPT" || true; }

# ---- 401/403 bypass tester (recon_bypass.sh) ---------------------------------
# WAF-fingerprint + tech-driven multi-path access-control bypass on score>=6
# in-scope paying hosts. 1h cycle, 30 hosts/batch, 7d per-host cooldown.
BYPASS_SCRIPT="${BYPASS_SCRIPT:-$(script_path recon_bypass.sh)}"
BYPASS_INTERVAL="${BYPASS_INTERVAL:-3600}"
run_bypass() { v21_killed bypass && return 0; [[ -f "$BYPASS_SCRIPT" ]] && run_scanner bash "$BYPASS_SCRIPT" || true; }

# ---- PHASE A evidence gate (recon_evidence_gate.sh) --------------------------
# Probes P0-CANDIDATEs (detection-only P0s triage held at P1) with non-intrusive
# class probes; promotes to P0 only on a real fire. Target-facing → run_scanner.
EVIDENCE_GATE_SCRIPT="${EVIDENCE_GATE_SCRIPT:-$(script_path recon_evidence_gate.sh)}"
GATE_INTERVAL="${GATE_INTERVAL:-1800}"   # 30 min
run_evidence_gate() { v21_killed evidence_gate && return 0; [[ -f "$EVIDENCE_GATE_SCRIPT" ]] && run_scanner bash "$EVIDENCE_GATE_SCRIPT" || true; }

# ---- v3 cohesive tail: reporter + observability digest ----------------------
# reporter.py: SQLite confirmed findings -> human review-queue artifacts (never
# auto-submits). observability.py: daily auditable digest. Run via run_scanner
# (reconrun) so they share the gate's ownership of ~/recon/v3/findings.db (the gate
# writes it as reconrun; a d0k reader/writer would hit a perms conflict). reporter
# may re-probe a stale finding (target-facing); run_scanner also enforces vpn_down.
V3_PY_DIR="${V3_PY_DIR:-$(cd "$(dirname "$(script_path recon_evidence_gate.sh)")/../engine" 2>/dev/null && pwd)}"
REPORTER_INTERVAL="${REPORTER_INTERVAL:-1800}"
V3_DIGEST_INTERVAL="${V3_DIGEST_INTERVAL:-86400}"
run_reporter()  { [[ -f "$V3_PY_DIR/reporter.py" ]] && run_scanner python3 "$V3_PY_DIR/reporter.py" >/dev/null 2>&1 || true; }
run_v3_digest() { [[ -f "$V3_PY_DIR/observability.py" ]] && run_scanner python3 "$V3_PY_DIR/observability.py" >/dev/null 2>&1 || true; }

# ---- Claude-Max validation agent (recon_ai_review.sh) ------------------------
# Headless `claude -p` (Max, NO API) adversarially validates gate-CONFIRMED findings
# (real / fp / needs-human) before they reach the review queue — the accuracy layer.
# Runs as d0k (NOT run_scanner) because Claude Code auth is per-user (~/.claude).
AI_REVIEW_SCRIPT="${AI_REVIEW_SCRIPT:-$(script_path recon_ai_review.sh)}"
AI_REVIEW_INTERVAL="${AI_REVIEW_INTERVAL:-1800}"
run_ai_review() { [[ -f "$AI_REVIEW_SCRIPT" ]] && bash "$AI_REVIEW_SCRIPT" >>"$LOG_FILE" 2>&1 || true; }

# ---- Claude-Max ANALYSIS agent (recon_ai_analyze.sh) ------------------------
# Headless Claude (Haiku — bulk/cheap, match-model-to-task) reads in-scope assets,
# decides what is worth verifying + which vuln class, and flags evidence-gate
# candidates: conscious surface selection, not blanket scanning. Feeds gate -> verify.
# Runs as d0k (Claude auth per-user). Not target-facing (reasons over stored data).
AI_ANALYZE_SCRIPT="${AI_ANALYZE_SCRIPT:-$(script_path recon_ai_analyze.sh)}"
AI_ANALYZE_INTERVAL="${AI_ANALYZE_INTERVAL:-3600}"
run_ai_analyze() { [[ -f "$AI_ANALYZE_SCRIPT" ]] && bash "$AI_ANALYZE_SCRIPT" >>"$LOG_FILE" 2>&1 || true; }

# ---- Claude-Max MONITOR / GUIDANCE pass (recon_ai_monitor.sh) ----------------
# Claude's oversight role: reads LOCAL telemetry (burn signals, verdict precision,
# failures/halts, daemon errors, VPN) and emits a health + guidance assessment to #ops.
# Read-only reasoning, NO target traffic. Runs as d0k. Watches for getting rate-limited/banned.
AI_MONITOR_SCRIPT="${AI_MONITOR_SCRIPT:-$(script_path recon_ai_monitor.sh)}"
AI_MONITOR_INTERVAL="${AI_MONITOR_INTERVAL:-3600}"
run_ai_monitor() { [[ -f "$AI_MONITOR_SCRIPT" ]] && bash "$AI_MONITOR_SCRIPT" >>"$LOG_FILE" 2>&1 || true; }

# ---- UNIQUE pillars (v3.7): go where the crowd doesn't ----------------------
# recon_jsintel  — mine each host's JS for the HIDDEN API surface + verify LIVE secrets
#                  (trufflehog). Target-facing -> d0k, VPN-gated. Writes endpoint feedstock.
# recon_ai_idor  — Claude reasons over that surface -> ranked BAC/IDOR worklist (the most-
#                  rewarded class; reasoning only, the human exploits with 2 accounts).
JSINTEL_SCRIPT="${JSINTEL_SCRIPT:-$(script_path recon_jsintel.sh)}"
JSINTEL_INTERVAL="${JSINTEL_INTERVAL:-3600}"
run_jsintel() { [[ -f "$JSINTEL_SCRIPT" ]] && bash "$JSINTEL_SCRIPT" >>"$LOG_FILE" 2>&1 || true; }
AI_IDOR_SCRIPT="${AI_IDOR_SCRIPT:-$(script_path recon_ai_idor.sh)}"
AI_IDOR_INTERVAL="${AI_IDOR_INTERVAL:-3600}"
run_ai_idor() { [[ -f "$AI_IDOR_SCRIPT" ]] && bash "$AI_IDOR_SCRIPT" >>"$LOG_FILE" 2>&1 || true; }
# recon_briefing — the 6:30pm "TONIGHT" worklist (IDOR leads to test + findings to submit).
BRIEFING_SCRIPT="${BRIEFING_SCRIPT:-$(script_path recon_briefing.sh)}"
BRIEFING_INTERVAL="${BRIEFING_INTERVAL:-3600}"
run_briefing() { [[ -f "$BRIEFING_SCRIPT" ]] && bash "$BRIEFING_SCRIPT" >>"$LOG_FILE" 2>&1 || true; }
# recon_nday — n-day racing: Claude version-reasons KEV/CVE matches (kills the KEV FP) -> worklist.
NDAY_SCRIPT="${NDAY_SCRIPT:-$(script_path recon_nday.sh)}"
NDAY_INTERVAL="${NDAY_INTERVAL:-7200}"
run_nday() { [[ -f "$NDAY_SCRIPT" ]] && bash "$NDAY_SCRIPT" >>"$LOG_FILE" 2>&1 || true; }
# recon_ghleaks — GitHub-leak pillar: code-search + trufflehog verify (live secrets), token-gated.
GHLEAKS_SCRIPT="${GHLEAKS_SCRIPT:-$(script_path recon_ghleaks.sh)}"
GHLEAKS_INTERVAL="${GHLEAKS_INTERVAL:-10800}"
run_ghleaks() { [[ -f "$GHLEAKS_SCRIPT" ]] && bash "$GHLEAKS_SCRIPT" >>"$LOG_FILE" 2>&1 || true; }

# ---- Browser XSS execution-confirm (recon_xss_confirm.sh) -------------------
# Confirms reflected-XSS LEADs actually EXECUTE in headless Chromium (Playwright) —
# "detection != exploitation" for the XSS class. TARGET-FACING -> d0k (Playwright
# cache in $HOME) and VPN-gated (the loop pauses on vpn_down). Confirmed -> SQLite
# -> Claude verify -> #review. Unauthenticated, marker-only, non-destructive.
XSS_CONFIRM_SCRIPT="${XSS_CONFIRM_SCRIPT:-$(script_path recon_xss_confirm.sh)}"
XSS_CONFIRM_INTERVAL="${XSS_CONFIRM_INTERVAL:-3600}"
run_xss_confirm() { [[ -f "$XSS_CONFIRM_SCRIPT" ]] && bash "$XSS_CONFIRM_SCRIPT" >>"$LOG_FILE" 2>&1 || true; }

# ---- Param differential confirm (recon_param_confirm.sh) --------------------
# SAFE differential confirmation for SSTI / open-redirect / SQLi across the params
# catalog ({{7*7}}->49, redirect->canary, error-diff). TARGET-FACING -> d0k, VPN-gated.
# Confirmed -> SQLite -> Claude verify -> #review. Widens the reliable net w/o exploitation.
PARAM_CONFIRM_SCRIPT="${PARAM_CONFIRM_SCRIPT:-$(script_path recon_param_confirm.sh)}"
PARAM_CONFIRM_INTERVAL="${PARAM_CONFIRM_INTERVAL:-3600}"
run_param_confirm() { [[ -f "$PARAM_CONFIRM_SCRIPT" ]] && bash "$PARAM_CONFIRM_SCRIPT" >>"$LOG_FILE" 2>&1 || true; }

# ---- Stale P0/P1 re-validate (recon_restale.sh) ------------------------------
# Re-queues high-value hosts not seen in N days so they flow back through
# httpx + ES + triage. Not target-facing (only writes to inbox), runs as d0k.
RESTALE_SCRIPT="${RESTALE_SCRIPT:-$(script_path recon_restale.sh)}"
RESTALE_INTERVAL="${RESTALE_INTERVAL:-28800}"    # 8h
run_restale() { [[ -f "$RESTALE_SCRIPT" ]] && bash "$RESTALE_SCRIPT" || true; }

# ---- Playwright screenshot module (recon_screenshot.sh) ----------------------
# Target-facing (Chromium issues TCP+TLS to every host), but runs as d0k —
# Playwright cache + browser deps live in $HOME and shuffling through sudo
# every cycle is brittle. The supervise_loop VPN gate (vpn_down flag) still
# pauses this loop on egress failure, so traffic never leaves with the real IP.
# Killswitch v2_screenshot. Cooldown 24h per host.
SCREENSHOT_SCRIPT="${SCREENSHOT_SCRIPT:-$(script_path recon_screenshot.sh)}"
SCREENSHOT_INTERVAL="${SCREENSHOT_INTERVAL:-7200}"  # 2h
run_screenshot() { v21_killed screenshot && return 0; [[ -f "$SCREENSHOT_SCRIPT" ]] && bash "$SCREENSHOT_SCRIPT" cycle || true; }

# ---- VPN leak guard (v2.8) -------------------------------------------------
# Runs as d0k (NOT via run_scanner — that would self-block on its own vpn_down
# gate, and the guard must keep running while down to detect recovery). Fast
# interval = small exposure window. On leak it sets vpn_down (pausing every
# other loop) and kills all egress; on recovery it clears the flag (auto-resume).
VPNGUARD_SCRIPT="${VPNGUARD_SCRIPT:-$(script_path recon_vpnguard.sh)}"
VPNGUARD_INTERVAL="${VPNGUARD_INTERVAL:-20}"
run_vpnguard() { [[ -f "$VPNGUARD_SCRIPT" ]] && SCANNER_USER="$SCANNER_USER" bash "$VPNGUARD_SCRIPT" || true; }

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
  # VPN leak guard FIRST — it must be watching before any scanner egresses.
  supervise_loop "vpnguard"      "VPNGUARD_INTERVAL"   run_vpnguard      &

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
  # v3: broad nuclei / dast / exposure / digest auto-scans RETIRED (the evidence gate +
  # the unique pillars own confirmation now); those remain runnable on demand via recon_ctl.
  supervise_loop "active-checks"  "ACTIVE_CHECKS_INTERVAL" run_active_checks  &
  supervise_loop "js-scanner"     "JS_SCAN_INTERVAL"       run_js_scanner     &
  supervise_loop "cloudrecon"     "CLOUDRECON_INTERVAL"    run_cloudrecon     &
  supervise_loop "params"         "PARAMS_INTERVAL"        run_params         &
  supervise_loop "params-verify"  "PARAMS_VERIFY_INTERVAL" run_params_verify  &
  supervise_loop "portscan"       "PORTSCAN_INTERVAL"      run_portscan       &
  supervise_loop "bypass"         "BYPASS_INTERVAL"        run_bypass         &
  supervise_loop "ai-analyze"     "AI_ANALYZE_INTERVAL"    run_ai_analyze     &
  supervise_loop "evidence-gate"  "GATE_INTERVAL"          run_evidence_gate  &
  supervise_loop "xss-confirm"    "XSS_CONFIRM_INTERVAL"   run_xss_confirm    &
  supervise_loop "param-confirm"  "PARAM_CONFIRM_INTERVAL" run_param_confirm  &
  supervise_loop "ai-review"      "AI_REVIEW_INTERVAL"     run_ai_review      &
  supervise_loop "ai-monitor"     "AI_MONITOR_INTERVAL"    run_ai_monitor     &
  supervise_loop "jsintel"        "JSINTEL_INTERVAL"       run_jsintel        &
  supervise_loop "ai-idor"        "AI_IDOR_INTERVAL"       run_ai_idor        &
  supervise_loop "nday"           "NDAY_INTERVAL"          run_nday           &
  supervise_loop "ghleaks"        "GHLEAKS_INTERVAL"       run_ghleaks        &
  supervise_loop "briefing"       "BRIEFING_INTERVAL"      run_briefing       &
  supervise_loop "reporter"       "REPORTER_INTERVAL"      run_reporter       &
  supervise_loop "v3-digest"      "V3_DIGEST_INTERVAL"     run_v3_digest      &
  supervise_loop "restale"        "RESTALE_INTERVAL"       run_restale        &
  supervise_loop "screenshot"     "SCREENSHOT_INTERVAL"    run_screenshot     &

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
      # Bot egresses to Discord — also pause it while VPN is down.
      if [[ -f "$STATE_DIR/vpn_down" ]]; then sleep 30; continue; fi
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

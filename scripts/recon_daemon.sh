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

# ---- Token-budget overrides (optional, operator-tunable) --------------------
# A single place to pace/right-tier the Claude layer WITHOUT editing code. If
# state/token_budget.env exists it is sourced here (before every ${VAR:-default}
# interval/model default below), so its `export`s win. Absent => stock defaults.
# Reversible: `rm state/token_budget.env` + restart to revert. NOT git-mirrored
# (it lives under ~/recon/state). Template: docs/token_budget.env.example.
TOKEN_BUDGET_ENV="${TOKEN_BUDGET_ENV:-$STATE_DIR/token_budget.env}"
if [[ -f "$TOKEN_BUDGET_ENV" ]]; then
  set -a; # shellcheck disable=SC1090
  source "$TOKEN_BUDGET_ENV" 2>/dev/null || true; set +a
fi

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
    "$STATE_DIR/blindxss"
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
  # Multi-tunnel egress (opt-in: MULTITUNNEL=1). Round-robin a Mullvad gluetun proxy
  # (scripts/recon_multitunnel.sh) per invocation so target traffic spreads across N
  # exit IPs = anti-ban throughput. Localhost/ES excluded so ingest stays direct.
  # Fail-closed (gluetun FIREWALL=on) and the containers sit behind the host Mullvad,
  # so the worst case is a Mullvad IP, never the real ISP. Flag off => behaviour unchanged.
  # SMART-SCOPED: only the CONFIRM + UNIQUE lanes get the proxy pool (MT_LANES) — the commodity
  # validate/portscan bulk drain stays on the single host exit, so the scarce IPs buy findings
  # (confirm throughput on dup-proof leads), not raw fps over commodity hosts.
  local _mtlanes="${MT_LANES:-recon_params|recon_param_confirm|recon_xss_confirm|recon_domxss_confirm|recon_dast|recon_ssrf_oob|recon_kr|recon_graphql|recon_unauth_expose}"
  if [[ "${MULTITUNNEL:-0}" == "1" && "${2##*/}" =~ ^(${_mtlanes}) ]]; then
    local _mtlist="${MT_PROXY_LIST:-$STATE_DIR/egress_proxies.txt}"
    local _mtrr="${MT_RR_FILE:-$STATE_DIR/egress_rr.idx}"
    if [[ -s "$_mtlist" ]]; then
      local -a _mtp; mapfile -t _mtp < "$_mtlist"
      local _mtn="${#_mtp[@]}"
      if (( _mtn > 0 )); then
        local _mti=$(( $(cat "$_mtrr" 2>/dev/null || echo 0) % _mtn ))
        local _mtpx="${_mtp[$_mti]}"
        echo $(( _mti + 1 )) > "$_mtrr" 2>/dev/null || true
        env_args+=( HTTP_PROXY="$_mtpx" HTTPS_PROXY="$_mtpx" http_proxy="$_mtpx" https_proxy="$_mtpx" \
                    NO_PROXY="localhost,127.0.0.1,::1" no_proxy="localhost,127.0.0.1,::1" )
        log "[run_scanner] multitunnel: ${2##*/} via $_mtpx ($((_mti+1))/$_mtn)"
      fi
    fi
  fi
  local rc
  # Per-loop memory BACKSTOP (2026-06-24). The recurring WSL crash was ONE uid-996
  # jq ballooning to ~24GB (the whole 24GiB VM) -> global OOM -> daemon killed ->
  # keepalive revived it -> re-OOM: a 2-min crash loop. triage self-caps at 14GiB
  # but run_scanner — the shared launcher for every OTHER reconrun lane — had NO cap,
  # so a single unbounded jq/ES slurp could eat the whole box. ulimit -v (address
  # space, inherited by every child) makes a runaway die cleanly at the cap (ENOMEM,
  # logged under its loop name) instead of OOM-killing the VM. Tuned to keep the
  # fleet at FULL power: every Go scanner starts fine far below this (verified to
  # 4GiB) and triage's jq needs <=8GiB, so 12GiB never clips legitimate work — it
  # only catches the runaway, while leaving ~12GiB VM headroom so it is non-fatal.
  local _vmax="${SCANNER_VMAX_KB:-12582912}"   # 12 GiB; override per-lane via env if ever needed
  if [[ "$(id -un 2>/dev/null || true)" == "$SCANNER_USER" ]]; then
    ( ulimit -v "$_vmax" 2>/dev/null || true; env "${env_args[@]}" "$@" ); rc=$?
  else
    sudo -n -u "$SCANNER_USER" env "${env_args[@]}" bash -c 'ulimit -v "$1" 2>/dev/null || true; shift; exec "$@"' _ "$_vmax" "$@"; rc=$?
  fi
  _egress_release "$_eslot"
  return $rc
}

prepare_scanner_dirs

log() { printf '[%s DAEMON] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"; }

# Throttled, self-diagnosing notice for the vpn_down paused state. Reads LOCAL
# state only (vpn_status.json + the flag's own trip reason) — NO network — and
# logs WHY egress is gated plus the concrete remedy, distinguishing a CONFIRMED
# Mullvad leak (reconnect Mullvad) from an UNREACHABLE/wedged egress (restart
# WSL). Emits at most one line per VPN_DOWN_NOTICE_THROTTLE seconds, shared
# across every supervised loop via a stamp file, so the pause explains itself
# instead of N loops printing the same opaque line every 15s.
vpn_down_notice() {
  local throttle="${VPN_DOWN_NOTICE_THROTTLE:-300}"
  local stamp="$STATE_DIR/.vpn_down_notice_at" now last
  now="$(date +%s)"; last="$(cat "$stamp" 2>/dev/null || echo 0)"
  [[ "$last" =~ ^[0-9]+$ ]] || last=0
  (( now - last < throttle )) && return 0   # another loop already announced recently
  echo "$now" > "$stamp" 2>/dev/null || true
  local reason mv method remedy
  reason="$(tr -d '\n' < "$STATE_DIR/vpn_down" 2>/dev/null | cut -c1-200)"
  # NB: plain '.mullvad', NOT '.mullvad // "null"' — jq's // treats a literal
  # false like null, which would misread a real LEAK as merely unreachable.
  mv="$(jq -r '.mullvad' "$STATE_DIR/vpn_status.json" 2>/dev/null)"; [[ -n "$mv" ]] || mv=null
  method="$(jq -r '.method // "?"' "$STATE_DIR/vpn_status.json" 2>/dev/null)"; [[ -n "$method" ]] || method='?'
  case "$mv" in
    false) remedy="CONFIRMED LEAK — Mullvad egress dropped (real IP was exposed). Remedy: reconnect Mullvad on Windows; the guard auto-resumes once a Mullvad exit is reconfirmed." ;;
    true)  remedy="RECOVERING — egress now reports a Mullvad exit but the flag is still set; the guard should clear vpn_down within one check interval. If it persists, re-run the safe launcher." ;;
    *)     remedy="EGRESS UNREACHABLE (method=$method) — WSL can't reach the check endpoints; Mullvad-on-Windows may be fine. Likely a wedged WSL network stack. Remedy: 'wsl --shutdown' from Windows, then re-run the safe launcher; the guard auto-clears vpn_down once egress is reconfirmed." ;;
  esac
  log "[vpn-gate] PAUSED on vpn_down — $remedy${reason:+ | trip: $reason}"
}

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

# Multi-tunnel egress: honor the toggle flag regardless of launcher (systemd unit or
# legacy nohup) — run_scanner reads MULTITUNNEL. (cmd_start used to export this.)
[[ -f "$STATE_DIR/multitunnel_on" ]] && export MULTITUNNEL=1

# Orphan reaper (2026-06-25): we now hold the single-instance flock, so ANY other
# recon_daemon.sh process is a stale supervise-loop orphan from a prior instance that
# was SIGKILLed (WSL reap) WITHOUT running its shutdown trap. Unreaped, these pile up
# across restarts (each old instance's ~57 loops keep spawning scanners) and explode
# RAM/CPU until the VM wedges. Reap them before launching our own loops. (recon-daemon.service
# KillMode=mixed also cleans the cgroup on a clean restart; this covers a SIGKILLed predecessor.)
{ for _op in $(pgrep -f 'recon_daemon\.sh' 2>/dev/null); do [[ "$_op" == "$$" ]] || kill -KILL "$_op" 2>/dev/null; done; } || true

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
  # Stop the persistent blind-XSS OOB collector (interactsh-client; long-lived child).
  if [[ -s "$STATE_DIR/blindxss/collector.pid" ]]; then
    local bxpid; bxpid="$(cat "$STATE_DIR/blindxss/collector.pid" 2>/dev/null)"
    [[ -n "$bxpid" ]] && kill -TERM "$bxpid" 2>/dev/null || true
    rm -f "$STATE_DIR/blindxss/collector.pid"
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
  # Sweep orphaned mktemp buffers leaked into /tmp. triage.sh (+ siblings) buffer
  # multi-GB raw JSON in mktemp files freed by an EXIT trap; in this env triage is
  # SIGKILLed routinely (jq OOM + the WSL interop relay reaping the process tree on
  # the scoring CPU spike), and EXIT traps never run on SIGKILL -- so the buffers leak
  # in /tmp permanently and pile up (~36G observed 2026-06-23). Self-heal here since no
  # trap can catch SIGKILL. Safe by construction: only /tmp/tmp.* (mktemp's default
  # prefix), only owned by the pipeline's own users, only >6h old (far beyond any live
  # run), and only when no process still holds the file open (fuser). reconrun-owned
  # files need reconrun to unlink them (sticky /tmp), hence the passwordless sudo -n -u.
  local _tsweep _tsu _tswept=0 _trunas
  for _tsu in "$(id -un)" reconrun; do
    _trunas=(); [[ "$_tsu" != "$(id -un)" ]] && _trunas=(sudo -n -u "$_tsu")
    while IFS= read -r -d '' _tsweep; do
      fuser -s "$_tsweep" 2>/dev/null && continue
      "${_trunas[@]}" rm -rf -- "$_tsweep" 2>/dev/null && _tswept=$(( _tswept + 1 )) || true
    done < <("${_trunas[@]}" find /tmp -maxdepth 1 -name 'tmp.*' -user "$_tsu" -mmin +"${TMP_SWEEP_AGE_MIN:-360}" -print0 2>/dev/null)
  done
  [[ "$_tswept" -gt 0 ]] && log "auto_cleanup: swept $_tswept orphaned /tmp/tmp.* mktemp leaks (>6h, not in use)"

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

  # De-thunder (2026-06-21): spread first-iteration launches so the ~35 loops don't all
  # spawn sudo/cgroup scopes in the same second. That simultaneous burst (6 lanes + dozens
  # of transient scopes at once) is what wedged systemd user@1000 ("Failed to spawn executor:
  # Device or resource busy"), which took WSL interop + the 9P \\wsl.localhost share down with
  # it. vpnguard is EXEMPT — it must start guarding egress immediately (fail-closed).
  # See memory project_wsl_netstack_wedge_vpn_latch (the systemd-user-session root cause).
  if [[ "$name" != "vpnguard" ]]; then
    local _stagger=$(( RANDOM % ${STARTUP_STAGGER:-240} )) _ss=0
    while [[ "$_ss" -lt "$_stagger" && "$SHUTDOWN" -eq 0 ]]; do sleep 3; _ss=$((_ss+3)); done
  fi

  while [[ "$SHUTDOWN" -eq 0 ]]; do
    # VPN gate: if recon_vpnguard tripped the vpn_down flag (egress not on
    # Mullvad), EVERY loop except the guard itself pauses — no scanner or feed
    # runs until Mullvad is reconfirmed and the guard clears the flag. This is
    # what stops the pipeline from scanning over the real IP if the VPN drops.
    if [[ "$name" != "vpnguard" && -f "$STATE_DIR/vpn_down" ]]; then
      vpn_down_notice   # throttled, self-diagnosing (reason + remedy); shared across loops
      sleep 15
      continue
    fi
    load_runtime_env  # so children always see fresh env (re-checks AC/battery)
    local sleep_secs="${!sleep_var}"

    # vpnguard logs its own state changes; logging every 20s here is pure noise.
    # Scanner loops get threads/rate context; lightweight loops get nothing extra.
    case "$name" in
      validate|validate-fast|discovery|scope-watch|active-checks|js-scanner|cloudrecon|params|params-enqueue|params-verify|params-live|portscan|bypass|evidence-gate|vuln-feed)
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

    # Interruptible sleep WITH JITTER — drift loops apart so equal intervals don't
    # periodically re-align into another simultaneous burst (de-thunder, part 2).
    local _div=$(( sleep_secs / 8 )); [[ "$_div" -lt 1 ]] && _div=1
    local _target=$(( sleep_secs + (RANDOM % _div) ))
    local slept=0
    while [[ "$slept" -lt "$_target" && "$SHUTDOWN" -eq 0 ]]; do
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

# sus_params targeting catalog (jobs-and-queues, like recon_validate.sh): a PRODUCER
# (enqueue) selects in-scope-paying hosts from ES into small job files; a CONSUMER
# (crawl) claims ONE job/cycle, crawls it (katana+gau), gf-classifies, and indexes
# to recon_params + per-class files for `recon_ctl params <class>`.
PARAMS_SCRIPT="${PARAMS_SCRIPT:-$(script_path recon_params.sh)}"
PARAMS_INTERVAL="${PARAMS_INTERVAL:-120}"                  # CONSUMER: claim+crawl one job / cycle (egress-gated)
PARAMS_ENQUEUE_INTERVAL="${PARAMS_ENQUEUE_INTERVAL:-300}"  # PRODUCER: refill the job queue from ES (no target traffic)
PARAMS_VERIFY_INTERVAL="${PARAMS_VERIFY_INTERVAL:-300}"   # verify IN PARALLEL ~5min — confirmed params -> findings.db -> agent's ai-pending (verified-only reaches the agent)
PARAMS_LIVE_INTERVAL="${PARAMS_LIVE_INTERVAL:-300}"      # LIVENESS: probe catalog URLs, keep live + DELETE dead (archive URLs go stale)
# CONSUMER — target-facing (katana+gau over Mullvad) → run_scanner (egress slot + vpn gate).
run_params() { v21_killed params && return 0; [[ -f "$PARAMS_SCRIPT" ]] && run_scanner bash "$PARAMS_SCRIPT" crawl || true; }
# LIVENESS — probe catalog URLs (deduped by path), keep live, DELETE dead so only worth-
# keeping params remain + confirmers never waste budget on 404s. Target-facing → run_scanner.
run_params_live() { v21_killed params && return 0; [[ -f "$PARAMS_SCRIPT" ]] && run_scanner bash "$PARAMS_SCRIPT" verify-live || true; }
# PRODUCER — ES-only candidate selection into the queue. Still via run_scanner so the
# job files are reconrun-owned (consistent with the consumer's claim) and ES auth/env
# match; the egress slot it briefly holds for the ES query is negligible (no targets hit).
run_params_enqueue() { v21_killed params && return 0; [[ -f "$PARAMS_SCRIPT" ]] && run_scanner bash "$PARAMS_SCRIPT" enqueue || true; }
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

# NOTE: the ai-review / ai-monitor / ai-idor daemon loops were RETIRED — the 2IC routine agent
# (~/.claude scheduled routine) is now the sole Claude brain: it verifies the ai-pending queue,
# records confirmed reals into state.py, self-monitors, and owns the IDOR worklist. The daemon keeps
# only the cheap haiku ai-analyze triage (feeds the deterministic gate). recon_ai_review.sh is kept
# as a FILE for the on-demand `recon-verify` command.

# ---- Claude-Max ANALYSIS agent (recon_ai_analyze.sh) ------------------------
# Headless Claude (Haiku — bulk/cheap, match-model-to-task) reads in-scope assets,
# decides what is worth verifying + which vuln class, and flags evidence-gate
# candidates: conscious surface selection, not blanket scanning. Feeds gate -> verify.
# Runs as d0k (Claude auth per-user). Not target-facing (reasons over stored data).
AI_ANALYZE_SCRIPT="${AI_ANALYZE_SCRIPT:-$(script_path recon_ai_analyze.sh)}"
AI_ANALYZE_INTERVAL="${AI_ANALYZE_INTERVAL:-3600}"
run_ai_analyze() { [[ -f "$AI_ANALYZE_SCRIPT" ]] && bash "$AI_ANALYZE_SCRIPT" >>"$LOG_FILE" 2>&1 || true; }

# ---- Claude HUNTER agent (recon_ai_hunter.sh) — the seeded per-target hunter ----------------
# The finding engine (docs/knowledge/class-ai-hunter-design.md): Opus reasons over ONE in-scope+pays
# target's already-collected surface -> app-model + focused testable hypotheses -> the harness runs the
# unauth-safe ones via recon_safe_probe.sh -> execution-grounded adjudication -> confirmed mint (-> the
# verify gate -> #review) / 2-OWNED-ACCOUNT operator plan. Runs as d0k (Claude OAuth); the ONLY target
# traffic is safe_probe (Mullvad + scope + anti-burn gated). Authed/IDOR stays human-in-the-loop.
# Killswitch v2_ai_hunter.
AI_HUNTER_SCRIPT="${AI_HUNTER_SCRIPT:-$(script_path recon_ai_hunter.sh)}"
AI_HUNTER_INTERVAL="${AI_HUNTER_INTERVAL:-1800}"   # 30 min — deep + Opus-tier, so paced
run_ai_hunter() { v21_killed ai_hunter && return 0; [[ -f "$AI_HUNTER_SCRIPT" ]] && bash "$AI_HUNTER_SCRIPT" cycle >>"$LOG_FILE" 2>&1 || true; }

# ---- Claude-Max VISION agent (recon_ai_vision.sh) --------------------------
# Headless Claude (Haiku, vision) looks at each captured SCREENSHOT and classifies
# what is actually on screen (unauth-panel / install-setup / error-disclosure /
# login-wall / app-content / ...), surfacing the exposed-panel + misconfig money
# that metadata-only ANALYZE is blind to; worth+probeable hits become evidence-gate
# candidates (feeds verify). Token-frugal: thumb-only, haiku, TTL. Not target-facing
# (reasons over stored thumbnails). Runs as d0k (Claude auth per-user).
AI_VISION_SCRIPT="${AI_VISION_SCRIPT:-$(script_path recon_ai_vision.sh)}"
AI_VISION_INTERVAL="${AI_VISION_INTERVAL:-3600}"
run_ai_vision() { [[ -f "$AI_VISION_SCRIPT" ]] && bash "$AI_VISION_SCRIPT" >>"$LOG_FILE" 2>&1 || true; }

# ---- UNIQUE pillars (v3.7): go where the crowd doesn't ----------------------
# recon_jsintel  — mine each host's JS for the HIDDEN API surface + verify LIVE secrets
#                  (trufflehog). Target-facing -> d0k, VPN-gated. Writes endpoint feedstock.
#                  (the BAC/IDOR worklist is now owned by the 2IC routine, not a daemon loop.)
JSINTEL_SCRIPT="${JSINTEL_SCRIPT:-$(script_path recon_jsintel.sh)}"
JSINTEL_INTERVAL="${JSINTEL_INTERVAL:-3600}"
run_jsintel() { [[ -f "$JSINTEL_SCRIPT" ]] && bash "$JSINTEL_SCRIPT" >>"$LOG_FILE" 2>&1 || true; }
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
# recon_bucket_scanner — cloud-bucket exposure (S3Scanner backend). Seeds bucket names ONLY from the
# target's OWN mined surface (jsintel/params → provenance-confirmed), read-only ACL/list grading,
# public-write → db_confirm/VERIFY. Target-facing (provider frontend) → run_scanner. Killswitch: v2_buckets.
BUCKETS_SCRIPT="${BUCKETS_SCRIPT:-$(script_path recon_bucket_scanner.sh)}"
BUCKETS_INTERVAL="${BUCKETS_INTERVAL:-14400}"   # 4h (anti-burn; bounded batch + 7d re-scan cooldown)
run_buckets() { v21_killed buckets && return 0; [[ -f "$BUCKETS_SCRIPT" ]] && run_scanner bash "$BUCKETS_SCRIPT" scan || true; }
# recon_graphql — GraphQL schema → human-test worklist (the under-hunted money class). Read-only
# introspection; ranks sensitive unauth ops + IDOR/injectable args → LEADs. Target-facing → run_scanner.
GRAPHQL_SCRIPT="${GRAPHQL_SCRIPT:-$(script_path recon_graphql.sh)}"
GRAPHQL_INTERVAL="${GRAPHQL_INTERVAL:-10800}"   # 3h
run_graphql() { v21_killed graphql && return 0; [[ -f "$GRAPHQL_SCRIPT" ]] && run_scanner bash "$GRAPHQL_SCRIPT" scan || true; }
# ---------------------------------------------------------------------------------------
# CHAIN-TO-IMPACT lanes (2026-08-17). Discovery is not a finding — each of these takes a
# lane that used to mint an observation and carries it through to recovered credentials or
# confirmed unauthenticated access. Each mints ONLY on demonstrated impact; a properly
# secured target is recorded as a negative and never minted. See CLAUDE.md.
#
# recon_feed — mines ES for what each impact lane needs (the lanes were starved: the bucket
# lane read a 162k-row endpoint file and found 11 buckets, ES holds 2.8M docs; the actuator
# lane had ZERO candidates because its fingerprints live in headers, not JS paths).
# Read-only against our OWN index — issues no target traffic → d0k. Killswitch: v2_feed.
FEED_SCRIPT="${FEED_SCRIPT:-$(script_path recon_feed.py)}"
FEED_INTERVAL="${FEED_INTERVAL:-21600}"          # 6h — cheap, keeps every lane supplied
run_feed() { v21_killed feed && return 0; [[ -f "$FEED_SCRIPT" ]] && \
  python3 "$FEED_SCRIPT" >>"$LOG_FILE" 2>&1 || true; }

# recon_actuator_chain — exposed actuator → /env + /configprops + streamed /heapdump →
# ACTUALLY recovered credentials. Read-only endpoints only (never /shutdown, /restart,
# /jolokia). Target-facing → run_scanner. Killswitch: v2_actchain.
ACTCHAIN_SCRIPT="${ACTCHAIN_SCRIPT:-$(script_path recon_actuator_chain.py)}"
ACTCHAIN_INTERVAL="${ACTCHAIN_INTERVAL:-28800}"  # 8h
run_actchain() { v21_killed actchain && return 0
  local f="$STATE_DIR/feed_actuator.txt"
  [[ -f "$ACTCHAIN_SCRIPT" && -s "$f" ]] || return 0
  run_scanner python3 "$ACTCHAIN_SCRIPT" $(head -60 "$f" | tr '\n' ' ') || true; }

# recon_port_proto — open port → SPEAK THE PROTOCOL → confirm unauthenticated access.
# Replaces "port 6379 is open" (96 findings, 0 real) with "no-AUTH Redis, N keys".
# Read-only verbs; no records read. CDN-fronted hosts excluded by the feed.
PORTPROTO_SCRIPT="${PORTPROTO_SCRIPT:-$(script_path recon_port_proto.py)}"
PORTPROTO_INTERVAL="${PORTPROTO_INTERVAL:-21600}"  # 6h
run_portproto() { v21_killed portproto && return 0
  local f="$STATE_DIR/feed_ports.txt"
  [[ -f "$PORTPROTO_SCRIPT" && -s "$f" ]] || return 0
  run_scanner python3 "$PORTPROTO_SCRIPT" $(head -60 "$f" | tr '\n' ' ') || true; }

# recon_graphql_chain — introspection → a sensitive query with NO required args → EXECUTE ONE
# read-only query. "Introspection enabled" alone is the #1 GraphQL duplicate; the finding is
# the data returned. Queries only, never a mutation, never an invented identifier.
GQLCHAIN_SCRIPT="${GQLCHAIN_SCRIPT:-$(script_path recon_graphql_chain.py)}"
GQLCHAIN_INTERVAL="${GQLCHAIN_INTERVAL:-28800}"  # 8h
run_gqlchain() { v21_killed gqlchain && return 0
  local f="$STATE_DIR/feed_graphql.txt"
  [[ -f "$GQLCHAIN_SCRIPT" && -s "$f" ]] || return 0
  run_scanner python3 "$GQLCHAIN_SCRIPT" $(head -40 "$f" | tr '\n' ' ') || true; }

# recon_wcd — web-cache deception/poisoning LEAD surfacer (detect-only, cache-busted = never poisons
# the real cache). CDN-fronted in-scope hosts only. Target-facing → run_scanner. Killswitch: v2_wcd.
WCD_SCRIPT="${WCD_SCRIPT:-$(script_path recon_wcd.sh)}"
WCD_INTERVAL="${WCD_INTERVAL:-21600}"           # 6h (heavier per-host probe set)
run_wcd() { v21_killed wcd && return 0; [[ -f "$WCD_SCRIPT" ]] && run_scanner bash "$WCD_SCRIPT" scan || true; }
# recon_research — standing Claude RESEARCH routine (tooling/vulns/kb/detect-tune) that keeps the
# system UPDATED. Web research (Anthropic→web, NOT target traffic) → runs as d0k, no run_scanner/vpn
# gate. Auto-commits dated digests + brand-NEW KB; edits to existing KB → review proposals. The script
# self-serializes (flock) so the 4 topics never run Claude concurrently. Killswitch: state/kill/v2_research.
RESEARCH_SCRIPT="${RESEARCH_SCRIPT:-$(script_path recon_research.sh)}"
RESEARCH_VULNS_INTERVAL="${RESEARCH_VULNS_INTERVAL:-86400}"        # daily
RESEARCH_TOOLING_INTERVAL="${RESEARCH_TOOLING_INTERVAL:-604800}"   # weekly
RESEARCH_KB_INTERVAL="${RESEARCH_KB_INTERVAL:-604800}"             # weekly
RESEARCH_DETECT_INTERVAL="${RESEARCH_DETECT_INTERVAL:-604800}"     # weekly
run_research_vulns()   { v21_killed research && return 0; [[ -f "$RESEARCH_SCRIPT" ]] && bash "$RESEARCH_SCRIPT" vulns       >>"$LOG_FILE" 2>&1 || true; }
run_research_tooling() { v21_killed research && return 0; [[ -f "$RESEARCH_SCRIPT" ]] && bash "$RESEARCH_SCRIPT" tooling     >>"$LOG_FILE" 2>&1 || true; }
run_research_kb()      { v21_killed research && return 0; [[ -f "$RESEARCH_SCRIPT" ]] && bash "$RESEARCH_SCRIPT" kb-enrich   >>"$LOG_FILE" 2>&1 || true; }
run_research_detect()  { v21_killed research && return 0; [[ -f "$RESEARCH_SCRIPT" ]] && bash "$RESEARCH_SCRIPT" detect-tune >>"$LOG_FILE" 2>&1 || true; }
# recon_targets — Under-Hunted Target Board: the selection layer at the mouth of the funnel.
# Scores every bug-bounty PROGRAM by Under-Hunted EV (freshness + low-saturation dominate, payout
# capped = anti-dup) → ranked menu (briefings/targets_<date>.md) + auto-onboards the top N into the
# validator queue. Pure data (no target traffic) → runs as d0k. Killswitch: state/kill/v2_targets.
TARGETS_SCRIPT="${TARGETS_SCRIPT:-$(script_path recon_targets.sh)}"
TARGETS_INTERVAL="${TARGETS_INTERVAL:-86400}"        # daily
run_targets() { v21_killed targets && return 0; [[ -f "$TARGETS_SCRIPT" ]] && bash "$TARGETS_SCRIPT" score >>"$LOG_FILE" 2>&1 || true; }
# recon_dangling_dns — dangling-NS subdomain takeover (audit #10b; the 2025 Hazy-Hawk class the
# CNAME-only takeover hunter misses). DNS-only (queries public resolvers about the zone, never the
# target) -> runs as d0k, not run_scanner. Killswitch: state/kill/v2_dangling_dns.
DANGLING_DNS_SCRIPT="${DANGLING_DNS_SCRIPT:-$(script_path recon_dangling_dns.sh)}"
DANGLING_DNS_INTERVAL="${DANGLING_DNS_INTERVAL:-21600}"   # 6h
run_dangling_dns() { v21_killed dangling_dns && return 0; [[ -f "$DANGLING_DNS_SCRIPT" ]] && bash "$DANGLING_DNS_SCRIPT" >>"$LOG_FILE" 2>&1 || true; }
# recon_permute — permutation-DNS lane: alterx generate → puredns resolve (PUBLIC resolvers) → NEW in-scope
# hosts → validator queue. PUBLIC-resolver DNS = NOT target traffic → runs as d0k (the supervise_loop vpn
# gate still pauses it on vpn_down). Bounded + sliding-window. Killswitch: state/kill/v2_permute.
PERMUTE_SCRIPT="${PERMUTE_SCRIPT:-$(script_path recon_permute.sh)}"
PERMUTE_INTERVAL="${PERMUTE_INTERVAL:-3600}"   # 1h — 25 seeds/cycle slides through the in-scope pool
run_permute() { v21_killed permute && return 0; [[ -f "$PERMUTE_SCRIPT" ]] && bash "$PERMUTE_SCRIPT" >>"$LOG_FILE" 2>&1 || true; }
# recon_uncover — surface expansion via uncover (Shodan/Censys dorks scoped to in-scope certs/roots) →
# puredns resolve → NEW in-scope hosts → validator queue. CREDIT-CONSERVATIVE: hard monthly Shodan budget
# (the operator's quota is scarce). 3rd-party API + public DNS = NOT target traffic → d0k (vpn-gated by the
# loop). The monthly budget is the real cap; 6h cadence. Killswitch: state/kill/v2_uncover.
UNCOVER_SCRIPT="${UNCOVER_SCRIPT:-$(script_path recon_uncover.sh)}"
UNCOVER_INTERVAL="${UNCOVER_INTERVAL:-21600}"   # 6h (budget guard is the real limiter)
run_uncover() { v21_killed uncover && return 0; [[ -f "$UNCOVER_SCRIPT" ]] && bash "$UNCOVER_SCRIPT" cycle >>"$LOG_FILE" 2>&1 || true; }
# recon_baddns — takeover-lane augmenter (BadDNS, ADOPT 2026-07-01): SECOND-ORDER takeover (embedded
# 3rd-party domains in HTML) + NSEC/CNAME/NS/TXT/WILDCARD. references module fetches target HTML → the
# script self-gates fail-closed on vpn_down. LEAD-only (never auto-mints a confirmed takeover).
# Killswitch: state/kill/v2_baddns.
BADDNS_SCRIPT="${BADDNS_SCRIPT:-$(script_path recon_baddns.sh)}"
BADDNS_INTERVAL="${BADDNS_INTERVAL:-14400}"   # 4h — 20 hosts/cycle slides through the in-scope pool
run_baddns() { v21_killed baddns && return 0; [[ -f "$BADDNS_SCRIPT" ]] && bash "$BADDNS_SCRIPT" >>"$LOG_FILE" 2>&1 || true; }
# recon_unauth_expose — U1 lane: shadow-endpoint UNAUTHENTICATED data-exposure confirmer.
# jsintel endpoints -> recon_safe_probe GET -> precision classifier -> state.py record-confirmed
# -> ai-pending -> 2IC verify -> SUBMIT. Target-facing -> run_scanner (reconrun, egress slot +
# vpn gate). Killswitch: state/kill/v2_unauth_expose. See docs/knowledge/class-unauth-hunting.md U1.
UNAUTH_EXPOSE_SCRIPT="${UNAUTH_EXPOSE_SCRIPT:-$(script_path recon_unauth_expose.sh)}"
UNAUTH_EXPOSE_INTERVAL="${UNAUTH_EXPOSE_INTERVAL:-3600}"
run_unauth_expose() { v21_killed unauth_expose && return 0; [[ -f "$UNAUTH_EXPOSE_SCRIPT" ]] && run_scanner bash "$UNAUTH_EXPOSE_SCRIPT" || true; }
# recon_ssrf_oob — U4 lane: UNAUTH SSRF discovery, OOB-confirmed (interactsh). Injects a unique
# canary per sink via recon_safe_probe (GET, in-scope, benign OUR-canary only) -> a callback =
# CONFIRMED SSRF -> state.py record-confirmed (signal_class=ssrf-oob) -> 2IC verify -> DIG (operator
# escalates; never autonomous). Target-facing -> run_scanner. Killswitch: state/kill/v2_ssrf_oob.
SSRF_OOB_SCRIPT="${SSRF_OOB_SCRIPT:-$(script_path recon_ssrf_oob.sh)}"
SSRF_OOB_INTERVAL="${SSRF_OOB_INTERVAL:-7200}"   # 2h (each cycle holds a short interactsh session)
run_ssrf_oob() { v21_killed ssrf_oob && return 0; [[ -f "$SSRF_OOB_SCRIPT" ]] && run_scanner bash "$SSRF_OOB_SCRIPT" || true; }
# recon_domxss_confirm — U6 DOM-XSS lane: dalfox --deep-domxss --force-headless-verification on XSS
# catalog candidates; a [POC] = headless-verified EXECUTION -> record-confirmed (signal_class=dom-xss)
# -> 2IC verify -> SUBMIT. Headless is heavy -> small batch, 2h. Target-facing -> run_scanner.
# Killswitch: state/kill/v2_domxss. See docs/knowledge/class-unauth-hunting.md U6.
DOMXSS_SCRIPT="${DOMXSS_SCRIPT:-$(script_path recon_domxss_confirm.sh)}"
DOMXSS_INTERVAL="${DOMXSS_INTERVAL:-7200}"   # 2h
run_domxss() { v21_killed domxss && return 0; [[ -f "$DOMXSS_SCRIPT" ]] && run_scanner bash "$DOMXSS_SCRIPT" || true; }
# recon_kr — kiterunner API-route discovery on in-scope 200-hosts that expose no crawlable paths (bare API
# gateways). Brute-discovers routes from the assetnote apiroutes wordlist → endpoints feedstock (IDOR ranker).
# Target-facing → run_scanner (reconrun, Mullvad + egress slot). Heavy → small batch + 14d cooldown. Killswitch v2_kr.
KR_SCRIPT="${KR_SCRIPT:-$(script_path recon_kr.sh)}"
KR_INTERVAL="${KR_INTERVAL:-7200}"   # 2h
run_kr() { v21_killed kr && return 0; [[ -f "$KR_SCRIPT" ]] && run_scanner bash "$KR_SCRIPT" || true; }
# recon_exposed_files — audit fix #9: actively probe high-signal exposed paths (.git/.env/Spring
# actuator/swagger) with CONTENT-SIGNATURE confirms -> record-confirmed -> 2IC -> SUBMIT. The
# classic exposed surface U1 (JS-route mining) never actively checked. Target-facing -> run_scanner.
# Killswitch: state/kill/v2_exposed_files. See docs/detection_verification_audit_2026-06-17.md.
EXPOSED_FILES_SCRIPT="${EXPOSED_FILES_SCRIPT:-$(script_path recon_exposed_files.sh)}"
EXPOSED_FILES_INTERVAL="${EXPOSED_FILES_INTERVAL:-3600}"   # 1h
run_exposed_files() { v21_killed exposed_files && return 0; [[ -f "$EXPOSED_FILES_SCRIPT" ]] && run_scanner bash "$EXPOSED_FILES_SCRIPT" || true; }

# ---- Cognito unauth-cred lane (recon_cognito_nighthunt.sh) -------------------
# Walks in-scope+paying hosts sorted newest-first (first_seen desc) harvesting
# Amplify config / root main-JS for Cognito pool IDs, tests unauth issuance, and
# blast-radius assesses issuers. Pings #review ONLY on a REAL finding (issued creds
# with a role that actually reaches resources). RUM/zero-perm/OOS-carveout pools are
# auto-suppressed as FP. Target-facing (curl to hosts) -> run_scanner (Mullvad gate).
# Short interval so new hosts are picked up quickly. Killswitch: state/kill/v2_cognito.
COGNITO_SCRIPT="${COGNITO_SCRIPT:-$(script_path recon_cognito_nighthunt.sh)}"
COGNITO_INTERVAL="${COGNITO_INTERVAL:-300}"   # 5m — cycle is fast; new hosts surface quickly
run_cognito() { v21_killed cognito && return 0; [[ -f "$COGNITO_SCRIPT" ]] && run_scanner bash "$COGNITO_SCRIPT" || true; }

# ---- BLIND / STORED-XSS lane (recon_blindxss.sh + DAST blind-plant) ----------
# The #1 unused dalfox feature, made into a real lane. THREE pieces:
#  (1) collector  — a PERSISTENT interactsh-client (long-lived child like gungnir; d0k,
#      NOT target-facing, NOT vpn-gated so it keeps catching late fires even when paused).
#      Launched in the long-running section below (restart loop). Killswitch: v2_blindxss.
#  (2) blind-plant — recon_dast.sh in DAST_BLIND_ONLY mode: crawls fresh-first in-scope
#      paying hosts and plants a per-host crafted canary + dual-beacon payload into params
#      (no nuclei / no reflected #vulns spam). Target-facing -> run_scanner. Killswitch: v2_dast.
#  (3) correlate  — maps a delayed callback -> the injected host -> a CONFIRMED stored-XSS
#      finding (gated: state.py -> 2IC verify -> #review). Writes findings.db -> run via
#      run_scanner (reconrun) for db ownership, like ssrf-oob/domxss/reporter. Killswitch: v2_blindxss.
BLINDXSS_SCRIPT="${BLINDXSS_SCRIPT:-$(script_path recon_blindxss.sh)}"
DAST_SCRIPT="${DAST_SCRIPT:-$(script_path recon_dast.sh)}"
BLINDXSS_PLANT_INTERVAL="${BLINDXSS_PLANT_INTERVAL:-10800}"   # 3h — plant on fresh hosts (polite)
BLINDXSS_CORRELATE_INTERVAL="${BLINDXSS_CORRELATE_INTERVAL:-300}"  # 5m — map fires fast
run_blindxss_plant() {
  v21_killed blindxss && return 0
  v21_killed dast && return 0
  [[ -f "$DAST_SCRIPT" ]] || return 0
  DAST_BLIND_ONLY=1 run_scanner bash "$DAST_SCRIPT" || true
}
run_blindxss_correlate() {
  v21_killed blindxss && return 0
  [[ -f "$BLINDXSS_SCRIPT" ]] && run_scanner bash "$BLINDXSS_SCRIPT" correlate || true
}
# collector restart-loop (long-running; relaunched if it dies). d0k, not run_scanner.
run_blindxss_collector() { [[ -f "$BLINDXSS_SCRIPT" ]] && bash "$BLINDXSS_SCRIPT" collector || true; }

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

# ---- recon-audit self-audit (recon_selfaudit.sh) -----------------------------
# Low-frequency standing self-audit. DRY-RUN ONLY from the daemon — it never passes
# --apply (whitelist remediation stays an operator action). Not target-facing (reads
# ES/SQLite/state, writes the report + selfaudit_latest.json + a cooled-down #ops
# summary). Runs as d0k. The supervise_loop VPN gate already skips it while vpn_down
# is set, so a paused pipeline doesn't churn audits.
SELFAUDIT_SCRIPT="${SELFAUDIT_SCRIPT:-$(script_path recon_selfaudit.sh)}"
SELFAUDIT_INTERVAL="${SELFAUDIT_INTERVAL:-21600}"  # 6h
run_selfaudit() { [[ -f "$SELFAUDIT_SCRIPT" ]] && bash "$SELFAUDIT_SCRIPT" >>"$LOG_FILE" 2>&1 || true; }

# ---- nuclei template refresh (audit fix: the evidence gate ran -duc with NO -update-templates
# anywhere = a FROZEN template set, missing every monthly FP-fix + new CVE). Refresh out-of-band
# (weekly); the gate keeps -duc at probe time for speed. Not target-facing (fetches from GitHub),
# runs as d0k; the supervise_loop vpn gate skips it while vpn_down (harmless to defer). ----
# RELIABILITY (2026-08-18): `nuclei -update-templates` reported "No new updates found" while the
# template set sat at 2026-03-02 — FIVE AND A HALF MONTHS stale, missing 438 CVE detections
# (293 of them 2026 CVEs). The binary was v3.7.1 against a current v3.11.1 and its version check
# had settled on a template release it considered latest. With `-silent ... || true` the failure
# was indistinguishable from success, so nothing ever alarmed.
#
# So: pull from git DIRECTLY (authoritative — a commit either arrives or it does not), then
# ASSERT THE OUTCOME. Never trust an updater's own report of its success.
NUCLEI_UPDATE_INTERVAL="${NUCLEI_UPDATE_INTERVAL:-86400}"    # daily — CVE detections age fast
NUCLEI_TEMPLATES_DIR="${NUCLEI_TEMPLATES_DIR:-$HOME/nuclei-templates}"
NUCLEI_MAX_STALE_DAYS="${NUCLEI_MAX_STALE_DAYS:-3}"
run_nuclei_update() {
  local d="$NUCLEI_TEMPLATES_DIR"
  [[ -d "$d/.git" ]] || { command -v nuclei >/dev/null 2>&1 && nuclei -update-templates -silent >>"$LOG_FILE" 2>&1; return 0; }
  ( cd "$d" || exit 0
    # local churn (TEMPLATES-STATS.json etc.) blocks a ff-only pull; park it, never merge it
    git stash push -u -m "daemon-autostash-$(date +%s)" >/dev/null 2>&1 || true
    timeout 600 git pull --ff-only origin main >>"$LOG_FILE" 2>&1 ||       timeout 600 git pull --ff-only origin master >>"$LOG_FILE" 2>&1 || true
    git stash drop >/dev/null 2>&1 || true ) || true

  # ASSERT: is the template set actually current? A stale detection set is a silent
  # capability outage — every CVE published since the freeze is invisible to us.
  local last_epoch age_days
  last_epoch="$( cd "$d" 2>/dev/null && git log -1 --format=%ct 2>/dev/null )" || last_epoch=""
  if [[ -n "$last_epoch" ]]; then
    age_days=$(( ( $(date +%s) - last_epoch ) / 86400 ))
    if (( age_days > NUCLEI_MAX_STALE_DAYS )); then
      log "ALARM nuclei-templates ${age_days}d stale (max ${NUCLEI_MAX_STALE_DAYS}d) — CVE detection coverage is FROZEN"
      discord_post ops "⚠️ nuclei-templates **${age_days} days stale** — every CVE disclosed since then has no detection. \`cd $d && git pull\`" 2>/dev/null || true
    else
      log "nuclei-templates current (${age_days}d old, $(find "$d" -name '*.yaml' 2>/dev/null | wc -l) templates)"
    fi
  fi
}

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
  supervise_loop "params-enqueue" "PARAMS_ENQUEUE_INTERVAL" run_params_enqueue &
  supervise_loop "params"         "PARAMS_INTERVAL"        run_params         &
  supervise_loop "params-verify"  "PARAMS_VERIFY_INTERVAL" run_params_verify  &
  supervise_loop "params-live"    "PARAMS_LIVE_INTERVAL"   run_params_live    &
  supervise_loop "portscan"       "PORTSCAN_INTERVAL"      run_portscan       &
  supervise_loop "bypass"         "BYPASS_INTERVAL"        run_bypass         &
  supervise_loop "ai-analyze"     "AI_ANALYZE_INTERVAL"    run_ai_analyze     &
  supervise_loop "ai-hunter"      "AI_HUNTER_INTERVAL"     run_ai_hunter      &
  supervise_loop "ai-vision"      "AI_VISION_INTERVAL"     run_ai_vision      &
  supervise_loop "evidence-gate"  "GATE_INTERVAL"          run_evidence_gate  &
  supervise_loop "xss-confirm"    "XSS_CONFIRM_INTERVAL"   run_xss_confirm    &
  supervise_loop "param-confirm"  "PARAM_CONFIRM_INTERVAL" run_param_confirm  &
  supervise_loop "jsintel"        "JSINTEL_INTERVAL"       run_jsintel        &
  supervise_loop "nday"           "NDAY_INTERVAL"          run_nday           &
  supervise_loop "ghleaks"        "GHLEAKS_INTERVAL"       run_ghleaks        &
  supervise_loop "buckets"        "BUCKETS_INTERVAL"       run_buckets        &
  supervise_loop "graphql"        "GRAPHQL_INTERVAL"       run_graphql        &
  supervise_loop "wcd"            "WCD_INTERVAL"           run_wcd            &
  # chain-to-impact lanes — feed first so the others always have fresh targets
  supervise_loop "feed"           "FEED_INTERVAL"          run_feed           &
  supervise_loop "actchain"       "ACTCHAIN_INTERVAL"      run_actchain       &
  supervise_loop "portproto"      "PORTPROTO_INTERVAL"     run_portproto      &
  supervise_loop "gqlchain"       "GQLCHAIN_INTERVAL"      run_gqlchain       &
  supervise_loop "research-vulns"   "RESEARCH_VULNS_INTERVAL"   run_research_vulns   &
  supervise_loop "research-tooling" "RESEARCH_TOOLING_INTERVAL" run_research_tooling &
  supervise_loop "research-kb"      "RESEARCH_KB_INTERVAL"      run_research_kb      &
  supervise_loop "research-detect"  "RESEARCH_DETECT_INTERVAL"  run_research_detect  &
  supervise_loop "targets"          "TARGETS_INTERVAL"          run_targets          &
  supervise_loop "dangling-dns"   "DANGLING_DNS_INTERVAL"  run_dangling_dns   &
  supervise_loop "permute"        "PERMUTE_INTERVAL"       run_permute        &
  supervise_loop "uncover"        "UNCOVER_INTERVAL"       run_uncover        &
  supervise_loop "baddns"         "BADDNS_INTERVAL"        run_baddns         &
  supervise_loop "unauth-expose"  "UNAUTH_EXPOSE_INTERVAL" run_unauth_expose  &
  supervise_loop "ssrf-oob"       "SSRF_OOB_INTERVAL"      run_ssrf_oob       &
  supervise_loop "domxss-confirm" "DOMXSS_INTERVAL"        run_domxss         &
  supervise_loop "kr"             "KR_INTERVAL"            run_kr             &
  supervise_loop "exposed-files"  "EXPOSED_FILES_INTERVAL" run_exposed_files  &
  supervise_loop "cognito"        "COGNITO_INTERVAL"       run_cognito        &
  supervise_loop "blindxss-plant"     "BLINDXSS_PLANT_INTERVAL"     run_blindxss_plant     &
  supervise_loop "blindxss-correlate" "BLINDXSS_CORRELATE_INTERVAL" run_blindxss_correlate &
  supervise_loop "briefing"       "BRIEFING_INTERVAL"      run_briefing       &
  supervise_loop "reporter"       "REPORTER_INTERVAL"      run_reporter       &
  supervise_loop "v3-digest"      "V3_DIGEST_INTERVAL"     run_v3_digest      &
  supervise_loop "restale"        "RESTALE_INTERVAL"       run_restale        &
  supervise_loop "screenshot"     "SCREENSHOT_INTERVAL"    run_screenshot     &
  supervise_loop "self-audit"     "SELFAUDIT_INTERVAL"     run_selfaudit      &
  supervise_loop "nuclei-update"  "NUCLEI_UPDATE_INTERVAL" run_nuclei_update  &

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
  (
    # Persistent blind-XSS OOB collector (interactsh-client). Long-lived like the gungnir
    # CT listener: it MUST keep polling to catch fires that land hours/days after a plant,
    # so it is NOT vpn-gated and runs even while scanning is paused. Relaunch if it dies.
    # Killswitch v2_blindxss stops it (and frees the registered correlation id on restart).
    while [[ "$SHUTDOWN" -eq 0 ]]; do
      if [[ -f "$STATE_DIR/kill/v2_blindxss" ]]; then sleep 60; continue; fi
      run_blindxss_collector || log "[blindxss-collector] exited, restarting in 30s"
      sleep 30
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

#!/usr/bin/env bash
# =============================================================================
# recon_ctl.sh — single CLI for the whole pipeline
# =============================================================================
set -uo pipefail

BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="$BASE_DIR/state"
QUEUE_DIR="$BASE_DIR/queue"
FB_DIR="$BASE_DIR/firstblood"
LOG_DIR="$BASE_DIR/logs"
TRIAGE_DIR="$BASE_DIR/triage"
VULN_DIR="$BASE_DIR/vuln"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

script_path() { printf '%s\n' "$SCRIPT_DIR/$1"; }

# permanent host-notes layer (note_add/note_get/note_has) — see recon_notes.sh
source "$SCRIPT_DIR/recon_notes.sh" 2>/dev/null || true

first_matching_or_nonblank() {
  local pattern="${1:?pattern}"
  local input
  input="$(cat)"
  printf '%s\n' "$input" | grep -m1 -E "$pattern" 2>/dev/null && return 0
  printf '%s\n' "$input" | sed '/^[[:space:]]*$/d' | head -1
}

DAEMON="${DAEMON:-$(script_path recon_daemon.sh)}"
PID_FILE="$STATE_DIR/recon_daemon.pid"

ES_URL="${ES_URL:-http://127.0.0.1:9200}"
INDEX_NAME="${INDEX_NAME:-recon_alive}"
ES_USER="${ES_USER:-elastic}"
ES_PASS="${ES_PASS:-$(tr -d '[:space:]' < "$HOME/.recon_es_pass" 2>/dev/null || true)}"
# write netrc so ES password stays off curl command line
if [[ -f "$HOME/.recon_es_pass" ]]; then
  _netrc_ep="$(tr -d '[:space:]' < "$HOME/.recon_es_pass" 2>/dev/null || true)"
  [[ -n "$_netrc_ep" ]] && { ( printf 'machine 127.0.0.1\nlogin elastic\npassword %s\n' "$_netrc_ep" > "$HOME/.recon_es_netrc" ) 2>/dev/null && chmod 600 "$HOME/.recon_es_netrc" && { command -v setfacl >/dev/null 2>&1 && setfacl -m u:reconrun:r "$HOME/.recon_es_netrc" 2>/dev/null || true; }; }
  unset _netrc_ep
fi

mkdir -p "$STATE_DIR"

c() { printf '\033[%sm%s\033[0m' "$1" "$2"; }
hdr() { printf '\n\033[1;36m== %s ==\033[0m\n' "$1"; }

# ---------------------------------------------------------------------------
# ES helpers — used by all viewer commands
# ---------------------------------------------------------------------------
_es_search() {
  # _es_search <json_body> — returns raw ES response JSON
  curl -sS -m30 --netrc-file "$HOME/.recon_es_netrc" \
    -H 'Content-Type: application/json' \
    -X POST "$ES_URL/$INDEX_NAME/_search" \
    -d "$1" 2>/dev/null
}

_es_count_q() {
  # _es_count_q <query_json> — returns integer count
  curl -sS -m10 --netrc-file "$HOME/.recon_es_netrc" \
    -H 'Content-Type: application/json' \
    -X POST "$ES_URL/$INDEX_NAME/_count" \
    -d "{\"query\":$1}" 2>/dev/null | jq -r '.count // 0' 2>/dev/null
}

new_archive_root() {
  local prefix="$1" ts
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  printf '%s\n' "$BASE_DIR/archive/${prefix}_${ts}"
}

archive_matching() {
  local archive_root="$1" rel_dir="$2"; shift 2
  local src_dir="$BASE_DIR/$rel_dir" dest_dir="$archive_root/$rel_dir"
  [[ -d "$src_dir" ]] || return 0
  mkdir -p "$dest_dir"
  local moved=0 pattern f
  shopt -s nullglob
  for pattern in "$@"; do
    for f in "$src_dir"/$pattern; do
      [[ -e "$f" ]] || continue
      mv "$f" "$dest_dir/" 2>/dev/null && moved=$((moved + 1))
    done
  done
  shopt -u nullglob
  [[ "$moved" -gt 0 ]] && printf '  archived %-24s %s item(s)\n' "$rel_dir" "$moved"
}

archive_old_files() {
  local archive_root="$1" src_dir="$2" older_mins="$3"
  [[ -d "$src_dir" ]] || return 0
  local moved=0 f rel dest_dir
  while IFS= read -r -d '' f; do
    rel="${f#$BASE_DIR/}"
    dest_dir="$archive_root/$(dirname "$rel")"
    mkdir -p "$dest_dir"
    mv "$f" "$dest_dir/" 2>/dev/null && moved=$((moved + 1))
  done < <(find "$src_dir" -type f -mmin +"$older_mins" -print0 2>/dev/null)
  [[ "$moved" -gt 0 ]] && printf '  archived stale files from %s: %s\n' "${src_dir#$BASE_DIR/}" "$moved"
}

seed_seen_files() {
  mkdir -p "$TRIAGE_DIR" "$BASE_DIR/nuclei"

  local triage_seen="$TRIAGE_DIR/.seen_high.txt"
  touch "$triage_seen" 2>/dev/null || true
  if [[ -s "$TRIAGE_DIR/agent_targets.jsonl" && -w "$triage_seen" ]]; then
    jq -r '
      select(.priority == "P0" or .priority == "P1") |
      [
        (.host // ""),
        ((.vuln_classes // []) | sort | join(",")),
        (.kev_signal // ""),
        ([(.kev_cves // [])[].id] | sort | join(","))
      ] | join("|")
    ' "$TRIAGE_DIR/agent_targets.jsonl" 2>/dev/null >> "$triage_seen" || true
    sort -u "$triage_seen" -o "$triage_seen" 2>/dev/null || true
  fi

  local nuclei_seen="$BASE_DIR/nuclei/.confirmed_seen"
  touch "$nuclei_seen" 2>/dev/null || true
  if [[ -s "$BASE_DIR/nuclei/confirmed.jsonl" && -w "$nuclei_seen" ]]; then
    jq -r '[.host // "", ."template-id" // ""] | @tsv' "$BASE_DIR/nuclei/confirmed.jsonl" 2>/dev/null \
      | awk -F'\t' '$1 != "" && $2 != "" {print $1 "|" $2}' >> "$nuclei_seen" || true
    sort -u "$nuclei_seen" -o "$nuclei_seen" 2>/dev/null || true
  fi
}

cmd_maintenance() {
  # Maintenance lock: when set, cmd_start AND the daemon refuse to launch (fail-
  # closed). Use during rebuilds/upgrades so nothing target-facing starts.
  local sub="${1:-status}" lock="$STATE_DIR/maintenance"
  case "$sub" in
    on|set|enable)
      mkdir -p "$STATE_DIR"
      printf 'maintenance lock set %s\nreason: %s\n' \
        "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "${2:-manual rebuild/upgrade}" > "$lock"
      echo "Maintenance lock ON — pipeline will refuse to start until cleared."
      echo "  lock: $lock"
      ;;
    off|clear|disable)
      if [[ -f "$lock" ]]; then rm -f "$lock"; echo "Maintenance lock OFF — pipeline may start again."; else echo "No maintenance lock was set."; fi
      ;;
    status|"")
      if [[ -f "$lock" ]]; then echo "Maintenance lock: ON"; sed 's/^/  /' "$lock" 2>/dev/null; else echo "Maintenance lock: off"; fi
      ;;
    *) echo "Usage: recon-ctl maintenance {on [reason]|off|status}" ;;
  esac
}

cmd_start() {
  unlink "$STATE_DIR/daemon_disabled" 2>/dev/null || true   # re-enable keepalive auto-restart
  rm -f "$STATE_DIR/keepalive_tripped" "$STATE_DIR/keepalive_restarts.log" 2>/dev/null || true   # reset crash-loop breaker
  # Maintenance lock (fail-closed): refuse to start while the pipeline is being
  # rebuilt/upgraded. Clear with `recon-ctl maintenance off` (or rm the file).
  if [[ -f "$STATE_DIR/maintenance" ]]; then
    echo "REFUSING to start: maintenance lock is set ($STATE_DIR/maintenance)."
    [[ -s "$STATE_DIR/maintenance" ]] && sed 's/^/  /' "$STATE_DIR/maintenance"
    echo "  Clear with: recon-ctl maintenance off"
    return 1
  fi
  # --- systemd-supervised path (the cure, 2026-06-25) ----------------------------
  # If recon-daemon.service is installed, delegate to systemd: bounded restarts
  # (StartLimitBurst) + cgroup MemoryMax + clean cgroup kills. This replaces the
  # fragile nohup+shell-keepalive launcher whose unbounded re-spawn churn overloaded
  # the WSL VM into Wsl/Service/E_UNEXPECTED. Falls through to the legacy launcher
  # only if the unit is not installed (tools/install_recon_daemon_service.sh).
  if [[ -f /etc/systemd/system/recon-daemon.service ]]; then
    if systemctl is-active --quiet recon-daemon.service 2>/dev/null; then
      echo "Daemon already running (systemd: recon-daemon.service)"; return 0
    fi
    if [[ "${RECON_SKIP_VPN_CHECK:-0}" != "1" ]]; then
      STATE_DIR="$STATE_DIR" bash "$SCRIPT_DIR/recon_vpn_check.sh" >/dev/null 2>&1
      case "$?" in
        0) echo "VPN OK — Mullvad egress confirmed." ;;
        1) echo "REFUSING to start: egress is a LEAK (not a Mullvad exit). Reconnect Mullvad."; return 1 ;;
        *) echo "REFUSING to start: could not CONFIRM Mullvad egress. Override: RECON_SKIP_VPN_CHECK=1 recon-start"; return 1 ;;
      esac
    fi
    [[ -f "$STATE_DIR/multitunnel_on" ]] && echo "multitunnel: ON (daemon reads the flag)"
    sudo -n systemctl reset-failed recon-daemon.service 2>/dev/null || true
    if sudo -n systemctl start recon-daemon.service 2>/dev/null; then
      sleep 1
      echo "Started (systemd: recon-daemon.service). Watch: journalctl -u recon-daemon -f"
      return 0
    fi
    echo "Could not start via systemd without a password. Run: sudo systemctl start recon-daemon"
    echo "(or install passwordless control: sudo bash tools/install_recon_daemon_service.sh)"
    return 1
  fi
  # --- legacy nohup launcher (only if the systemd unit is not installed) ----------
  if [[ -s "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "Daemon already running (pid $(cat "$PID_FILE"))"; return
  fi
  if [[ "${RECON_SKIP_PREFLIGHT:-0}" != "1" ]]; then
    if [[ -x /usr/local/sbin/recon-safe-preflight ]]; then
      echo "Running secure preflight"
      sudo -n /usr/local/sbin/recon-safe-preflight || {
        echo "Preflight failed; refusing to start target-facing recon."
        return 1
      }
    elif [[ "${RECON_REQUIRE_PREFLIGHT:-1}" == "1" ]]; then
      echo "Secure preflight is not installed; refusing to start target-facing recon."
      echo "Use tools/start_recon_safe.sh after installing /usr/local/sbin/recon-safe-preflight."
      return 1
    fi
  fi
  # VPN gate at launch (fail-closed): the WSL2 preflight does NOT verify the
  # tunnel, so confirm egress is a Mullvad exit before starting any target-facing
  # recon. recon_vpnguard then keeps watching during the run.
  if [[ "${RECON_SKIP_VPN_CHECK:-0}" != "1" ]]; then
    # Single cached multi-method egress check — does NOT hammer am.i.mullvad (local known-IP cache;
    # am.i.mullvad only on a NEW exit IP; org/ASN fallback when it's down). See recon_vpn_check.sh.
    STATE_DIR="$STATE_DIR" bash "$SCRIPT_DIR/recon_vpn_check.sh" >/dev/null 2>&1
    case "$?" in
      0) echo "VPN OK — Mullvad egress confirmed." ;;
      1) echo "REFUSING to start: egress is a LEAK (not a Mullvad exit). Reconnect Mullvad."; return 1 ;;
      *) echo "REFUSING to start: could not CONFIRM Mullvad egress (verification endpoints unreachable — NOT proof of a leak)."
         echo "  Verify your exit IP, then override: RECON_SKIP_VPN_CHECK=1 recon-start"; return 1 ;;
    esac
  fi
  # Multi-tunnel egress opt-in (scripts/recon_multitunnel.sh on|off). When the toggle file
  # exists, the daemon's run_scanner round-robins target traffic across the gluetun Mullvad
  # proxy pool (state/egress_proxies.txt). Persists across restarts; absent => single-exit.
  [[ -f "$STATE_DIR/multitunnel_on" ]] && { export MULTITUNNEL=1; echo "multitunnel: ON (egress via gluetun proxy pool)"; }
  nohup bash "$DAEMON" >/dev/null 2>&1 &
  sleep 1
  if [[ -s "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "Started (pid $(cat "$PID_FILE"))"
  else
    echo "Failed to start. Check $LOG_DIR/recon_daemon.log"; return 1
  fi
}

cmd_stop() {
  mkdir -p "$STATE_DIR" 2>/dev/null || true; touch "$STATE_DIR/daemon_disabled" 2>/dev/null || true   # tell keepalive: deliberate stop, do not auto-restart
  # Stop the systemd-supervised daemon cleanly first (a clean stop does NOT trigger
  # Restart=on-failure). The pkill sweep below still runs as belt-and-suspenders.
  if [[ -f /etc/systemd/system/recon-daemon.service ]]; then
    sudo -n systemctl stop recon-daemon.service 2>/dev/null || systemctl stop recon-daemon.service 2>/dev/null || true
  fi
  # Bulletproof full stop. NEVER gate the kill logic on the pidfile: if the
  # master died/was-killed without a clean trap, its supervise_loop subshells
  # orphan to PID 1 (showing as `bash recon_daemon.sh`) and keep firing
  # scanners. The old code printed "Not running" and killed nothing in that case.
  local su="${SCANNER_USER:-reconrun}"
  echo "Stopping recon pipeline (full)..."

  # 1) Graceful TERM the master (if pidfile valid) so its EXIT trap can clean up.
  local pid=""
  [[ -s "$PID_FILE" ]] && pid="$(cat "$PID_FILE" 2>/dev/null)"
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    echo "  graceful TERM master pid $pid"
    kill -TERM "$pid" 2>/dev/null || true
    for i in $(seq 1 8); do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
  fi
  rm -f "$PID_FILE"

  # 2) ALWAYS kill the daemon tree (master + orphaned supervise loops) + every
  #    module loop + the discord bot. d0k-owned, so plain pkill works here.
  local DAEMON_PAT='recon_daemon\.sh'
  local LOOP_PAT='recon_(validate|discovery|hot_seed|scope_watch|takeover_hunter|discord_bot|scope_db|cve_intel|vuln_feed|nuclei|true_fresh|fresh_modules|cloudrecon|dast|params|vpnguard|brain|ai_analyze|ai_vision|ai_hunter|jsintel|nday|ghleaks|briefing|evidence_gate|xss_confirm|param_confirm|portscan|bypass|restale|digest|screenshot|blindxss|permute|kr|uncover)\.sh'
  pkill -TERM -f "$DAEMON_PAT" 2>/dev/null || true
  pkill -TERM -f "$LOOP_PAT"   2>/dev/null || true
  pkill -TERM -f 'triage\.sh'  2>/dev/null || true

  # 3) gungnir CT listener (setsid process group)
  if [[ -s "$BASE_DIR/state/true_fresh/gungnir.pid" ]]; then
    local gpid; gpid="$(cat "$BASE_DIR/state/true_fresh/gungnir.pid" 2>/dev/null)"
    [[ -n "$gpid" ]] && { kill -TERM -- "-$gpid" 2>/dev/null || kill -TERM "$gpid" 2>/dev/null || true; }
    rm -f "$BASE_DIR/state/true_fresh/gungnir.pid"
  fi
  pkill -TERM -f 'gungnir -r' 2>/dev/null || true

  # 4) reconrun-owned scanners + tools. recon_ctl runs as d0k and CANNOT signal
  #    reconrun procs directly — but the passwordless `sudo -u reconrun` rule
  #    lets us kill them AS reconrun. Without this, in-flight target-facing
  #    scanners (httpx/nuclei/katana/...) survive a stop and keep sending traffic.
  local TOOL_PAT='httpx|nuclei|katana|caduceus|dalfox|subfinder|assetfinder|dnsx|\bgau\b'
  sudo -n -u "$su" pkill -TERM -f "recon_|triage\.sh|$TOOL_PAT" 2>/dev/null || true
  pkill -TERM -f "$TOOL_PAT" 2>/dev/null || true

  # 5) Grace, then force-kill stragglers (both users).
  sleep 3
  pkill -KILL -f "$DAEMON_PAT" 2>/dev/null || true
  pkill -KILL -f "$LOOP_PAT"   2>/dev/null || true
  pkill -KILL -f 'triage\.sh|gungnir -r' 2>/dev/null || true
  pkill -KILL -f "$TOOL_PAT"   2>/dev/null || true
  sudo -n -u "$su" pkill -KILL -f "recon_|triage\.sh|$TOOL_PAT" 2>/dev/null || true

  # 6) Verify (exclude this recon_ctl process itself).
  sleep 1
  local left dleft
  left="$(pgrep -af "recon_daemon|$LOOP_PAT|gungnir|triage\.sh|$TOOL_PAT" 2>/dev/null | grep -vE 'recon_ctl|grep' | wc -l | tr -d ' ')"
  dleft="$(ps -eo stat 2>/dev/null | grep -c '^D')"
  if [[ "$left" -eq 0 ]]; then
    echo "Stopped — all recon processes terminated."
  else
    echo "WARNING: $left recon process(es) still present:"
    pgrep -af "recon_daemon|$LOOP_PAT|gungnir|triage\.sh|$TOOL_PAT" 2>/dev/null | grep -vE 'recon_ctl|grep' | head
    [[ "$dleft" -gt 0 ]] && echo "  ($dleft in uninterruptible D-state — only 'wsl --shutdown' clears those)"
  fi
}

cmd_status() {
  hdr "Daemon"
  if [[ -s "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    local pid; pid="$(cat "$PID_FILE")"
    local etime; etime="$(ps -o etime= -p "$pid" 2>/dev/null | tr -d ' ')"
    echo "Running (pid $pid, uptime $etime)"
    if command -v acpi >/dev/null 2>&1; then
      if acpi -a 2>/dev/null | grep -qi 'off-line'; then
        echo "Power: battery (auto-throttled to 50% concurrency)"
      else
        echo "Power: AC"
      fi
    fi
    echo "Children:"
    pgrep -af 'recon_(validate|discovery|hot_seed|scope_watch|takeover_hunter)\.sh' 2>/dev/null \
      | awk '{printf "  pid=%s %s %s\n",$1,$2,$3}' || true
  else
    echo "Stopped"
  fi
  cmd_queue
  hdr "ES health"
  if [[ -n "$ES_PASS" ]]; then
    curl -fsS -m 5 --netrc-file "$HOME/.recon_es_netrc" "$ES_URL/_cluster/health" 2>/dev/null \
      | jq -r '"  status=\(.status) nodes=\(.number_of_nodes) docs?\(.active_primary_shards) shards"' || echo "  ES unreachable"
    local count; count="$(curl -fsS -m 5 --netrc-file "$HOME/.recon_es_netrc" "$ES_URL/$INDEX_NAME/_count" 2>/dev/null | jq -r '.count // "?"')"
    echo "  $INDEX_NAME doc count: $count"
    local params_count; params_count="$(curl -fsS -m 5 --netrc-file "$HOME/.recon_es_netrc" "$ES_URL/recon_params/_count" 2>/dev/null | jq -r '.count // "?"')"
    echo "  recon_params doc count: $params_count"
  else
    echo "  ES_PASS not set"
  fi
  hdr "First-blood files"
  echo "  CLAIM: $(wc -l < "$FB_DIR/takeovers_to_claim.tsv" 2>/dev/null || echo 0) entries  → $FB_DIR/takeovers_to_claim.tsv"
  echo "  WATCH: $(wc -l < "$FB_DIR/takeovers_watching.tsv" 2>/dev/null || echo 0) entries  → $FB_DIR/takeovers_watching.tsv"
  hdr "Memory"
  free -h | head -2 | tail -1 | awk '{printf "  total=%s used=%s free=%s available=%s\n",$2,$3,$4,$7}'
}

# ---------------------------------------------------------------------------
# Rate control — live calibration without daemon restart.
# Writes ~/recon/state/rate_override; daemon reads it each iteration (~30s lag).
# ---------------------------------------------------------------------------
_rate_write() {
  local t="$1" r="$2" label="$3"
  printf 'THREADS=%s\nRATE=%s\n' "$t" "$r" > "$STATE_DIR/rate_override"
  printf '  rate → %s: %st / %s rps\n' "$label" "$t" "$r"
  # Kill running httpx processes immediately so validate.sh restarts them at
  # the new rate on the next batch. Batches in-flight return to inbox for retry
  # — nothing is lost. Without this, old httpx runs finish at the old rate
  # (up to ~6 min per validate cycle).
  local httpx_pids n=0
  httpx_pids="$(pgrep -x httpx 2>/dev/null || true)"
  if [[ -n "$httpx_pids" ]]; then
    n="$(printf '%s\n' "$httpx_pids" | wc -l | tr -d ' ')"
    printf '%s\n' "$httpx_pids" | xargs kill -TERM 2>/dev/null || true
    printf '  killed %s httpx worker(s) — next validate batch uses new rate\n' "$n"
  else
    printf '  no httpx running — new rate applies on next validate cycle\n'
  fi
}

cmd_rate() {
  local arg1="${1:-}" arg2="${2:-}"
  case "$arg1" in
    ""|show|status)
      hdr "Rate"
      local t r label source
      if [[ -f "$STATE_DIR/rate_override" ]]; then
        t="$(grep '^THREADS=' "$STATE_DIR/rate_override" 2>/dev/null | cut -d= -f2 | tr -d '[:space:]')"
        r="$(grep '^RATE='   "$STATE_DIR/rate_override" 2>/dev/null | cut -d= -f2 | tr -d '[:space:]')"
        source="override"
      else
        t=150; r=100; source="daemon default"
      fi
      case "${t}/${r}" in
        30/20)   label="light"  ;;
        60/40)   label="easy"   ;;
        100/65)  label="medium" ;;
        150/100) label="full"   ;;
        *)       label="custom" ;;
      esac
      # Power source + daemon thread budget from most recent daemon log line
      local power daemon_threads
      power="$(grep -oE 'power=[a-z]+' "$LOG_DIR/recon_daemon.log" 2>/dev/null | tail -1 | cut -d= -f2)"
      daemon_threads="$(grep -oE '\(power=[a-z]+ threads=[0-9]+\)' "$LOG_DIR/recon_daemon.log" 2>/dev/null | tail -1 | grep -oE 'threads=[0-9]+' | cut -d= -f2)"
      # Actual httpx rate from most recent validate run
      local last_val
      last_val="$(grep 'VAL\].*threads=[0-9].*rate=[0-9]' "$LOG_DIR/recon_daemon.log" 2>/dev/null | tail -1 | grep -oE 'threads=[0-9]+ rate=[0-9]+')"
      # Live httpx worker count (pgrep -c exits 1 with no matches, so capture separately)
      local httpx_n; httpx_n="$(pgrep -x httpx 2>/dev/null | wc -l | tr -d '[:space:]')"

      printf '  %-20s %st / %s rps  [%s]  (source: %s)\n' \
        "effective rate:" "$t" "$r" "$label" "$source"
      printf '  %-20s %s  (daemon thread budget: %s)\n' \
        "power:" "${power:-unknown}" "${daemon_threads:--}"
      [[ -n "$last_val" ]] && \
        printf '  %-20s %s\n' "last httpx run:" "$last_val"
      if [[ "$httpx_n" -gt 0 ]]; then
        printf '  %-20s %s instance(s) active\n' "live httpx:" "$httpx_n"
      else
        printf '  %-20s none\n' "live httpx:"
      fi
      printf '\n'
      printf '  presets : light=30t/20rps  easy=60t/40rps  medium=100t/65rps  full=150t/100rps\n'
      printf '  set     : recon-rate <preset>  or  recon-rate <threads> <rps>\n'
      printf '  reset   : recon-rate reset\n'
      ;;
    reset|off|default)
      rm -f "$STATE_DIR/rate_override"
      printf '  rate override cleared — daemon default (150t/100rps) on next cycle\n'
      local httpx_pids n=0
      httpx_pids="$(pgrep -x httpx 2>/dev/null || true)"
      if [[ -n "$httpx_pids" ]]; then
        n="$(printf '%s\n' "$httpx_pids" | wc -l | tr -d ' ')"
        printf '%s\n' "$httpx_pids" | xargs kill -TERM 2>/dev/null || true
        printf '  killed %s httpx worker(s) — next batch runs at daemon default\n' "$n"
      fi
      ;;
    light)  _rate_write 30  20  "light"  ;;
    easy)   _rate_write 60  40  "easy"   ;;
    medium) _rate_write 100 65  "medium" ;;
    full)   _rate_write 150 100 "full"   ;;
    [0-9]*)
      [[ "$arg2" =~ ^[0-9]+$ ]]              || { printf 'usage: recon-rate <threads> <rps>\n' >&2; return 1; }
      [[ "$arg1" -ge 1 && "$arg1" -le 500 ]] || { printf 'threads must be 1-500\n' >&2; return 1; }
      [[ "$arg2" -ge 1 && "$arg2" -le 500 ]] || { printf 'rps must be 1-500\n' >&2; return 1; }
      _rate_write "$arg1" "$arg2" "custom"
      ;;
    *)
      printf 'usage: recon-rate [light|easy|medium|full|reset|<threads> <rps>]\n' >&2
      return 1
      ;;
  esac
}

cmd_queue() {
  hdr "Queue"
  local inbox proc done_p done_t
  inbox="$(find "$QUEUE_DIR/inbox" -maxdepth 1 -name '*.txt' 2>/dev/null | wc -l | tr -d ' ')"
  proc="$(find "$QUEUE_DIR/processing" -maxdepth 1 -name '*.txt' 2>/dev/null | wc -l | tr -d ' ')"
  done_t="$(find "$QUEUE_DIR/done" -maxdepth 1 -name '*.txt.processed' 2>/dev/null | wc -l | tr -d ' ')"
  done_p="$(find "$QUEUE_DIR/done" -maxdepth 1 -name '*.jsonl' 2>/dev/null | wc -l | tr -d ' ')"
  echo "  inbox: $inbox"
  echo "  processing: $proc"
  echo "  done (httpx jsonl recent): $done_p"
  echo "  done (batches archived): $done_t"
  if [[ "$inbox" -gt 0 ]]; then
    echo "  next 5:"
    find "$QUEUE_DIR/inbox" -maxdepth 1 -name '*.txt' 2>/dev/null | sort | head -5 | sed 's/^/    /'
  fi
}

cmd_logs() {
  local log="$LOG_DIR/recon_daemon.log"
  if [[ ! -f "$log" ]]; then
    echo "(no log at $log)"
    return
  fi
  # Print last 50 lines then follow — Ctrl-C to exit
  printf '\033[1;36m== recon_daemon.log — live  (Ctrl-C to exit) ==\033[0m\n'
  tail -n 50 -f "$log"
}

cmd_top() {
  local n="${1:-15}"
  hdr "Top $n triage targets (from ES)"
  local resp
  resp="$(_es_search "{
    \"size\": $n,
    \"_source\": [\"host\",\"triage_priority\",\"triage_score\",\"triage_payout_tier\",
                  \"triage_program\",\"triage_classes\",\"triage_true_fresh\",
                  \"triage_kev_match\",\"js_secret_hit\",\"js_endpoint_hit\"],
    \"query\": {\"bool\":{
      \"filter\": [{\"exists\":{\"field\":\"triage_score\"}}],
      \"must_not\": [{\"term\":{\"triage_ignored\":true}}]
    }},
    \"sort\": [{\"triage_score\":{\"order\":\"desc\",\"missing\":\"_last\"}}]
  }")"
  local total; total="$(printf '%s' "$resp" | jq -r '.hits.total.value // 0' 2>/dev/null)"
  [[ "$total" -eq 0 ]] && { echo "  (no triaged targets in ES yet)"; return; }
  printf '%-2s %-3s %-4s %-7s %-52s %-22s %s\n' "FL" "PRI" "SCR" "TIER" "HOST" "PROGRAM" "CLASSES"
  printf '%s\n' "$(printf '─%.0s' {1..136})"
  printf '%s' "$resp" | jq -r '
    .hits.hits[]._source |
    [
      (if (.triage_true_fresh // false) then "⚡"
       elif (.triage_kev_match // false) then "🎯"
       elif (.js_secret_hit // false) then "🔑"
       else " " end),
      (.triage_priority // "?"),
      ((.triage_score // 0) | tostring),
      (.triage_payout_tier // "-"),
      (.host // "?"),
      (.triage_program // "-"),
      ((.triage_classes // []) | map(select(. != "low-priority" and . != "low-signal")) | join(","))
    ] | @tsv' 2>/dev/null \
  | while IFS=$'\t' read -r fl pri scr tier host prog cls; do
      printf '%-2s %-3s %-4s %-7s %-52s %-22s %s\n' \
        "$fl" "$pri" "$scr" "$tier" "${host:0:52}" "${prog:0:22}" "$cls"
    done
  echo
  printf "  showing: %s  |  total scored in ES: %s\n" "$n" "$total"
}

cmd_takeovers() {
  local n="${1:-60}"
  local B='\033[1m' R='\033[0m' C='\033[1;36m' G='\033[0;32m' Y='\033[1;33m' BOLD='\033[1m'
  hdr "Takeovers — CLAIM list"

  # ── Section 1: ES-confirmed takeovers (tagged by takeover_hunter) ──────────
  local resp
  resp="$(_es_search "{
    \"size\": $n,
    \"_source\": [\"host\",\"triage_priority\",\"triage_score\",\"triage_payout_tier\",
                  \"triage_program\",\"triage_pays\",\"takeover_service\",
                  \"takeover_cname\",\"takeover_confidence\",\"takeover_payout\",
                  \"takeover_detected_at\"],
    \"query\": {\"term\": {\"takeover_confirmed\": true}},
    \"sort\": [{\"takeover_detected_at\": {\"order\": \"desc\"}}]
  }")"
  local es_count; es_count="$(jq -r '.hits.total.value // 0' <<< "$resp" 2>/dev/null)"

  if [[ "${es_count:-0}" -gt 0 ]]; then
    printf '\n  %bES-confirmed takeovers%b (%s)  — these have program + payout context\n\n' \
      "$BOLD" "$R" "$es_count"
    printf '  %-44s %-12s %-16s %-8s %-6s %s\n' \
      "HOST" "CONFIDENCE" "SERVICE" "PAYOUT" "PAYS" "PROGRAM"
    printf '  %s\n' "$(printf '─%.0s' {1..115})"
    jq -r '.hits.hits[]._source |
      [.host,
       (.takeover_confidence // "?"),
       (.takeover_service // "?"),
       (.takeover_payout // "?"),
       (if .triage_pays == true then "💰" else "" end),
       (.triage_program // "-")] | @tsv' <<< "$resp" 2>/dev/null \
    | while IFS=$'\t' read -r host conf svc payout pays prog; do
        local col="$R"
        case "$conf" in CRITICAL) col='\033[1;31m' ;; HIGH) col="$G" ;; MEDIUM-HIGH) col="$Y" ;; esac
        printf "  ${col}%-44s${R} %-12s %-16s %-8s %-6s %s\n" \
          "$host" "$conf" "$svc" "$payout" "$pays" "$prog"
      done
    echo
  fi

  # ── Section 2: Raw CLAIM file, deduplicated by CNAME target ──────────────
  local claim_f="$FB_DIR/takeovers_to_claim.tsv"
  if [[ ! -s "$claim_f" ]]; then
    [[ "${es_count:-0}" -eq 0 ]] && echo "  No takeover candidates yet — pipeline still scanning."
    printf '  tip: recon-takeover-check <host>   — manual probe of any host\n\n'
    return
  fi

  local total_claims; total_claims="$(wc -l < "$claim_f" | tr -d ' ')"
  local unique_cnames; unique_cnames="$(awk -F'\t' '{print $4}' "$claim_f" 2>/dev/null | sort -u | grep -c .)"

  printf '  %bClaim file%b: %s entries → %b%s unique CNAME targets%b (each = one real opportunity)\n\n' \
    "$BOLD" "$R" "$total_claims" "$G" "$unique_cnames" "$R"
  printf '  %-48s %-16s %-12s %-6s  %s\n' \
    "CNAME TARGET" "SERVICE" "CONF" "HOSTS" "EXAMPLE HOST"
  printf '  %s\n' "$(printf '─%.0s' {1..115})"

  awk -F'\t' '{print $4}' "$claim_f" 2>/dev/null | sort -u | while IFS= read -r cname_target; do
    [[ -z "$cname_target" ]] && continue
    local host_count svc conf example diff
    host_count="$(grep -cF "$cname_target" "$claim_f" 2>/dev/null || echo 0)"
    svc="$(grep -F "$cname_target" "$claim_f" 2>/dev/null | head -1 | awk -F'\t' '{print $3}')"
    conf="$(grep -F "$cname_target" "$claim_f" 2>/dev/null | head -1 | awk -F'\t' '{print $5}')"
    diff="$(grep -F "$cname_target" "$claim_f" 2>/dev/null | head -1 | awk -F'\t' '{print $7}')"
    example="$(grep -F "$cname_target" "$claim_f" 2>/dev/null | head -1 | awk -F'\t' '{print $2}')"
    local col="$R"
    case "$conf" in CRITICAL) col='\033[1;31m' ;; HIGH) col="$G" ;; MEDIUM-HIGH) col="$Y" ;; esac
    local diff_icon=""
    [[ "$diff" == "easy" ]] && diff_icon="⚡"
    printf "  ${col}%-48s${R} %-16s %-12s %-6s  %s%s\n" \
      "$cname_target" "$svc" "$conf" "$host_count" "$diff_icon" "$example"
  done
  echo
  printf '  %b⚡ easy%b = claim in minutes | no icon = medium/hard | one CNAME target = one opportunity\n' "$G" "$R"
  printf '  tip: recon-takeover-check <host>      — manual re-probe any specific host\n'
  printf '  tip: recon-submit <host> takeover     — log as submitted\n\n'
}

cmd_watching() {
  hdr "Takeovers — WATCH list (medium confidence, periodic recheck every 15 min)"
  local f="$FB_DIR/takeovers_watching.tsv"
  if [[ ! -s "$f" ]]; then
    echo "  Watch list empty — nothing pending recheck."
    return
  fi

  local total; total="$(wc -l < "$f" | tr -d ' ')"
  local now_epoch; now_epoch="$(date +%s)"

  # Summary by provider
  printf '  %s entries in watch queue\n\n' "$total"
  printf '  %-22s %s\n' "PROVIDER" "COUNT"
  printf '  %-22s %s\n' "──────────────────────" "─────"
  awk -F'\t' '{print $3}' "$f" | sort | uniq -c | sort -rn | \
    while read -r cnt svc; do
      printf '  %-22s %s\n' "$svc" "$cnt"
    done
  echo

  # Recent entries sorted newest first
  printf '  %-40s %-16s %-12s %-8s %s\n' "HOST" "SERVICE" "CONF" "AGE" "CNAME TARGET"
  printf '  %s\n' "$(printf '─%.0s' {1..110})"
  sort -t$'\t' -k1,1r "$f" | head -30 | \
    while IFS=$'\t' read -r ts host svc cname conf rest; do
      local entry_epoch age_str
      entry_epoch="$(date -d "$ts" +%s 2>/dev/null || echo 0)"
      local age_sec=$(( now_epoch - entry_epoch ))
      if   (( age_sec < 3600 ));  then age_str="${age_sec}s"
      elif (( age_sec < 86400 )); then age_str="$((age_sec/3600))h"
      else                             age_str="$((age_sec/86400))d"
      fi
      printf '  %-40s %-16s %-12s %-8s %s\n' "$host" "$svc" "$conf" "$age_str" "$cname"
    done
  echo
  printf '  Recheck runs every 15 min automatically. Manual: recon-takeover-check <host>\n\n'
}

cmd_takeover_check() {
  local host="${1:?usage: recon-takeover-check <host>}"
  hdr "Manual takeover probe: $host"
  bash "$(script_path recon_takeover_hunter.sh)" check "$host"
}

cmd_dupes() {
  local pattern="${1:-}"
  hdr "Submission history"
  local f="$HOME/.recon_submissions.jsonl"
  [[ -f "$f" ]] || { echo "No submissions file at $f"; return; }
  if [[ -z "$pattern" ]]; then
    jq -r '[.submitted_date,.host,.vuln_class,.status] | @tsv' "$f" | column -t -s $'\t'
  else
    jq -r --arg p "$pattern" 'select(.host|test($p)) | [.submitted_date,.host,.vuln_class,.status] | @tsv' "$f" \
      | column -t -s $'\t'
  fi
}

cmd_submit() {
  local host="${1:?host}" cls="${2:?vuln_class}" status="${3:-pending}"
  local f="$HOME/.recon_submissions.jsonl"
  local root; root="$(echo "$host" | awk -F. '{print $(NF-1)"."$NF}')"
  jq -nc --arg h "$host" --arg r "$root" --arg c "$cls" --arg s "$status" \
    --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{host:$h, root_domain:$r, vuln_class:$c, status:$s, submitted_date:$ts}' >> "$f"
  echo "Logged: $host [$cls] $status"
}

cmd_health() {
  hdr "Health check"
  command -v httpx >/dev/null 2>&1 && echo "  httpx: $(httpx -version 2>&1 | first_matching_or_nonblank 'Current Version|[Vv]ersion')" || echo "  httpx: MISSING"
  command -v subfinder >/dev/null 2>&1 && echo "  subfinder: $(subfinder -version 2>&1 | first_matching_or_nonblank 'Current Version|[Vv]ersion')" || echo "  subfinder: MISSING"
  command -v assetfinder >/dev/null 2>&1 && echo "  assetfinder: present" || echo "  assetfinder: missing"
  command -v jq >/dev/null 2>&1 && echo "  jq: $(jq --version)" || echo "  jq: MISSING"
  command -v dig >/dev/null 2>&1 && echo "  dig: present" || echo "  dig: MISSING"
  command -v docker >/dev/null 2>&1 && echo "  docker: $(docker --version | head -1)" || echo "  docker: missing (ok if ES via systemd)"
  echo
  hdr "Worker duplication"
  local name pattern count
  for item in \
    "validate:recon_validate.sh" \
    "discovery:recon_discovery.sh" \
    "scope-watch:recon_scope_watch.sh" \
    "takeover-watch:recon_takeover_hunter.sh watch" \
    "true-fresh:recon_true_fresh.sh" \
    "hot-seed:recon_hot_seed.sh" \
    "vpnguard:recon_vpnguard.sh" \
    "nuclei:recon_nuclei.sh" \
    "vuln-feed:recon_vuln_feed.sh" \
    "cloudrecon:recon_cloudrecon.sh" \
    "dast:recon_dast.sh" \
    "params:recon_params.sh" \
    "blindxss-collector:recon_blindxss.sh collector" \
    "discord-bot:recon_discord_bot.sh"; do
    name="${item%%:*}"
    pattern="${item#*:}"
    count="$(ps -eo pid=,ppid=,user=,args= 2>/dev/null \
      | awk -v pat="$pattern" '
          $0 ~ pat &&
          $0 !~ /sudo -n -u/ &&
          $0 !~ /timeout --kill-after/ &&
          $0 !~ /pgrep -af/ &&
          $0 !~ /awk -v pat/ {
            pids[$1]=1
            ppids[$1]=$2
          }
          END {
            for (pid in pids) {
              if (!(ppids[pid] in pids)) n++
            }
            print n+0
          }
        ')"
    if [[ "${count:-0}" -gt 1 ]]; then
      echo "  WARN $name duplicate workers: $count"
    else
      echo "  OK   $name workers: $count"
    fi
  done
  echo
  cmd_status
}

cmd_space() {
  hdr "Disk usage"
  for d in "$BASE_DIR" "$BASE_DIR/queue" "$BASE_DIR/cache" "$BASE_DIR/logs" "$BASE_DIR/spool" "$BASE_DIR/firstblood" "$BASE_DIR/triage" "$BASE_DIR/state"; do
    [[ -d "$d" ]] && du -sh "$d" 2>/dev/null
  done
  echo
  df -h "$BASE_DIR" 2>/dev/null | tail -1 | awk '{printf "Filesystem: %s used, %s avail (%s)\n", $3, $4, $5}'
}

cmd_clean() {
  hdr "Cleanup"
  local archive_root
  archive_root="$(new_archive_root stale_cleanup)"
  mkdir -p "$archive_root"
  echo "Archiving sent spool >7d"
  archive_old_files "$archive_root" "$BASE_DIR/spool/sent" 10080
  echo "Archiving done/ files >24h"
  archive_old_files "$archive_root" "$BASE_DIR/queue/done" 1440
  echo "Archive: $archive_root"
  echo "Done"
  cmd_space
}

cmd_clean_start() {
  local arg="${1:-}"
  hdr "Clean start"
  if [[ "$arg" != "--yes" && "$arg" != "yes" ]]; then
    cat <<EOF
This archives stale active views without deleting useful data:
  - queue/done httpx outputs and processed batch markers
  - active triage target/report files
  - nuclei run result folders and active confirmed.jsonl
  - current log files

It preserves scope/CVE databases, submissions, known/alive host state, false-positive lists, and seen/dedup files.
Stop the daemon first, then run:
  recon_ctl clean-start --yes
EOF
    return 0
  fi

  if [[ -s "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "Daemon is running. Stop it first with: recon_ctl stop"
    return 1
  fi

  seed_seen_files

  local archive_root
  archive_root="$(new_archive_root clean_start)"
  mkdir -p "$archive_root"

  archive_matching "$archive_root" "queue/done" "*.jsonl" "*.txt.processed"
  archive_matching "$archive_root" "triage" "agent_targets.jsonl" "report_*.md"
  archive_matching "$archive_root" "nuclei" "confirmed.jsonl"
  archive_matching "$archive_root" "nuclei/results" "run_*"
  archive_matching "$archive_root" "logs" "*.log"

  mkdir -p "$QUEUE_DIR/inbox" "$QUEUE_DIR/processing" "$QUEUE_DIR/done" \
           "$BASE_DIR/spool/pending" "$BASE_DIR/spool/sent" "$BASE_DIR/spool/failed" \
           "$TRIAGE_DIR" "$BASE_DIR/nuclei/results"

  echo "Clean active views ready."
  echo "Archive: $archive_root"
  cmd_space
}

cmd_reset_queue() {
  hdr "Reset queue (CONFIRM)"
  read -r -p "This will archive inbox/processing/done and clear the active queue. Type yes to continue: " ans
  [[ "$ans" == "yes" ]] || { echo "Aborted"; return; }
  local archive_root
  archive_root="$(new_archive_root queue_reset)"
  mkdir -p "$archive_root"
  archive_matching "$archive_root" "queue/inbox" "*.txt"
  archive_matching "$archive_root" "queue/processing" "*.txt"
  archive_matching "$archive_root" "queue/done" "*.txt.processed" "*.jsonl"
  echo "Queue cleared; archive: $archive_root"
}


V21_SCOPE_CHECK="$(script_path recon_scope_check.sh)"
V21_KILL_DIR="$HOME/recon/state/kill"

cmd_kev() {
  hdr "KEV-matched targets (from ES)"
  local resp
  resp="$(_es_search '{
    "size": 50,
    "_source": ["host","triage_priority","triage_score","triage_payout_tier",
                "triage_program","triage_kev_signal","triage_kev_cves","triage_true_fresh","triage_pays"],
    "query": {"term":{"triage_kev_match":true}},
    "sort": [{"triage_score":{"order":"desc","missing":"_last"}}]
  }')"
  local total; total="$(printf '%s' "$resp" | jq -r '.hits.total.value // 0' 2>/dev/null)"
  if [[ "$total" -eq 0 ]]; then echo "  none yet"; return; fi
  printf '%-3s %-4s %-7s %-52s %-22s %s\n' "PRI" "SCR" "TIER" "HOST" "PROGRAM" "KEV_SIGNAL"
  printf '%s\n' "$(printf '─%.0s' {1..130})"
  printf '%s' "$resp" | jq -r '
    .hits.hits[]._source |
    [
      (.triage_priority // "-"),
      ((.triage_score // 0) | tostring),
      (.triage_payout_tier // "-"),
      (.host // ""),
      (.triage_program // "-"),
      (.triage_kev_signal // ((.triage_kev_cves // []) | join(",")))
    ] | @tsv' 2>/dev/null \
  | while IFS=$'\t' read -r pri scr tier host prog sig; do
      printf '%-3s %-4s %-7s %-52s %-22s %s\n' "$pri" "$scr" "$tier" "${host:0:52}" "${prog:0:22}" "${sig:0:50}"
    done
  echo
  printf "  total KEV-matched hosts in ES: %s\n" "$total"
}

cmd_scope() {
  local host="${1:-}"
  if [[ -z "$host" ]]; then echo "Usage: recon_ctl scope <host>"; return 1; fi
  [[ -f "$V21_SCOPE_CHECK" ]] || { echo "scope_check missing"; return 1; }
  bash "$V21_SCOPE_CHECK" "$host" | jq .
}

cmd_programs() {
  hdr "Programs in scope DB"
  local f="$HOME/recon/scope/programs.json"
  [[ ! -s "$f" ]] && { echo "  scope DB not populated"; return; }
  jq -r '
    group_by(.platform) | map({
      platform: .[0].platform,
      total: length,
      paying: [.[] | select(.pays == true)] | length
    }) | .[] | "  \(.platform): \(.total) total, \(.paying) paying"
  ' "$f"
  echo
  echo "  TOTAL: $(jq 'length' "$f")"
}

# Fix 12: load active ignored hosts from ignored.jsonl (respecting TTL)
# Returns newline-separated list of currently-active ignored hostnames
_load_active_ignored() {
  local ig_file="$HOME/recon/state/ignored.jsonl"
  local ttl_days="${IGNORE_TTL_DAYS:-7}"
  [[ ! -s "$ig_file" ]] && return
  local cutoff; cutoff="$(date -u -d "-${ttl_days} days" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u '+%Y-%m-%dT%H:%M:%SZ')"
  jq -r --arg cutoff "$cutoff" 'select((.added_at // "") >= $cutoff) | .host' \
    "$ig_file" 2>/dev/null | sort -u
}

cmd_fresh() {
  # Usage: fresh [--new] [--save] [--out <path>] [--all | N]
  #   --new        only show hosts not returned by a previous fresh query
  #   --save       write to ~/recon/fresh/fresh_TIMESTAMP.txt
  #   --out <path> write to a specific file (implies --save)
  #   --all        fetch every result (no cap)
  #   N            cap results (default 50)
  local new_only=0 save=0 n=50 outfile=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --new)       new_only=1; shift ;;
      --save)      save=1; shift ;;
      --out|-o)    outfile="$2"; save=1; shift 2 ;;
      --all)       n=9999; shift ;;
      [0-9]*)      n="$1"; shift ;;
      *) shift ;;
    esac
  done
  # --new: fetch a large pool so we can filter unseen before capping at N.
  # Use 2000 — with 3000+ P0/P1 hosts during a bulk sweep, a pool of 500
  # gets exhausted by already-seen high-scorers, leaving nothing new to show.
  local fetch_n="$n"
  [[ "$new_only" -eq 1 && "$n" -lt 2000 ]] && fetch_n=2000

  local FRESH_DIR="$BASE_DIR/fresh"
  local SEEN_FILE="$STATE_DIR/fresh_seen.txt"
  mkdir -p "$FRESH_DIR"
  touch "$SEEN_FILE"

  local resp
  resp="$(curl -sS -m30 --netrc-file "$HOME/.recon_es_netrc" \
    -H 'Content-Type: application/json' \
    -X POST "$ES_URL/$INDEX_NAME/_search" -d "{
      \"size\": $fetch_n,
      \"_source\": [\"host\",\"url\",\"triage_priority\",\"triage_score\",\"triage_signals\",
                    \"triage_program\",\"triage_payout_tier\",\"triage_kev_match\",\"first_seen\"],
      \"query\": {\"bool\": {\"filter\": [
        {\"term\": {\"triage_true_fresh\": true}},
        {\"term\": {\"triage_pays\": true}},
        {\"term\": {\"triage_in_scope\": true}},
        {\"terms\": {\"triage_priority\": [\"P0\",\"P1\"]}}
      ], \"must_not\": [{\"term\": {\"triage_out_of_scope\": true}}]}},
      \"sort\": [{\"triage_score\": {\"order\": \"desc\"}},{\"first_seen\": {\"order\": \"desc\"}}]
    }" 2>/dev/null)"
  local total; total="$(printf '%s' "$resp" | jq -r '.hits.total.value // 0' 2>/dev/null)"

  # Format rows: icon | priority | score | tier | host | program | signals | date
  local rows; rows="$(printf '%s' "$resp" | jq -r '
    .hits.hits[]?._source |
    [
      (if .triage_kev_match then "KEV" elif .triage_priority=="P0" then "P0" else "P1" end),
      (.triage_priority // "?"),
      ((.triage_score // 0) | tostring),
      (.triage_payout_tier // "?"),
      (.host // "?"),
      (.triage_program // "?"),
      ((.triage_signals // []) | join(",")),
      (.first_seen // "" | split("T")[0])
    ] | @tsv
  ' 2>/dev/null)"

  # Fix 12: load active ignored hosts for query-time filtering
  local ignored_hosts; ignored_hosts="$(_load_active_ignored)"

  # --new: filter to hosts not in seen file, cap at N after filtering
  local new_hosts="" shown_rows="" count=0
  if [[ "$new_only" -eq 1 ]]; then
    while IFS=$'\t' read -r icon pri score tier host prog sigs date; do
      [[ -z "$host" ]] && continue
      [[ "$count" -ge "$n" ]] && break
      # Fix 12: skip if host is in active ignore list
      if printf '%s\n' "$ignored_hosts" | grep -qxF "$host" 2>/dev/null; then continue; fi
      if ! grep -qxF "$host" "$SEEN_FILE"; then
        shown_rows="${shown_rows}${icon}	${pri}	${score}	${tier}	${host}	${prog}	${sigs}	${date}"$'\n'
        new_hosts="${new_hosts}${host}"$'\n'
        count=$(( count + 1 ))
      fi
    done <<< "$rows"
  else
    # Non---new browse: never write to seen file. Writing here poisons the
    # seen list with high-scoring hosts that the user may not have acted on,
    # making subsequent recon-fresh-new calls return nothing.
    while IFS=$'\t' read -r icon pri score tier host prog sigs date; do
      [[ -z "$host" ]] && continue
      # Fix 12: skip if host is in active ignore list
      if printf '%s\n' "$ignored_hosts" | grep -qxF "$host" 2>/dev/null; then continue; fi
      shown_rows="${shown_rows}${icon}	${pri}	${score}	${tier}	${host}	${prog}	${sigs}	${date}"$'\n'
    done <<< "$rows"
  fi

  local label="True-Fresh P0/P1"
  [[ "$new_only" -eq 1 ]] && label="True-Fresh P0/P1 — NEW ONLY (unseen)"
  hdr "$label"

  local out
  out="$(printf '%s' "$shown_rows" | awk -F'\t' 'NF{
    icon = ($1=="KEV") ? "🔴" : ($1=="P0") ? "⚡" : "▸"
    printf "%-3s %-3s %-4s %-8s %-55s %-25s %s  %s\n", icon,$2,$3,$4,$5,$6,$7,$8
  }')"

  if [[ -n "$out" ]]; then
    printf '%s\n' "$out"
  else
    echo "  (no results)"
  fi

  local shown_n=0
  [[ "$new_only" -eq 1 ]] && shown_n="$count" || shown_n="$(printf '%s' "$shown_rows" | awk 'NF' | wc -l | tr -d ' ')"
  printf '\n  showing: %s  |  total true-fresh P0/P1 in ES: %s\n' "$shown_n" "$total"

  # Record newly seen hosts — ONLY in --new mode. Regular recon-fresh is
  # browsing; only recon-fresh-new means "I have acknowledged these targets".
  if [[ "$new_only" -eq 1 && -n "$new_hosts" ]]; then
    printf '%s' "$new_hosts" >> "$SEEN_FILE"
    sort -u "$SEEN_FILE" -o "$SEEN_FILE"
  fi

  # --save / --out: write txt
  if [[ "$save" -eq 1 ]]; then
    local ts; ts="$(date -u +%Y%m%dT%H%M%SZ)"
    [[ -z "$outfile" ]] && outfile="$FRESH_DIR/fresh_${ts}.txt"
    mkdir -p "$(dirname "$outfile")"
    {
      printf '# recon-fresh %s  (total_in_es=%s shown=%s new_only=%s)\n' \
        "$ts" "$total" "$shown_n" "$new_only"
      printf '%s\n' "$shown_rows" | awk -F'\t' 'NF{
        ai = ($9 != "") ? $9 : ""
        printf "%-3s %-4s %-8s %-55s %-25s %-6s %s  %s\n", $2,$3,$4,$5,$6,ai,$7,$8
      }'
    } > "$outfile"
    printf '  saved → %s\n' "$outfile"
  fi
}

cmd_tech() {
  # Usage: tech <tech[,tech2,...]> [--apex] [--pays] [--no-save] [--out <path>] [N]
  #   <tech>       technology name(s) — comma or space separated
  #                e.g.  wordpress   nginx,apache   "F5 BIG-IP"
  #   --apex       exclude subdomains — only hosts where host == root_domain
  #   --pays       limit to in-scope paying targets only
  #   --no-save    do NOT write txt file (default: always saves)
  #   --out <path> write to a specific file instead of ~/recon/tech/
  #   N            result cap (default 200)
  local apex=0 pays=0 nosave=0 n=200 outfile=""
  local techs=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --apex)      apex=1; shift ;;
      --pays)      pays=1; shift ;;
      --no-save)   nosave=1; shift ;;
      --out|-o)    outfile="$2"; shift 2 ;;
      [0-9]*)      n="$1"; shift ;;
      *)
        # split comma-separated values and add each
        IFS=',' read -ra _t <<< "$1"
        techs+=("${_t[@]}")
        shift ;;
    esac
  done
  if [[ ${#techs[@]} -eq 0 ]]; then
    echo "Usage: recon_ctl tech <tech[,tech2]> [--apex] [--pays] [--no-save] [N]"
    echo "       recon-tech wordpress"
    echo "       recon-tech nginx,apache --apex --pays 50"
    return 1
  fi

  local TECH_DIR="$BASE_DIR/tech"
  mkdir -p "$TECH_DIR"

  # Build a should[OR] clause for each tech:
  #   (a) wildcard on `tech` field — case-insensitive, matches versioned values e.g. "WordPress:5.7"
  #   (b) term on `triage_signals` — e.g. "tech:wordpress" (triage may detect it even when httpx misses)
  local should_clauses=""
  local t
  for t in "${techs[@]}"; do
    local tl; tl="$(printf '%s' "$t" | tr '[:upper:]' '[:lower:]')"
    [[ -n "$should_clauses" ]] && should_clauses="$should_clauses,"
    should_clauses="${should_clauses}
      {\"wildcard\":{\"tech\":{\"value\":\"*${tl}*\",\"case_insensitive\":true}}},
      {\"term\":{\"triage_signals\":\"tech:${tl}\"}}"
  done

  # Extra mandatory filters
  local extra_filters=""
  [[ "$pays" -eq 1 ]] && extra_filters=',{"term":{"triage_pays":true}},{"term":{"triage_in_scope":true}}'

  local resp
  resp="$(curl -sS -m30 --netrc-file "$HOME/.recon_es_netrc" \
    -H 'Content-Type: application/json' \
    -X POST "$ES_URL/$INDEX_NAME/_search" -d "{
      \"size\": $n,
      \"_source\": [\"host\",\"root_domain\",\"url\",\"tech\",\"triage_priority\",\"triage_score\",
                    \"triage_signals\",\"triage_program\",\"triage_payout_tier\",\"triage_pays\",
                    \"triage_in_scope\",\"triage_true_fresh\",\"first_seen\"],
      \"query\": {\"bool\": {
        \"filter\": [
          {\"bool\":{\"should\":[$should_clauses],\"minimum_should_match\":1}}
          $extra_filters
        ],
        \"must_not\": [{\"term\":{\"triage_out_of_scope\":true}}]
      }},
      \"sort\": [{\"triage_score\":{\"order\":\"desc\",\"missing\":\"_last\"}},
                 {\"first_seen\":{\"order\":\"desc\"}}]
    }" 2>/dev/null)"

  local total; total="$(printf '%s' "$resp" | jq -r '.hits.total.value // 0' 2>/dev/null)"
  local label="tech:$(IFS=','; printf '%s' "${techs[*]}")"
  [[ "$apex" -eq 1 ]] && label="$label (apex only)"
  [[ "$pays" -eq 1 ]] && label="$label (paying)"
  hdr "Hosts matching $label"

  # Format and optionally filter apex
  local rows; rows="$(printf '%s' "$resp" | jq -r '
    .hits.hits[]?._source |
    [
      (.host // ""),
      (.root_domain // ""),
      (.triage_priority // "-"),
      ((.triage_score // 0) | tostring),
      (.triage_payout_tier // "-"),
      (.triage_program // "-"),
      ((.tech // []) | map(select(length>0)) | join(",")),
      (if .triage_true_fresh then "fresh" else "" end),
      (.first_seen // "" | split("T")[0])
    ] | @tsv
  ' 2>/dev/null)"

  local out_lines=() host_list=()
  while IFS=$'\t' read -r host root pri score tier prog tech_list tfresh fdate; do
    [[ -z "$host" ]] && continue
    # --apex: skip if host has more labels than root_domain (i.e. is a subdomain)
    if [[ "$apex" -eq 1 ]]; then
      # count dots: subdomain has more dots than root
      local hdots rdots
      hdots=$(tr -cd '.' <<< "$host" | wc -c)
      rdots=$(tr -cd '.' <<< "$root" | wc -c)
      [[ "$hdots" -gt "$rdots" ]] && continue
    fi
    local fresh_tag=""
    [[ "$tfresh" == "fresh" ]] && fresh_tag="⚡"
    out_lines+=("$(printf '%-3s %-3s %-4s %-8s %-50s %-22s %-30s %s' \
      "$fresh_tag" "$pri" "$score" "$tier" "$host" "$prog" "$tech_list" "$fdate")")
    host_list+=("$host")
  done <<< "$rows"

  local shown=${#out_lines[@]}
  if [[ "$shown" -eq 0 ]]; then
    echo "  (no results)"
  else
    printf '%s\n' "${out_lines[@]}"
  fi
  printf '\n  showing: %s  |  total matched in ES: %s\n' "$shown" "$total"

  # Save txt (unless --no-save)
  if [[ "$nosave" -eq 0 && "$shown" -gt 0 ]]; then
    local ts; ts="$(date -u +%Y%m%dT%H%M%SZ)"
    if [[ -z "$outfile" ]]; then
      local slug; slug="$(printf '%s' "${techs[*]}" | tr ' /' '__')"
      outfile="$TECH_DIR/tech_${slug}_${ts}.txt"
    fi
    mkdir -p "$(dirname "$outfile")"
    {
      printf '# tech query: %s  apex=%s pays=%s  %s  (es_total=%s shown=%s)\n' \
        "$(IFS=','; printf '%s' "${techs[*]}")" "$apex" "$pays" "$ts" "$total" "$shown"
      printf '%s\n' "${out_lines[@]}"
      printf '\n# hosts only:\n'
      printf '%s\n' "${host_list[@]}"
    } > "$outfile"
    printf '  saved → %s\n' "$outfile"
  fi
}

cmd_confirmed() {
  hdr "Latest confirmed nuclei findings"
  local f="$HOME/recon/nuclei/confirmed.jsonl"
  [[ ! -s "$f" ]] && { echo "  none yet"; return; }
  tail -20 "$f" | jq -r '"  [\(.info.severity // \"?\")] \(.host) — \(.\"template-id\") (program: \(.scope.program // \"?\"))"'
}

# ---------------------------------------------------------------------------
# _ai_db <sql> — read-only query against the v3 finding-state DB (findings.db).
# The AI layer is now the Claude-Max VALIDATION agent (recon_ai_review.sh): its
# verdicts (ai_verdict / ai_confidence / ai_reason) live in SQLite, not ES.
# (The legacy Ollama ai_relevance_score/ai_recommendation pre-scorer was retired
# in v3.1.) Tab-separated rows on stdout; silent on any error (missing/locked db).
# ---------------------------------------------------------------------------
_ai_db() {
  local db="${V3_DB:-$BASE_DIR/v3/findings.db}"
  python3 - "$db" "$1" <<'PY' 2>/dev/null
import sqlite3, sys
db, sql = sys.argv[1], sys.argv[2]
try:
    c = sqlite3.connect("file:%s?mode=ro" % db, uri=True)
    for row in c.execute(sql):
        print("\t".join("" if v is None else str(v) for v in row))
except Exception:
    pass
PY
}

# ---------------------------------------------------------------------------
# _ai_table <where> <limit> — render finding rows as a Claude-verdict table.
# ---------------------------------------------------------------------------
_ai_table() {
  local where="$1" n="${2:-50}"
  local B=$'\033[1m' R=$'\033[0m' G=$'\033[0;32m' Y=$'\033[1;33m' RD=$'\033[0;31m'
  local rows
  rows="$(_ai_db "SELECT host, COALESCE(ai_verdict,'unreviewed'), printf('%.2f',COALESCE(ai_confidence,0)), COALESCE(vuln_class,'-'), state, COALESCE(ai_reason,'') FROM findings WHERE $where ORDER BY (ai_verdict='real') DESC, ai_confidence DESC, state_changed_at DESC LIMIT $n;")"
  if [[ -z "$rows" ]]; then echo "  (no matching findings)"; return; fi
  printf "${B}%-12s %-5s %-40s %-9s %s${R}\n" "VERDICT" "CONF" "HOST" "STATE" "CLASS"
  printf '%s\n' "$(printf '─%.0s' {1..150})"
  printf '%s\n' "$rows" | while IFS=$'\t' read -r host verdict conf cls state reason; do
    local col="$R"
    case "$verdict" in
      real) col="$G" ;; fp) col="$RD" ;; needs-human) col="$Y" ;;
    esac
    printf "${col}%-12s${R} %-5s %-40s %-9s %s\n" "$verdict" "$conf" "${host:0:40}" "${state:0:9}" "${cls:0:30}"
  done
}

cmd_ai() {
  local sub="${1:-status}"; shift || true
  local DB="${V3_DB:-$BASE_DIR/v3/findings.db}"
  local claude="$HOME/.local/bin/claude"; [[ -x "$claude" ]] || claude="$(command -v claude 2>/dev/null || echo '')"

  case "$sub" in
    # ---- status (default): validation-agent health + verdict breakdown ----
    status|"")
      hdr "AI validation layer (Claude-Max) — status"
      if [[ -n "$claude" && -x "$claude" ]]; then
        echo "  claude CLI: ✅ $("$claude" --version 2>/dev/null | head -1)  (Max headless, no API key)"
      else
        echo "  claude CLI: ❌ not found — deterministic confidence fallback in effect"
      fi
      echo "  model:      ${CLAUDE_MODEL:-sonnet}    on-demand verify batch: ${AI_REVIEW_BATCH:-15}  (daemon ai-review loop retired; 2IC routine + recon-verify own validation)"
      if [[ ! -f "$DB" ]]; then echo "  db:         ❌ $DB (not found — evidence gate has not run yet)"; return 0; fi
      echo "  db:         $DB"
      local stats
      stats="$(_ai_db "SELECT SUM(state='confirmed'), SUM(ai_verdict='real'), SUM(ai_verdict='fp'), SUM(ai_verdict='needs-human'), SUM(state='confirmed' AND ai_verdict IS NULL), SUM(state='reported'), SUM(state='dismissed') FROM findings;")"
      local conf real fp human pending reported dismissed
      IFS=$'\t' read -r conf real fp human pending reported dismissed <<<"$stats"
      echo
      printf "  Confirmed findings:      %s\n" "${conf:-0}"
      printf "    \033[0;32mreal\033[0m (reportable):    %s\n" "${real:-0}"
      printf "    \033[1;33mneeds-human\033[0m:           %s\n" "${human:-0}"
      printf "    \033[0;31mfp\033[0m (auto-dismissed):   %s   [total dismissed: %s]\n" "${fp:-0}" "${dismissed:-0}"
      printf "    pending validation:     %s\n" "${pending:-0}"
      printf "  Reported (review queue):   %s\n" "${reported:-0}"
      echo
      printf "  Subcommands:\n"
      printf "    recon-ai real          — Claude-validated reportable findings\n"
      printf "    recon-ai human         — needs-human (operator decision)\n"
      printf "    recon-ai pending       — confirmed, awaiting Claude validation\n"
      printf "    recon-ai fp            — auto-dismissed false positives\n"
      printf "    recon-ai detail <host> — full verdict + evidence for one host\n"
      ;;

    real)              hdr "AI-validated — REAL (reportable)";      _ai_table "ai_verdict='real'" "${1:-999}" ;;
    human|needs-human) hdr "AI-validated — needs human decision";   _ai_table "ai_verdict='needs-human'" "${1:-999}" ;;
    pending)           hdr "Confirmed — pending Claude validation"; _ai_table "state='confirmed' AND ai_verdict IS NULL" "${1:-999}" ;;
    fp)                hdr "AI-validated — false positives";        _ai_table "ai_verdict='fp'" "${1:-200}" ;;
    top|all)           hdr "All findings (verdict order)";          _ai_table "1=1" "${1:-50}" ;;

    # ---- analysis: Claude ANALYSIS leads worth verifying (from ES, not SQLite) ----
    analysis|analyze)
      local an_n="${1:-50}"
      hdr "Claude-analysis leads (worth verifying) — from ES"
      local an_resp
      an_resp="$(_es_search "{
        \"size\": $an_n,
        \"_source\": [\"host\",\"claude_interest\",\"claude_suggested_class\",
                      \"claude_analysis\",\"triage_program\",\"triage_payout_tier\"],
        \"query\": {\"term\": {\"claude_worth\": true}},
        \"sort\": [{\"claude_interest\": {\"order\": \"desc\", \"missing\": \"_last\"}}]
      }")"
      local an_total; an_total="$(printf '%s' "$an_resp" | jq -r '.hits.total.value // 0' 2>/dev/null)"
      if [[ "${an_total:-0}" -eq 0 ]]; then echo "  (no Claude-analysis leads in ES yet)"; return 0; fi
      printf "%-4s %-44s %-20s %s\n" "INT" "HOST" "CLASS" "PROGRAM"
      printf '%s\n' "$(printf '─%.0s' {1..120})"
      printf '%s' "$an_resp" | jq -r '
        .hits.hits[]._source |
        [
          ((.claude_interest // 0) | tostring),
          (.host // "?"),
          (.claude_suggested_class // "-"),
          (.triage_program // "-"),
          ((.claude_analysis // "") | gsub("[\n\t]";" "))
        ] | @tsv' 2>/dev/null \
      | while IFS=$'\t' read -r intr host cls prog note; do
          printf "%-4s %-44s %-20s %s\n" "$intr" "${host:0:44}" "${cls:0:20}" "${prog:0:30}"
          [[ -n "$note" ]] && printf "       %s\n" "${note:0:110}"
        done
      echo
      printf "  showing: %s  |  total Claude-worth leads in ES: %s\n" "$an_n" "$an_total"
      ;;

    # ---- accuracy: Claude layer self-audit (is it actually working?) ----
    accuracy|audit)
      hdr "Claude accuracy — self-audit (human disposition of 'real' verdicts)"
      local sp="${STATE_PY:-$SCRIPT_DIR/../engine/state.py}"
      [[ -f "$DB" ]] || { echo "  db not found ($DB — evidence gate has not run yet)"; return 0; }
      V3_DB="$DB" python3 "$sp" ai-accuracy 2>/dev/null | jq -r '
        "  reviewed total: \(.reviewed_total)",
        "  verdicts: " + ([.verdict_distribution|to_entries[]|"\(.key)=\(.value.count)(conf \(.value.avg_conf))"]|join("  ")),
        "  real-verdict precision (human-decided): " + (if .real_disposition.precision_when_decided==null then "n/a (no human decisions yet)" else ((.real_disposition.precision_when_decided*100|floor|tostring)+"%") end),
        "    accepted=\(.real_disposition.accepted_submitted)  rejected=\(.real_disposition.rejected_dismissed)  pending-human=\(.real_disposition.pending_human)",
        "  escalations=\(.escalations)  AI-learned-FP-sigs=\(.fp_signatures_from_ai)  KB-lessons=\(.kb_lessons) (used \(.kb_retrievals)x)"
      ' 2>/dev/null || echo "  (no data yet — Claude validation layer has not produced verdicts)"
      ;;

    # ---- detail <host>: full verdict + evidence from SQLite ----
    detail|show|inspect)
      local target="${1:-}"
      [[ -z "$target" ]] && { echo "Usage: recon-ai detail <host>"; return 1; }
      local esc="${target//\'/\'\'}"
      local row
      row="$(_ai_db "SELECT host, COALESCE(ai_verdict,'unreviewed'), printf('%.2f',COALESCE(ai_confidence,0)), COALESCE(ai_reason,'(none)'), state, COALESCE(vuln_class,'?'), COALESCE(signal_class,'?'), COALESCE(program,'?'), COALESCE(url,host), printf('%.2f',COALESCE(confidence,0)), COALESCE(ai_reviewed_at,'never'), COALESCE(evidence,'') FROM findings WHERE host LIKE '%$esc%' ORDER BY state_changed_at DESC LIMIT 1;")"
      if [[ -z "$row" ]]; then echo "  No finding for host: $target"; return 1; fi
      hdr "AI detail — $target"
      local host verdict conf reason state cls sig prog url dconf reviewed evidence
      IFS=$'\t' read -r host verdict conf reason state cls sig prog url dconf reviewed evidence <<<"$row"
      printf "  Verdict:     %s   (Claude confidence %s)\n" "$verdict" "$conf"
      printf "  Reason:      %s\n" "$reason"
      printf "  Reviewed:    %s\n\n" "$reviewed"
      printf "  State:       %s\n" "$state"
      printf "  Vuln class:  %s   (signal: %s)\n" "$cls" "$sig"
      printf "  Gate-confidence: %s\n" "$dconf"
      printf "  Program:     %s\n" "$prog"
      printf "  URL:         %s\n" "$url"
      printf "  Evidence:    %s\n" "${evidence:0:300}"
      ;;

    *)
      echo "recon-ai subcommands (Claude-Max validation, SQLite-backed):"
      echo "  status              Validation-agent health + verdict breakdown (default)"
      echo "  real                Claude-validated reportable findings"
      echo "  human               needs-human findings (operator decision)"
      echo "  pending             confirmed findings awaiting validation"
      echo "  fp                  auto-dismissed false positives"
      echo "  top [N]             all findings in verdict order"
      echo "  analysis            Claude-analysis leads worth verifying (from ES)"
      echo "  accuracy            self-audit: 'real'-verdict precision + verdict mix"
      echo "  detail <host>       full verdict + evidence for one host"
      ;;
  esac
}

# ---------------------------------------------------------------------------
# cmd_view — comprehensive pipeline dashboard (ES-based, all data live)
# ---------------------------------------------------------------------------
cmd_outcome() {
  # Record the PLATFORM resolution of a submitted finding (the post-submission feedback
  # loop): accepted | dup | na | info [+bounty]. Feeds state.py ai-accuracy + the learning
  # stores (accepted=KB positive anchor; dup/na/info=FP signature = dedup signal).
  local fid="${1:-}" res="${2:-}" bounty="${3:-0}"
  local DB="${V3_DB:-$BASE_DIR/v3/findings.db}"
  local sp="${STATE_PY:-$SCRIPT_DIR/../engine/state.py}"
  if [[ -z "$fid" || -z "$res" ]]; then
    echo "Usage: recon-outcome <finding_id> <accepted|dup|na|info> [bounty_usd]"
    echo "  Records what the platform decided after you submitted, so the system learns:"
    echo "    accepted      -> KB positive anchor (severity/dedup calibration)"
    echo "    dup|na|info   -> FP signature (the same host+class won't re-surface)"
    echo "  See the result mix:  recon-ai accuracy   (.submission_outcomes)"
    return 1
  fi
  [[ -f "$DB" ]] || { echo "  db not found ($DB)"; return 1; }
  local out; out="$(V3_DB="$DB" python3 "$sp" outcome "$fid" "$res" "$bounty" 2>&1)" \
    || { echo "  ✗ $out"; return 1; }
  echo "  ✓ recorded: $out"
}

cmd_view() {
  local n_top="${1:-10}"
  local B='\033[1m' R='\033[0m' C='\033[1;36m' G='\033[0;32m' Y='\033[1;33m' RD='\033[0;31m'
  local tmp; tmp="$(mktemp -d)"

  printf "${C}${B}╔══════════════════════════════ RECON PIPELINE DASHBOARD ════════════════════════════════╗${R}\n"

  # ── Daemon / queue (local state — fast) ───────────────────────────────────
  local daemon_state="STOPPED"
  if [[ -s "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    local etime; etime="$(ps -o etime= -p "$(cat "$PID_FILE")" 2>/dev/null | tr -d ' ')"
    daemon_state="RUNNING pid=$(cat "$PID_FILE") up=$etime"
  fi
  local inbox proc
  inbox="$(find "$QUEUE_DIR/inbox"      -maxdepth 1 -name '*.txt' 2>/dev/null | wc -l | tr -d ' ')"
  proc="$(find  "$QUEUE_DIR/processing" -maxdepth 1 -name '*.txt' 2>/dev/null | wc -l | tr -d ' ')"

  # ── Fire all ES queries in parallel ───────────────────────────────────────
  { _es_count_q '{"match_all":{}}' > "$tmp/es_total"; } &
  { STATE_DIR="$STATE_DIR" bash "$SCRIPT_DIR/recon_vpn_check.sh" --cached >/dev/null 2>&1
    jq -r 'if .mullvad==true then "✅ "+.ip elif .mullvad==false then "❌ NOT MULLVAD ("+.ip+")" else "❓ unconfirmed" end' \
      "$STATE_DIR/vpn_status.json" 2>/dev/null || echo "❓ unknown"; } > "$tmp/vpn" &
  { _es_search "{\"size\":$n_top,\"_source\":[\"host\",\"triage_priority\",\"triage_score\",\"triage_payout_tier\",\"triage_program\",\"triage_signals\"],\"query\":{\"bool\":{\"filter\":[{\"term\":{\"triage_priority\":\"P0\"}},{\"term\":{\"triage_true_fresh\":true}},{\"term\":{\"triage_pays\":true}}]}},\"sort\":[{\"triage_score\":{\"order\":\"desc\"}}]}" > "$tmp/fresh_p0"; } &
  { _es_search "{\"size\":$n_top,\"_source\":[\"host\",\"triage_priority\",\"triage_score\",\"triage_payout_tier\",\"triage_program\",\"triage_true_fresh\",\"triage_classes\"],\"query\":{\"term\":{\"triage_priority\":\"P0\"}},\"sort\":[{\"triage_score\":{\"order\":\"desc\"}}]}" > "$tmp/all_p0"; } &
  { _es_search "{\"size\":$n_top,\"_source\":[\"host\",\"triage_priority\",\"triage_score\",\"triage_payout_tier\",\"triage_program\",\"triage_kev_signal\"],\"query\":{\"term\":{\"triage_kev_match\":true}},\"sort\":[{\"triage_score\":{\"order\":\"desc\"}}]}" > "$tmp/kev"; } &
  { _es_search "{\"size\":5,\"_source\":[\"host\",\"triage_priority\",\"triage_score\",\"triage_program\",\"js_secret_hit\",\"js_endpoint_hit\",\"url\"],\"query\":{\"bool\":{\"should\":[{\"term\":{\"js_secret_hit\":true}},{\"term\":{\"js_endpoint_hit\":true}}],\"minimum_should_match\":1}},\"sort\":[{\"triage_score\":{\"order\":\"desc\"}}]}" > "$tmp/js"; } &
  {
    _es_count_q '{"term":{"triage_priority":"P0"}}' > "$tmp/cnt_p0"
    _es_count_q '{"term":{"triage_priority":"P1"}}' > "$tmp/cnt_p1"
    _es_count_q '{"term":{"triage_priority":"P2"}}' > "$tmp/cnt_p2"
    _es_count_q '{"term":{"triage_true_fresh":true}}' > "$tmp/cnt_fresh"
    _es_count_q '{"term":{"triage_kev_match":true}}' > "$tmp/cnt_kev"
    _es_count_q '{"bool":{"should":[{"term":{"js_secret_hit":true}},{"term":{"js_endpoint_hit":true}}],"minimum_should_match":1}}' > "$tmp/cnt_js"
  } &
  wait

  local es_count; es_count="$(cat "$tmp/es_total" 2>/dev/null || echo '?')"
  local vpn_state; vpn_state="$(cat "$tmp/vpn"    2>/dev/null || echo '?')"
  printf "  daemon: ${B}%s${R}   queue: inbox=%s proc=%s   ES: %s docs   VPN: %s\n\n" \
    "$daemon_state" "$inbox" "$proc" "$es_count" "$vpn_state"

  # ── 2. True-fresh P0 targets ───────────────────────────────────────────────
  local n_fresh_p0; n_fresh_p0="$(jq -r '.hits.total.value // 0' "$tmp/fresh_p0" 2>/dev/null || echo 0)"
  printf "${Y}${B}━━━ ⚡ TRUE-FRESH P0 (in-scope paying) — %s total ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${R}\n" "$n_fresh_p0"
  if [[ "$n_fresh_p0" -gt 0 ]]; then
    printf "${B}%-3s %-4s %-7s %-52s %-22s %s${R}\n" "PRI" "SCR" "TIER" "HOST" "PROGRAM" "SIGNALS"
    jq -r '
      .hits.hits[]._source |
      [
        (.triage_priority // "-"),
        ((.triage_score // 0) | tostring),
        (.triage_payout_tier // "-"),
        (.host // ""),
        (.triage_program // "-"),
        ((.triage_signals // []) | join(",") | .[0:60])
      ] | @tsv' "$tmp/fresh_p0" 2>/dev/null \
    | while IFS=$'\t' read -r pri scr tier host prog sigs; do
        printf "%-3s %-4s %-7s %-52s %-22s %s\n" "$pri" "$scr" "$tier" "${host:0:52}" "${prog:0:22}" "$sigs"
      done
  else
    echo "  (none)"
  fi
  echo

  # ── 3. All P0 targets ─────────────────────────────────────────────────────
  local p0_total; p0_total="$(cat "$tmp/cnt_p0" 2>/dev/null || echo 0)"
  printf "${B}━━━ P0 TARGETS (top $n_top of $p0_total, sorted by score) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${R}\n"
  local p0_shown; p0_shown="$(jq -r '.hits.total.value // 0' "$tmp/all_p0" 2>/dev/null || echo 0)"
  if [[ "$p0_shown" -gt 0 ]]; then
    printf "${B}%-2s %-3s %-4s %-7s %-52s %-22s %s${R}\n" "FR" "PRI" "SCR" "TIER" "HOST" "PROGRAM" "CLASSES"
    jq -r '
      .hits.hits[]._source |
      [
        (if (.triage_true_fresh // false) then "⚡" else " " end),
        (.triage_priority // "-"),
        ((.triage_score // 0) | tostring),
        (.triage_payout_tier // "-"),
        (.host // ""),
        (.triage_program // "-"),
        ((.triage_classes // []) | map(select(. != "low-priority" and . != "low-signal")) | join(","))
      ] | @tsv' "$tmp/all_p0" 2>/dev/null \
    | while IFS=$'\t' read -r fr pri scr tier host prog cls; do
        printf "%-2s %-3s %-4s %-7s %-52s %-22s %s\n" "$fr" "$pri" "$scr" "$tier" "${host:0:52}" "${prog:0:22}" "$cls"
      done
  else
    echo "  (no P0 targets)"
  fi
  echo

  # ── 5. KEV matches ────────────────────────────────────────────────────────
  local n_kev; n_kev="$(cat "$tmp/cnt_kev" 2>/dev/null || echo 0)"
  printf "${B}━━━ 🎯 KEV MATCHES — %s hosts ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${R}\n" "$n_kev"
  if [[ "$n_kev" -gt 0 ]]; then
    jq -r '
      .hits.hits[]._source |
      [.host, (.triage_kev_signal // "-"), (.triage_priority // "-"), ((.triage_score // 0) | tostring)]
      | @tsv' "$tmp/kev" 2>/dev/null \
    | while IFS=$'\t' read -r host sig pri scr; do
        printf "  %-50s %-30s %s/%s\n" "${host:0:50}" "${sig:0:30}" "$pri" "$scr"
      done
  else
    echo "  (none)"
  fi
  echo

  # ── 6. JS findings ────────────────────────────────────────────────────────
  local n_js; n_js="$(cat "$tmp/cnt_js" 2>/dev/null || echo 0)"
  printf "${B}━━━ 🔑 JS FINDINGS (secrets / endpoints) — %s hosts ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${R}\n" "$n_js"
  if [[ "$n_js" -gt 0 ]]; then
    printf "${B}%-50s %-8s %-9s %s${R}\n" "HOST" "SECRETS" "ENDPTS" "PROGRAM"
    jq -r '
      .hits.hits[]._source |
      [
        .host,
        (if (.js_secret_hit // false) then "🔑 yes" else "no" end),
        (if (.js_endpoint_hit // false) then "🛤 yes" else "no" end),
        (.triage_program // "-")
      ] | @tsv' "$tmp/js" 2>/dev/null \
    | while IFS=$'\t' read -r host sec ep prog; do
        printf "%-50s %-8s %-9s %s\n" "${host:0:50}" "$sec" "$ep" "${prog:0:22}"
      done
  else
    echo "  (none)"
  fi
  echo

  # ── 7. Recent confirmed nuclei findings (still local — not in ES) ─────────
  local confirmed_f="$HOME/recon/nuclei/confirmed.jsonl"
  if [[ -s "$confirmed_f" ]]; then
    printf "${B}━━━ ✅ CONFIRMED FINDINGS (nuclei) — latest 5 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${R}\n"
    tail -5 "$confirmed_f" | jq -r \
      '"  [\(.info.severity//"?")] \(.host) — \(."template-id") (\(.scope.program//"?"))"' \
      2>/dev/null || echo "  (none)"
    echo
  fi

  # ── 8. Summary counts ─────────────────────────────────────────────────────
  printf "${C}${B}╔══════════════════════════════════════ SUMMARY ═════════════════════════════════════════╗${R}\n"
  local t_p0 t_p1 t_p2 t_fresh t_kev t_js
  t_p0="$(cat    "$tmp/cnt_p0"       2>/dev/null || echo 0)"
  t_p1="$(cat    "$tmp/cnt_p1"       2>/dev/null || echo 0)"
  t_p2="$(cat    "$tmp/cnt_p2"       2>/dev/null || echo 0)"
  t_fresh="$(cat "$tmp/cnt_fresh"    2>/dev/null || echo 0)"
  t_kev="$(cat   "$tmp/cnt_kev"      2>/dev/null || echo 0)"
  t_js="$(cat    "$tmp/cnt_js"       2>/dev/null || echo 0)"

  printf "  Triage: P0=%-4s P1=%-4s P2=%-4s  true-fresh=%-4s  KEV=%-4s  JS=%-4s\n" \
    "$t_p0" "$t_p1" "$t_p2" "$t_fresh" "$t_kev" "$t_js"
  printf "\n  Quick commands:  ${G}recon-ai${R}  ${G}recon-fresh${R}  ${G}recon-kev${R}  ${G}recon-js${R}  ${G}recon-top 30${R}\n"
  rm -rf "$tmp"
}

# ---------------------------------------------------------------------------
# cmd_ports — show hosts with open non-standard ports discovered by portscan
# cmd_exposed — critical-only view (Docker/Redis/MongoDB/K8s/etcd)
# ---------------------------------------------------------------------------
cmd_ports() {
  local n="${1:-50}" critical_only="${2:-0}"
  local label="Hosts with exposed non-standard ports"
  [[ "$critical_only" == "1" ]] && label="CRITICAL exposed services (Docker/Redis/MongoDB/K8s/etcd)"
  hdr "$label"

  local crit_filter=""
  # portscan_critical is a long (0/1), not a boolean — query with 1, not true.
  [[ "$critical_only" == "1" ]] && crit_filter=',"must":[{"term":{"portscan_critical":1}}]'

  local resp
  resp="$(_es_search "$(printf '{
    "size":%s,
    "_source":["host","portscan_open_ports","portscan_critical","portscan_at",
                "triage_priority","triage_score","triage_program","triage_payout_tier"],
    "query":{"bool":{"filter":[{"exists":{"field":"portscan_open_ports"}},
                               {"range":{"portscan_open_ports":{"gt":0}}}]%s}},
    "sort":[{"portscan_critical":{"order":"desc"}},{"triage_score":{"order":"desc"}}]
  }' "$n" "$crit_filter")")"

  local total; total="$(printf '%s' "$resp" | jq -r '.hits.total.value // 0')"
  printf '%s' "$resp" | jq -r '
    .hits.hits[]._source |
    [
      (if (.portscan_critical == 1) then "🔴" else "🟠" end),
      (.triage_priority // "?"),
      ((.triage_score // 0) | tostring),
      (.triage_payout_tier // "?"),
      (.host // "?"),
      ((.portscan_open_ports // []) | map(tostring) | join(",")),
      (.triage_program // "?"),
      (.portscan_at // "" | split("T")[0])
    ] | @tsv
  ' 2>/dev/null | awk -F'\t' 'NF{
    printf "%-3s %-3s %-4s %-8s %-50s %-30s %-25s %s\n",$1,$2,$3,$4,$5,$6,$7,$8
  }'

  printf '\n  total with open ports in ES: %s\n' "$total"
  printf '  tip: recon-inspect <host> for full detail  |  recon-exposed for critical only\n'
}

cmd_exposed() { cmd_ports "${1:-100}" "1"; }

cmd_portscan_now() {
  local ps_script="$SCRIPT_DIR/recon_portscan.sh"
  [[ -f "$ps_script" ]] || { echo "recon_portscan.sh not found"; return 1; }
  echo "Triggering port scan cycle (running as reconrun via VPN)..."
  sudo -n -u reconrun env HOME="$HOME" BASE_DIR="$BASE_DIR" \
    ES_URL="${ES_URL:-http://127.0.0.1:9200}" \
    bash "$ps_script"
}

# ---------------------------------------------------------------------------
# cmd_bypass — view confirmed access-control bypasses (from ES)
# ---------------------------------------------------------------------------
cmd_bypass() {
  local n="${1:-30}"
  hdr "Confirmed access-control bypasses (top $n, by confidence)"
  local resp
  resp="$(_es_search "{
    \"size\": $n,
    \"_source\": [\"host\",\"triage_priority\",\"triage_score\",\"triage_payout_tier\",
                  \"triage_program\",\"bypass_technique\",\"bypass_top_confidence\",
                  \"bypass_waf\",\"bypass_paths\",\"bypass_checked_at\"],
    \"query\": {\"term\":{\"bypass_confirmed\":true}},
    \"sort\": [
      {\"bypass_top_confidence\":{\"order\":\"desc\",\"missing\":\"_last\"}},
      {\"triage_score\":{\"order\":\"desc\",\"missing\":\"_last\"}}
    ]
  }")"
  local total; total="$(printf '%s' "$resp" | jq -r '.hits.total.value // 0' 2>/dev/null)"
  if [[ "$total" -eq 0 ]]; then echo "  (no confirmed bypasses yet)"; return; fi
  printf '%-3s %-4s %-6s %-12s %-44s %-22s %-22s %s\n' \
    "PRI" "SCR" "CONF" "WAF" "HOST" "PROGRAM" "BEST TECHNIQUE" "PATHS"
  printf '%s\n' "$(printf '─%.0s' {1..150})"
  printf '%s' "$resp" | jq -r '
    .hits.hits[]._source |
    [
      (.triage_priority // "-"),
      ((.triage_score // 0) | tostring),
      ((.bypass_top_confidence // 0) | tostring),
      (.bypass_waf // "?"),
      (.host // ""),
      (.triage_program // "-"),
      (.bypass_technique // "?"),
      ((.bypass_paths // []) | map(.path) | unique | join(","))
    ] | @tsv' 2>/dev/null \
  | while IFS=$'\t' read -r pri scr conf waf host prog tech paths; do
      printf '%-3s %-4s %-6s %-12s %-44s %-22s %-22s %s\n' \
        "$pri" "$scr" "$conf" "${waf:0:12}" "${host:0:44}" "${prog:0:22}" "${tech:0:22}" "${paths:0:60}"
    done
  echo
  printf "  showing: %s of %s confirmed bypass(es)\n" \
    "$(printf '%s' "$resp" | jq -r '.hits.hits | length' 2>/dev/null)" "$total"
  printf "  tip: recon-inspect <host>   for full detail incl. all paths\n"
}

cmd_bypass_now() {
  local s="$SCRIPT_DIR/recon_bypass.sh"
  [[ -f "$s" ]] || { echo "recon_bypass.sh not found"; return 1; }
  echo "Triggering bypass cycle (running as reconrun via VPN)..."
  sudo -n -u reconrun env HOME="$HOME" BASE_DIR="$BASE_DIR" \
    ES_URL="${ES_URL:-http://127.0.0.1:9200}" \
    bash "$s"
}

cmd_revalidate_now() {
  local s="$SCRIPT_DIR/recon_restale.sh"
  [[ -f "$s" ]] || { echo "recon_restale.sh not found"; return 1; }
  echo "Re-queuing stale P0/P1 hosts into inbox..."
  bash "$s"
}

cmd_digest_now() {
  local s="$SCRIPT_DIR/recon_digest.sh"
  [[ -f "$s" ]] || { echo "recon_digest.sh not found"; return 1; }
  echo "Posting daily digest to #health channel..."
  bash "$s"
}

cmd_leads() {
  # Curated high-signal lead digest — read-only preview to stdout (no posting).
  bash "$SCRIPT_DIR/recon_digest_leads.sh" print
}

cmd_leads_post() {
  # Headless-Claude verification + post to #leads (deterministic fallback inside).
  bash "$SCRIPT_DIR/../tools/recon_leads_digest.sh"
}

# ---------------------------------------------------------------------------
# Screenshot module (Playwright + stealth)
# ---------------------------------------------------------------------------
SHOT_VENV="${SHOT_VENV:-$HOME/recon/venv/screenshot}"
SHOT_SCRIPT="${SHOT_SCRIPT:-$SCRIPT_DIR/recon_screenshot.sh}"
SHOT_DIR="${SHOT_DIR:-$BASE_DIR/screenshots}"

cmd_screenshot_install() {
  hdr "Screenshot module install"
  mkdir -p "$SHOT_DIR" "$HOME/recon/venv"
  if [[ ! -x "$SHOT_VENV/bin/python" ]]; then
    echo "Creating venv at $SHOT_VENV"
    python3 -m venv "$SHOT_VENV"
  fi
  "$SHOT_VENV/bin/pip" install --quiet --upgrade pip
  "$SHOT_VENV/bin/pip" install --quiet playwright playwright-stealth pillow
  echo "Installing chromium (one-time, ~120MB)..."
  "$SHOT_VENV/bin/playwright" install chromium 2>&1 | tail -5
  echo "Done. Smoke test: recon-screenshot-test example.com"
}

cmd_screenshot_now() {
  [[ -f "$SHOT_SCRIPT" ]] || { echo "recon_screenshot.sh not found"; return 1; }
  echo "Running one screenshot cycle..."
  bash "$SHOT_SCRIPT" cycle
}

cmd_screenshot_backfill() {
  [[ -f "$SHOT_SCRIPT" ]] || { echo "recon_screenshot.sh not found"; return 1; }
  local n="${1:-200}"
  echo "Backfilling up to $n hosts that have NO screenshot_at yet..."
  bash "$SHOT_SCRIPT" backfill "$n"
}

cmd_screenshot_test() {
  local host="${1:?usage: recon-screenshot-test <host>}"
  [[ -f "$SHOT_SCRIPT" ]] || { echo "recon_screenshot.sh not found"; return 1; }
  bash "$SHOT_SCRIPT" test "$host"
}

cmd_gallery() {
  [[ -f "$SHOT_SCRIPT" ]] || { echo "recon_screenshot.sh not found"; return 1; }
  bash "$SHOT_SCRIPT" gallery "${1:-1000}"
  local out="$SHOT_DIR/index.html"
  if [[ -f "$out" ]]; then
    echo "Gallery: $out"
    # WSL: explorer.exe opens with the Windows shell. Translate path if needed.
    if command -v wslpath >/dev/null 2>&1; then
      local winpath; winpath="$(wslpath -w "$out" 2>/dev/null || true)"
      [[ -n "$winpath" ]] && echo "Open with: explorer.exe '$winpath'"
    fi
  else
    echo "(gallery file not produced — check daemon log)"
  fi
}

cmd_screenshots() {
  local n="${1:-30}"
  hdr "Screenshots — top $n (from ES)"
  local resp
  resp="$(_es_search "{
    \"size\": $n,
    \"_source\": [\"host\",\"triage_priority\",\"triage_score\",\"triage_program\",
                  \"screenshot_status\",\"screenshot_at\",\"screenshot_title\",
                  \"screenshot_w\",\"screenshot_h\"],
    \"query\": {\"exists\":{\"field\":\"screenshot_at\"}},
    \"sort\": [{\"screenshot_at\":{\"order\":\"desc\"}}]
  }")"
  local total; total="$(printf '%s' "$resp" | jq -r '.hits.total.value // 0' 2>/dev/null)"
  if [[ "$total" -eq 0 ]]; then echo "  (no screenshots yet — run: recon-screenshot-backfill)"; return; fi
  printf '%-3s %-4s %-8s %-44s %-22s %s\n' "PRI" "SCR" "STATUS" "HOST" "PROGRAM" "TITLE"
  printf '%s\n' "$(printf '─%.0s' {1..130})"
  printf '%s' "$resp" | jq -r '
    .hits.hits[]._source |
    [
      (.triage_priority // "-"),
      ((.triage_score // 0) | tostring),
      (.screenshot_status // "?"),
      (.host // ""),
      (.triage_program // "-"),
      (.screenshot_title // "")
    ] | @tsv' 2>/dev/null \
  | while IFS=$'\t' read -r pri scr st host prog title; do
      printf '%-3s %-4s %-8s %-44s %-22s %s\n' \
        "$pri" "$scr" "$st" "${host:0:44}" "${prog:0:22}" "${title:0:55}"
    done
  echo
  printf "  showing: %s of %s screenshotted host(s)\n" \
    "$(printf '%s' "$resp" | jq -r '.hits.hits | length' 2>/dev/null)" "$total"
  printf "  tip: recon-gallery   open the HTML gallery in explorer\n"
}

# cmd_js — JS secrets + interesting endpoints from ES
# ---------------------------------------------------------------------------
cmd_js() {
  local n="${1:-50}"
  hdr "JS findings — secrets + endpoints (top $n, from ES)"
  local resp
  resp="$(_es_search "{
    \"size\": $n,
    \"_source\": [\"host\",\"url\",\"triage_priority\",\"triage_score\",\"triage_payout_tier\",
                  \"triage_program\",\"js_secret_hit\",\"js_endpoint_hit\",\"triage_true_fresh\"],
    \"query\": {\"bool\":{\"should\":[
      {\"term\":{\"js_secret_hit\":true}},
      {\"term\":{\"js_endpoint_hit\":true}}
    ],\"minimum_should_match\":1}},
    \"sort\": [
      {\"js_secret_hit\":{\"order\":\"desc\"}},
      {\"triage_score\":{\"order\":\"desc\",\"missing\":\"_last\"}}
    ]
  }")"
  local total; total="$(printf '%s' "$resp" | jq -r '.hits.total.value // 0' 2>/dev/null)"
  if [[ "$total" -eq 0 ]]; then echo "  (none)"; return; fi
  printf '%-3s %-8s %-9s %-52s %-22s %s\n' "PRI" "SECRETS" "ENDPTS" "HOST" "PROGRAM" "URL"
  printf '%s\n' "$(printf '─%.0s' {1..130})"
  printf '%s' "$resp" | jq -r '
    .hits.hits[]._source |
    [
      (.triage_priority // "-"),
      (if (.js_secret_hit // false) then "🔑 yes" else "no" end),
      (if (.js_endpoint_hit // false) then "🛤 yes" else "no" end),
      (.host // ""),
      (.triage_program // "-"),
      (.url // .host // "")
    ] | @tsv' 2>/dev/null \
  | while IFS=$'\t' read -r pri sec ep host prog url; do
      printf '%-3s %-8s %-9s %-52s %-22s %s\n' \
        "$pri" "$sec" "$ep" "${host:0:52}" "${prog:0:22}" "${url:0:70}"
    done
  echo
  printf "  showing: %s of %s JS-hit hosts\n" \
    "$(printf '%s' "$resp" | jq -r '.hits.hits | length' 2>/dev/null)" "$total"
}

# ---------------------------------------------------------------------------
# cmd_ignored — view ignored hosts (triage_ignored=true in ES)
# ---------------------------------------------------------------------------
cmd_ignored() {
  local n="${1:-50}"
  hdr "Ignored hosts — triage_ignored=true (top $n, from ES)"
  local resp
  resp="$(_es_search "{
    \"size\": $n,
    \"_source\": [\"host\",\"triage_ignored_reason\",\"triage_program\",\"triage_score\",\"triage_at\"],
    \"query\": {\"term\":{\"triage_ignored\":true}},
    \"sort\": [{\"triage_score\":{\"order\":\"desc\",\"missing\":\"_last\"}}]
  }")"
  local total; total="$(printf '%s' "$resp" | jq -r '.hits.total.value // 0' 2>/dev/null)"
  if [[ "$total" -eq 0 ]]; then echo "  (none)"; return; fi
  printf '%-52s %-22s %-6s %s\n' "HOST" "PROGRAM" "SCORE" "REASON"
  printf '%s\n' "$(printf '─%.0s' {1..120})"
  printf '%s' "$resp" | jq -r '
    .hits.hits[]._source |
    [.host, (.triage_program // "-"), ((.triage_score // 0) | tostring), (.triage_ignored_reason // "-")]
    | @tsv' 2>/dev/null \
  | while IFS=$'\t' read -r host prog score reason; do
      printf '%-52s %-22s %-6s %s\n' "${host:0:52}" "${prog:0:22}" "$score" "${reason:0:60}"
    done
  echo
  printf "  showing: %s of %s ignored hosts\n" \
    "$(printf '%s' "$resp" | jq -r '.hits.hits | length' 2>/dev/null)" "$total"
}

# ---------------------------------------------------------------------------
# cmd_fetch — universal ES data fetcher
# Build any query from flags — combine freely.
#
# Usage: recon_ctl fetch [flags] [N]
#   -p P0|P1|P2        priority tier (repeat for OR: -p P0 -p P1)
#   -t <tech>          technology name (repeat for OR, case-insensitive)
#   -P <prog>          program name contains (partial, case-insensitive)
#   --kev              KEV-matched hosts only
#   --js               JS secrets or endpoints only
#   --fresh            true-fresh hosts only
#   --pays             paying in-scope targets only
#   --ignored          show triage_ignored=true hosts (default: excluded)
#   --hosts            output hostnames only — for piping to nuclei/httpx/etc.
#   -o <file>          save results to file (auto-named if omitted)
#   --save             save to ~/recon/fetch/fetch_TIMESTAMP.txt
#   N                  result cap (default 100)
#
# Examples:
#   recon-fetch -p P0 --pays                        paying P0 targets
#   recon-fetch -t jenkins -t confluence --pays      Jenkins or Confluence, paying
#   recon-fetch --kev --pays --hosts                 KEV-matched paying hosts
#   recon-fetch --fresh -p P0 -p P1 --hosts          fresh P0/P1 host list
#   recon-fetch -P hackerone_program -t wordpress     wordpress on one program
#   recon-fetch --class takeover                     all hosts with triage_classes:takeover
#   recon-fetch --class takeover --class rce --pays  takeover OR rce, paying programs
#   recon-fetch --takeover                           confirmed takeovers (ES-tagged by hunter)
# ---------------------------------------------------------------------------
cmd_fetch() {
  local priorities=() techs=() classes=() program=""
  local kev=0 js=0 fresh=0 pays=0 show_ignored=0 takeover=0
  local hosts_only=0 save=0 outfile="" n=100

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -p)              priorities+=("$2"); shift 2 ;;
      -t)              techs+=("$2"); shift 2 ;;
      -c|--class)      classes+=("$2"); shift 2 ;;
      -P)              program="$2"; shift 2 ;;
      --kev)           kev=1; shift ;;
      --js)            js=1; shift ;;
      --fresh)         fresh=1; shift ;;
      --pays)          pays=1; shift ;;
      --ignored)       show_ignored=1; shift ;;
      --takeover)      takeover=1; shift ;;
      --hosts|-H)      hosts_only=1; shift ;;
      --save)          save=1; shift ;;
      -o|--out)        outfile="$2"; save=1; shift 2 ;;
      [0-9]*)          n="$1"; shift ;;
      *) shift ;;
    esac
  done

  # ── Build ES bool query ────────────────────────────────────────────────────
  local filters=() must_nots=()

  # Priority — OR between values
  if [[ ${#priorities[@]} -gt 0 ]]; then
    local pv; pv="$(printf '"%s",' "${priorities[@]}" | sed 's/,$//')"
    filters+=("{\"terms\":{\"triage_priority\":[$pv]}}")
  fi

  # Tech — OR across wildcard + signal hits for each tech
  if [[ ${#techs[@]} -gt 0 ]]; then
    local tshoulds=""
    for t in "${techs[@]}"; do
      local tl; tl="$(printf '%s' "$t" | tr '[:upper:]' '[:lower:]')"
      [[ -n "$tshoulds" ]] && tshoulds="$tshoulds,"
      tshoulds="${tshoulds}{\"wildcard\":{\"tech\":{\"value\":\"*${tl}*\",\"case_insensitive\":true}}},{\"term\":{\"triage_signals\":\"tech:${tl}\"}}"
    done
    filters+=("{\"bool\":{\"should\":[$tshoulds],\"minimum_should_match\":1}}")
  fi

  # Program partial match
  [[ -n "$program" ]] && filters+=("{\"wildcard\":{\"triage_program\":{\"value\":\"*${program}*\",\"case_insensitive\":true}}}")

  # Triage classes — OR between values (e.g. --class takeover --class rce)
  if [[ ${#classes[@]} -gt 0 ]]; then
    local cv; cv="$(printf '"%s",' "${classes[@]}" | sed 's/,$//')"
    filters+=("{\"terms\":{\"triage_classes\":[$cv]}}")
  fi

  # Boolean flags
  [[ "$kev"      -eq 1 ]] && filters+=("{\"term\":{\"triage_kev_match\":true}}")
  [[ "$js"       -eq 1 ]] && filters+=("{\"bool\":{\"should\":[{\"term\":{\"js_secret_hit\":true}},{\"term\":{\"js_endpoint_hit\":true}}],\"minimum_should_match\":1}}")
  [[ "$fresh"    -eq 1 ]] && filters+=("{\"term\":{\"triage_true_fresh\":true}}")
  [[ "$pays"     -eq 1 ]] && filters+=("{\"term\":{\"triage_pays\":true}},{\"term\":{\"triage_in_scope\":true}}")
  [[ "$takeover" -eq 1 ]] && filters+=("{\"term\":{\"takeover_confirmed\":true}}")

  # Ignored: include only if explicitly requested, otherwise exclude
  if [[ "$show_ignored" -eq 1 ]]; then
    filters+=("{\"term\":{\"triage_ignored\":true}}")
  else
    must_nots+=("{\"term\":{\"triage_ignored\":true}}")
  fi

  # Build query JSON
  local fs="" mns=""
  [[ ${#filters[@]}   -gt 0 ]] && fs="$(IFS=','; printf '%s' "${filters[*]}")"
  [[ ${#must_nots[@]} -gt 0 ]] && mns="$(IFS=','; printf '%s' "${must_nots[*]}")"

  local query
  if   [[ -z "$fs" && -z "$mns" ]]; then query='{"match_all":{}}'
  elif [[ -z "$mns"              ]]; then query="{\"bool\":{\"filter\":[$fs]}}"
  elif [[ -z "$fs"               ]]; then query="{\"bool\":{\"must_not\":[$mns]}}"
  else                                    query="{\"bool\":{\"filter\":[$fs],\"must_not\":[$mns]}}"
  fi

  local sort_clause='[{"triage_score":{"order":"desc","missing":"_last"}}]'

  local body; body="$(printf '{
    "size": %s,
    "_source": ["host","url","triage_priority","triage_score","triage_payout_tier",
                "triage_program","triage_classes","triage_signals","triage_true_fresh",
                "triage_kev_match","js_secret_hit","js_endpoint_hit",
                "triage_pays","triage_in_scope","tech","first_seen"],
    "query": %s,
    "sort": %s
  }' "$n" "$query" "$sort_clause")"

  local resp; resp="$(_es_search "$body")"
  local total; total="$(printf '%s' "$resp" | jq -r '.hits.total.value // 0' 2>/dev/null)"
  local shown; shown="$(printf '%s' "$resp" | jq -r '.hits.hits | length' 2>/dev/null)"

  # Build human-readable label for header / save filename
  local parts=()
  [[ ${#priorities[@]} -gt 0 ]] && parts+=("pri=$(IFS=,; printf '%s' "${priorities[*]}")")
  [[ ${#techs[@]}      -gt 0 ]] && parts+=("tech=$(IFS=,; printf '%s' "${techs[*]}")")
  [[ ${#classes[@]}    -gt 0 ]] && parts+=("class=$(IFS=,; printf '%s' "${classes[*]}")")
  [[ -n "$program"             ]] && parts+=("prog~$program")
  [[ "$kev"      -eq 1         ]] && parts+=("KEV")
  [[ "$js"       -eq 1         ]] && parts+=("JS")
  [[ "$fresh"    -eq 1         ]] && parts+=("fresh")
  [[ "$pays"     -eq 1         ]] && parts+=("pays")
  [[ "$takeover" -eq 1         ]] && parts+=("confirmed-takeovers")
  [[ "$show_ignored" -eq 1     ]] && parts+=("ignored")
  local label; label="$(IFS=' '; printf '%s' "${parts[*]}")"
  [[ -z "$label" ]] && label="all (no filters)"

  # ── hosts-only mode — for piping to nuclei / httpx / etc. ─────────────────
  if [[ "$hosts_only" -eq 1 ]]; then
    printf '%s' "$resp" | jq -r '.hits.hits[]._source.host' 2>/dev/null
    if [[ "$save" -eq 1 || -n "$outfile" ]]; then
      [[ -z "$outfile" ]] && outfile="$HOME/recon/fetch/fetch_$(date -u +%Y%m%dT%H%M%SZ)_hosts.txt"
      mkdir -p "$(dirname "$outfile")"
      printf '%s' "$resp" | jq -r '.hits.hits[]._source.host' 2>/dev/null > "$outfile"
      printf '# saved %s hosts → %s\n' "$shown" "$outfile" >&2
    fi
    return
  fi

  # ── table mode ────────────────────────────────────────────────────────────
  hdr "fetch: $label  ($shown of $total in ES)"

  local B='\033[1m' R='\033[0m' G='\033[0;32m' Y='\033[1;33m' RD='\033[0;31m'

  # Standard triage columns
  printf "${B}%-2s %-3s %-4s %-7s %-50s %-22s %-25s %s${R}\n" \
    "FL" "PRI" "SCR" "TIER" "HOST" "PROGRAM" "TECH" "CLASSES"
  printf '%s\n' "$(printf '─%.0s' {1..160})"
  printf '%s' "$resp" | jq -r '
    .hits.hits[]._source |
    [
      ([
        (if (.triage_true_fresh // false) then "⚡" else "" end),
        (if (.triage_kev_match // false) then "🎯" else "" end),
        (if (.js_secret_hit // false) then "🔑" else "" end)
      ] | map(select(length>0)) | join("")),
      (.triage_priority // "-"),
      ((.triage_score // 0) | tostring),
      (.triage_payout_tier // "-"),
      (.host // ""),
      (.triage_program // "-"),
      ((.tech // []) | .[0:3] | join(",")),
      ((.triage_classes // []) | map(select(. != "low-priority" and . != "low-signal")) | join(","))
    ] | @tsv' 2>/dev/null \
  | while IFS=$'\t' read -r fl pri scr tier host prog tech cls; do
      printf '%-2s %-3s %-4s %-7s %-50s %-22s %-25s %s\n' \
        "$fl" "$pri" "$scr" "$tier" "${host:0:50}" "${prog:0:22}" "${tech:0:25}" "$cls"
    done

  echo
  printf "  total matching in ES: %s  |  shown: %s  |  cap: %s\n" "$total" "$shown" "$n"
  printf "  tip: add --hosts to get a plain host list for piping\n"

  # ── Save to file ───────────────────────────────────────────────────────────
  if [[ "$save" -eq 1 || -n "$outfile" ]]; then
    local ts; ts="$(date -u +%Y%m%dT%H%M%SZ)"
    if [[ -z "$outfile" ]]; then
      local slug; slug="$(printf '%s' "$label" | tr ' =~≥,' '_____' | tr -cd '[:alnum:]_')"
      outfile="$HOME/recon/fetch/fetch_${slug}_${ts}.txt"
    fi
    mkdir -p "$(dirname "$outfile")"
    {
      printf '# recon-fetch  filters: %s  ts: %s  total_in_es: %s  shown: %s\n' \
        "$label" "$ts" "$total" "$shown"
      printf '%s' "$resp" | jq -r '
        .hits.hits[]._source |
        [(.triage_priority // "-"), ((.triage_score // 0) | tostring),
         (.triage_payout_tier // "-"), .host, (.triage_program // "-"), (.url // .host // "")]
        | @tsv' 2>/dev/null
      printf '\n# hosts only:\n'
      printf '%s' "$resp" | jq -r '.hits.hits[]._source.host' 2>/dev/null
    } > "$outfile"
    printf '  saved → %s\n' "$outfile"
  fi
}

# ---------------------------------------------------------------------------
# cmd_bulk — bulk scope discovery: enumerate ALL in-scope targets via subfinder
# then batch-queue them through the existing httpx → triage → ES pipeline.
#
# Usage: recon_ctl bulk [subcommand]
#   status              Show scope coverage vs ES counts
#   domains [--all]     List wildcard root domains that would be enumerated
#   run [--all] [--dry-run] [N]
#                       Subfinder on every paying wildcard, queue results
#                       --all       include non-paying programs too
#                       --dry-run   print domains, don't run
#                       N           limit to first N domains (test runs)
# ---------------------------------------------------------------------------
cmd_bulk() {
  local sub="${1:-status}"; shift || true
  local scope_f="$HOME/recon/scope/programs.json"

  # ── shared helpers to extract scope entries ──────────────────────────────
  # Wildcard root domains from *.root.tld entries — for subfinder
  _bulk_wildcard_roots() {
    local pays="$1"   # 1 = paying only, 0 = all
    jq -r --argjson pays "$pays" '
      .[] |
      select(if $pays == 1 then .pays == true else true end) |
      .in_scope[]? |
      select(type == "string") |
      select(startswith("*.")) |
      ltrimstr("*.") |
      select(contains("*") | not) |
      select(contains("█") | not) |
      select(split(".") | length >= 2)
    ' "$scope_f" 2>/dev/null | sort -u
  }

  # Direct hosts (specific subdomain or apex) — queue without subfinder
  _bulk_direct_hosts() {
    local pays="$1"
    jq -r --argjson pays "$pays" '
      .[] |
      select(if $pays == 1 then .pays == true else true end) |
      .in_scope[]? |
      select(type == "string") |
      select(startswith("*.") | not) |
      select(startswith("http") | not) |
      select(contains("*") | not) |
      select(contains("█") | not) |
      select(contains(" ") | not) |
      select(split(".") | length >= 2)
    ' "$scope_f" 2>/dev/null | sort -u
  }

  case "$sub" in

    status)
      hdr "Bulk discovery — scope vs ES coverage"
      if [[ ! -s "$scope_f" ]]; then
        echo "  scope DB missing — run: recon-v2 refresh-scope"
        return
      fi
      local n_prog n_pay n_wild n_direct
      n_prog="$(jq 'length' "$scope_f" 2>/dev/null || echo 0)"
      n_pay="$(jq '[.[] | select(.pays == true)] | length' "$scope_f" 2>/dev/null || echo 0)"
      n_wild="$(_bulk_wildcard_roots 1 | wc -l | tr -d ' ')"
      n_direct="$(_bulk_direct_hosts 1 | wc -l | tr -d ' ')"
      echo "  Scope DB:      $n_prog programs total, $n_pay paying"
      echo "  Wildcards:     $n_wild paying *.root.tld entries  (subfinder will enumerate)"
      echo "  Direct hosts:  $n_direct specific hosts  (queued directly → httpx → triage)"
      echo
      local es_total es_scope es_pays
      es_total="$(_es_count_q '{"match_all":{}}')"
      es_scope="$(_es_count_q '{"term":{"triage_in_scope":true}}')"
      es_pays="$(_es_count_q '{"bool":{"filter":[{"term":{"triage_pays":true}},{"term":{"triage_in_scope":true}}]}}')"
      echo "  ES: total=$es_total  in-scope=$es_scope  paying=$es_pays"
      echo
      echo "  To fill ES with all in-scope targets:"
      echo "    recon-bulk-dry          — preview what would run"
      echo "    recon-bulk-run          — run it (subfinder wildcards + queue direct hosts)"
      echo "    recon-bulk-run 10       — test: limit to first 10 wildcard domains"
      echo "    recon-bulk-run --threads 5   — lower RAM (default: 10 goroutines/domain)"
      ;;

    domains)
      [[ ! -s "$scope_f" ]] && { echo "scope DB missing"; return 1; }
      local pays_only=1
      [[ "${1:-}" == "--all" ]] && pays_only=0
      local label; label="$([ "$pays_only" -eq 1 ] && echo 'paying only' || echo 'all programs')"
      hdr "Wildcard root domains — subfinder targets ($label)"
      _bulk_wildcard_roots "$pays_only"
      echo
      hdr "Direct hosts — queued immediately ($label)"
      _bulk_direct_hosts "$pays_only" | head -20
      local nd; nd="$(_bulk_direct_hosts "$pays_only" | wc -l | tr -d ' ')"
      [[ "$nd" -gt 20 ]] && printf '  ... and %s more\n' "$(( nd - 20 ))"
      ;;

    run|discover)
      # Flags
      # --all        include non-paying programs
      # --dry-run    print domains, don't execute
      # --threads N  subfinder goroutine cap (default 10, low RAM)
      # --batch N    hosts per queue file (default 300)
      # N            max domains to enumerate (0 = all)
      local pays_only=1 dry_run=0 max_doms=0 sf_threads=10 batch_size=300
      while [[ $# -gt 0 ]]; do
        case "$1" in
          --all)         pays_only=0; shift ;;
          --dry-run)     dry_run=1; shift ;;
          --threads|-T)  sf_threads="$2"; shift 2 ;;
          --batch)       batch_size="$2"; shift 2 ;;
          [0-9]*)        max_doms="$1"; shift ;;
          *) shift ;;
        esac
      done

      hdr "Bulk discover — subfinder → queue inbox → httpx → triage → ES"
      [[ ! -s "$scope_f" ]] && { echo "scope DB missing — run: recon-v2 refresh-scope"; return 1; }
      command -v subfinder >/dev/null 2>&1 || { echo "subfinder not found in PATH"; return 1; }

      # Temp files — never buffer scope lists in bash variables
      local domains_file; domains_file="$(mktemp)"
      local direct_file;  direct_file="$(mktemp)"
      local sub_tmp;      sub_tmp="$(mktemp)"
      _bulk_wildcard_roots "$pays_only" > "$domains_file"
      _bulk_direct_hosts   "$pays_only" > "$direct_file"

      local total_d; total_d="$(wc -l < "$domains_file" | tr -d ' ')"
      local total_h; total_h="$(wc -l < "$direct_file"  | tr -d ' ')"
      if [[ "$max_doms" -gt 0 && "$total_d" -gt "$max_doms" ]]; then
        local trimmed; trimmed="$(mktemp)"
        head -"$max_doms" "$domains_file" > "$trimmed"
        mv "$trimmed" "$domains_file"
        total_d="$max_doms"
      fi

      printf "  Mode:             %s\n" "$([ "$pays_only" -eq 1 ] && echo 'paying in-scope only (--all for everything)' || echo 'all programs')"
      printf "  Wildcard domains: %s  (subfinder enumerate)\n" "$total_d"
      printf "  Direct hosts:     %s  (queued immediately)\n" "$total_h"
      printf "  Threads/domain:   %s  (--threads N to tune; higher = faster, more RAM)\n" "$sf_threads"
      printf "  Batch size:       %s hosts per queue file\n" "$batch_size"

      if [[ "$dry_run" -eq 1 ]]; then
        echo
        echo "  [DRY RUN] wildcard domains — would subfinder:"
        head -15 "$domains_file" | sed 's/^/    /'
        [[ "$total_d" -gt 15 ]] && printf '    ... and %s more\n' "$(( total_d - 15 ))"
        echo
        echo "  [DRY RUN] direct hosts — would queue immediately (sample):"
        head -10 "$direct_file" | sed 's/^/    /'
        [[ "$total_h" -gt 10 ]] && printf '    ... and %s more\n' "$(( total_h - 10 ))"
        rm -f "$domains_file" "$direct_file" "$sub_tmp"
        echo
        echo "  Remove --dry-run to execute."
        return
      fi

      echo
      printf "  RAM note: one domain at a time, output streamed to disk — not held in memory.\n"
      printf "  If RAM climbs, use --threads 5 (default: %s).\n\n" "$sf_threads"

      # ── Resume support ──────────────────────────────────────────────────────
      # BULK_RESUME_FILE tracks completed domains. If it exists on startup,
      # domains already listed are skipped — bulk continues from where it left
      # off. Deleted only on clean exit so crashes/stops are always resumable.
      local BULK_RESUME_FILE="$STATE_DIR/bulk_resume.txt"
      local skipped=0
      declare -A _bulk_done=()
      if [[ -f "$BULK_RESUME_FILE" ]]; then
        while IFS= read -r _d; do
          [[ -n "$_d" ]] && _bulk_done["$_d"]=1
        done < "$BULK_RESUME_FILE"
        skipped="${#_bulk_done[@]}"
        printf "  Resuming — skipping %s already-completed domains.\n\n" "$skipped"
      fi

      local ts; ts="$(date -u +%Y%m%dT%H%M%SZ)"
      local batch_n=0 found=0 queued=0 dom_n=0
      local KNOWN="${KNOWN_HOSTS:-$STATE_DIR/known_hosts.txt}"   # 4M-host ever-seen ledger (has NUL → grep -a)
      local all_hosts; all_hosts="$(mktemp)"                     # collect ALL discovered → dedup once, at end
      mkdir -p "$QUEUE_DIR/inbox"

      # Collect every discovered host to ONE file (streamed to disk, not memory). Dedup
      # against the ever-seen ledger + split into batches happens once, after discovery —
      # so already-seen hosts never re-flood the validator (see the finalize block below).
      _bulk_write_host() {
        local h="$1"
        [[ -z "$h" ]] && return
        printf '%s\n' "$h" >> "$all_hosts"
      }

      # ── Phase 1: queue direct hosts immediately (no subfinder) ─────────────
      if [[ "$total_h" -gt 0 ]]; then
        printf "  Queueing %s direct hosts...\n" "$total_h"
        while IFS= read -r h; do
          _bulk_write_host "$h"
        done < "$direct_file"
        printf "  Direct hosts queued.\n\n"
      fi

      # ── Phase 2: subfinder on each wildcard root domain ─────────────────────
      if [[ "$total_d" -gt 0 ]]; then
        printf "  Running subfinder on %s wildcard domains...\n" "$total_d"
        while IFS= read -r domain; do
          [[ -z "$domain" ]] && continue
          dom_n=$(( dom_n + 1 ))

          # Resume: skip domains already completed in a prior run
          if [[ -n "${_bulk_done[$domain]+_}" ]]; then
            printf "  [%s/%s] %-44s SKIP (already done)\n" "$dom_n" "$total_d" "$domain"
            continue
          fi

          printf "  [%s/%s] %-44s " "$dom_n" "$total_d" "$domain"

          # Stream subfinder to disk — never hold output in a bash variable
          : > "$sub_tmp"
          subfinder -d "$domain" -all -silent -timeout 60 -t "$sf_threads" \
            2>/dev/null > "$sub_tmp" || true

          local n_d; n_d="$(wc -l < "$sub_tmp" | tr -d ' ')"
          printf "%s subdomains\n" "$n_d"
          found=$(( found + n_d ))

          while IFS= read -r h; do
            _bulk_write_host "$h"
          done < "$sub_tmp"

          : > "$sub_tmp"  # free disk between domains

          # Mark domain done for resume
          printf '%s\n' "$domain" >> "$BULK_RESUME_FILE"
        done < "$domains_file"
      fi

      rm -f "$domains_file" "$direct_file" "$sub_tmp"
      # Clean exit — delete resume file so next run starts fresh
      rm -f "$BULK_RESUME_FILE"

      # ── Finalize: dedup against the ever-seen ledger, queue only NEW hosts ──────────
      # Each weekly bulk re-enumerates the SAME roots → ~2.5M mostly-already-seen
      # subdomains. Without this dedup they re-flood the validator faster than it drains
      # (4 weekly dumps had stacked to 21k+ batch files). Same doctrine as permute/uncover/
      # true_fresh: only hosts NOT in known_hosts.txt reach the queue. grep -a: ledger has NUL.
      local disc_u new_hosts seen_sorted skipped_seen=0
      new_hosts="$(mktemp)"; seen_sorted="$(mktemp)"
      LC_ALL=C sort -u "$all_hosts" -o "$all_hosts"
      disc_u="$(wc -l < "$all_hosts" | tr -d ' ')"
      if [[ -s "$KNOWN" ]]; then
        # The ledger uses NUL as a record separator in places → split (not delete) so NUL-joined
        # hostnames dedup correctly; sort -u to a clean set; comm keeps only NOT-yet-seen hosts.
        # comm needs both inputs identically sorted → LC_ALL=C on both. Bounded RAM (sort spills).
        tr '\0' '\n' < "$KNOWN" | LC_ALL=C sort -u > "$seen_sorted"
        LC_ALL=C comm -23 "$all_hosts" "$seen_sorted" > "$new_hosts"
      else
        cp "$all_hosts" "$new_hosts"
      fi
      queued="$(wc -l < "$new_hosts" | tr -d ' ')"
      skipped_seen=$(( disc_u - queued ))

      # Split NEW hosts into FIFO batch files (zero-padded suffix → correct lexical sort).
      if [[ "$queued" -gt 0 ]]; then
        split -l "$batch_size" -d -a 6 --additional-suffix=.txt \
          "$new_hosts" "$QUEUE_DIR/inbox/bulk_${ts}_"
        batch_n="$(find "$QUEUE_DIR/inbox" -maxdepth 1 -name "bulk_${ts}_*.txt" 2>/dev/null | wc -l | tr -d ' ')"
      fi
      rm -f "$all_hosts" "$new_hosts" "$seen_sorted"

      echo
      printf "  ── Done ────────────────────────────────────────────────────\n"
      printf "  Wildcard domains enumerated: %s  (skipped: %s already done)\n" "$dom_n" "$skipped"
      printf "  Subdomains discovered:       %s (raw)\n" "$found"
      printf "  Unique hosts discovered:     %s\n" "$disc_u"
      printf "  Already-seen (deduped out):  %s\n" "$skipped_seen"
      printf "  NEW hosts queued:            %s  (in %s batch files)\n" "$queued" "$batch_n"
      printf "  Queue inbox:                 %s\n" "$QUEUE_DIR/inbox"
      echo
      printf "  Daemon will probe + triage all of these automatically.\n"
      printf "  Watch with:  recon-queue   recon-status   recon-logs\n"
      ;;

    *)
      echo "recon-bulk subcommands:"
      echo "  status              Scope coverage vs ES host counts"
      echo "  domains [--all]     List domains/hosts that would be processed"
      echo "  run [opts]          Subfinder wildcards + queue direct hosts → ES"
      echo "    --all             Include non-paying programs"
      echo "    --dry-run         Preview without executing"
      echo "    --threads N       Subfinder goroutines (default 10, lower = less RAM)"
      echo "    --batch N         Queue batch file size (default 300)"
      echo "    N                 Limit to first N wildcard domains (for testing)"
      ;;
  esac
}

cmd_vuln() {
  local sub="${1:-status}"
  case "$sub" in
    refresh)
      bash "$(script_path recon_vuln_feed.sh)" all
      ;;
    status)
      hdr "Vuln intelligence"
      if [[ -f "$(script_path recon_vuln_feed.sh)" ]]; then
        bash "$(script_path recon_vuln_feed.sh)" status
      else
        echo "  recon_vuln_feed.sh missing"
      fi
      ;;
    top)
      hdr "Top passive vuln-to-asset matches"
      local f="$VULN_DIR/vuln_targets.jsonl"
      [[ ! -s "$f" ]] && { echo "  none yet"; return; }
      jq -r '[.best_vuln_tier,.best_vuln_id,(.triage_payout_tier // "none"),(.triage_score // 0),.host,.matched_signal] | @tsv' "$f" 2>/dev/null | head -30
      ;;
    *)
      echo "Usage: recon_ctl vuln [status|refresh|top]"
      return 1
      ;;
  esac
}

cmd_ignore() {
  local host="${1:-}"; shift || true
  local reason="${*:-manual}"
  if [[ -z "$host" ]]; then echo "Usage: recon_ctl ignore <host> [reason...]"; return 1; fi
  local ig_file="$HOME/recon/state/ignored.jsonl"
  mkdir -p "$(dirname "$ig_file")"
  local who; who="$(id -un 2>/dev/null || echo unknown)"
  local now; now="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  local expires; expires="$(date -u -d '+7 days' '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo "$now")"
  jq -nc --arg host "$host" --arg reason "$reason" --arg added_by "$who" \
         --arg added_at "$now" --arg expires_at "$expires" \
    '{host:$host, reason:$reason, added_by:$added_by, added_at:$added_at, expires_at:$expires_at}' \
    >> "$ig_file"
  # ADDITIVE: persist the WHY as a permanent (non-expiring) note when a real reason was given.
  # The 7d TTL above is untouched; "manual" (no reason) carries no signal -> no note.
  if [[ "$reason" != "manual" ]]; then
    note_add "$host" "$reason" "ignore" "$now" >/dev/null 2>&1 || true
  fi
  # mirror the bench state into ES (source of truth) — best-effort
  es_ignore_push "$host" "$reason" "$now" "$expires" 2>/dev/null || true
  echo "Ignored $host (7 days)  — $reason"
}

cmd_note() {
  # recon-note <host>            -> print all notes for host + its root_domain, newest first
  # recon-note <host> "<text>"   -> add a permanent manual note (source="manual")
  local host="${1:-}"; shift || true
  local text="${*:-}"
  if [[ -z "$host" ]]; then echo 'Usage: recon-note <host> ["note text"]'; return 1; fi
  if [[ -n "$text" ]]; then
    if note_add "$host" "$text" "manual"; then echo "📝 noted: $host"; else echo "note failed (jq missing?)"; return 1; fi
    return 0
  fi
  local rows; rows="$(note_get "$host")"
  if [[ -z "$rows" ]]; then echo "  (no notes for $host)"; return 0; fi
  hdr "📝 Notes — $host"
  printf '%s\n' "$rows" | jq -r '"  [\(.created_at[0:10])] (\(.source))" + (if .program then " ["+.program+"]" else "" end) + " " + .note'
}

cmd_fp() {
  local host="${1:-}" tmpl="${2:-}"
  if [[ -z "$host" || -z "$tmpl" ]]; then echo "Usage: recon_ctl fp <host> <template_id>"; return 1; fi
  local fp_file="$HOME/recon/nuclei/fp/known_fp.txt"
  mkdir -p "$(dirname "$fp_file")"
  echo "${host}|${tmpl}" >> "$fp_file"
  sort -u "$fp_file" -o "$fp_file"
  echo "Added to FP list"
}

cmd_v2() {
  local sub="${1:-status}"; shift || true
  case "$sub" in
    status)
      hdr "V2 modules"
      for k in v2_scope v2_cve v2_vuln_feed v2_nuclei v2_cloudrecon v2_dast v2_params v2_blindxss v2_permute v2_kr v2_uncover v2_ai_hunter v2_cognito; do
        if [[ -f "$V21_KILL_DIR/$k" ]]; then
          printf "  [0;31mDISABLED[0m %s — %s
" "$k" "$(cat "$V21_KILL_DIR/$k")"
        else
          printf "  [0;32mactive[0m %s
" "$k"
        fi
      done
      echo
      hdr "V2 data"
      for f in "scope/programs.json" "cve/kev.json" "cve/tech_cve_map.json" "cve/kev_targets.jsonl" "vuln/vuln_feed.jsonl" "vuln/vuln_targets.jsonl"; do
        local p="$HOME/recon/$f"
        if [[ -f "$p" ]]; then
          local h=$(( ($(date +%s) - $(stat -c %Y "$p")) / 3600 ))
          printf "  %-30s %dh old
" "$f" "$h"
        else
          printf "  %-30s missing
" "$f"
        fi
      done
      ;;
    enable)
      local mod="${1:-}"; [[ -z "$mod" ]] && { echo "Usage: recon_ctl v2 enable {scope|cve|vuln_feed|nuclei}"; return 1; }
      rm -f "$V21_KILL_DIR/v2_$mod"; echo "$mod re-enabled"
      ;;
    disable)
      local mod="${1:-}"; shift || true
      [[ -z "$mod" ]] && { echo "Usage: recon_ctl v2 disable {scope|cve|vuln_feed|nuclei} [reason]"; return 1; }
      mkdir -p "$V21_KILL_DIR"
      echo "${*:-manual}" > "$V21_KILL_DIR/v2_$mod"; echo "$mod disabled"
      ;;
    refresh-scope) bash "$(script_path recon_scope_db.sh)" ;;
    refresh-cve)   bash "$(script_path recon_cve_intel.sh)" all ;;
    refresh-vuln)  bash "$(script_path recon_vuln_feed.sh)" all ;;
    scan-now)      bash "$(script_path recon_nuclei.sh)" ;;
    *)
      echo "v2 subcommands: status | enable <mod> | disable <mod> [reason] | refresh-scope | refresh-cve | refresh-vuln | scan-now"
      ;;
  esac
}

cmd_inspect() {
  local host="${1:-}"
  if [[ -z "$host" ]]; then echo "Usage: recon_ctl inspect <host>"; return 1; fi
  bash "$(script_path recon_inspect.sh)" "$host"
}

usage() {
  # Alias-centric help — shown by recon-help
  local B='\033[1m' C='\033[1;36m' Y='\033[1;33m' G='\033[0;32m' R='\033[0m'
  printf "${C}recon-help — alias quick reference${R}\n\n"

  printf "${B}── DAEMON ──────────────────────────────────────────────────────────${R}\n"
  printf "  ${G}recon-start${R}                    Launch the pipeline daemon\n"
  printf "  ${G}recon-stop${R}                     Stop daemon + all child processes\n"
  printf "  ${G}recon-status${R}                   Daemon, queue, ES and firstblood summary\n"
  printf "  ${G}recon-logs${R}                     Live tail of daemon log\n"
  printf "  ${G}recon-health${R}                   Tool versions and module status\n"
  printf "  ${G}recon-queue${R}                    Queue depth per lane\n"
  printf "  ${G}recon-space${R}                    Disk usage breakdown\n\n"

  printf "${B}── RATE ────────────────────────────────────────────────────────────${R}\n"
  printf "  ${G}recon-rate${R} [preset|N M]        Show or set live scan rate (no restart)\n"
  printf "             presets: light easy medium full reset\n"
  printf "             raw:     recon-rate 80 60\n"
  printf "  ${G}recon-boost${R}                    Rate: full  (150t / 100 rps)\n"
  printf "  ${G}recon-browse${R}                   Rate: light  (30t / 20 rps)\n\n"

  printf "${B}── FETCH (universal ES query — combine any filters) ────────────────${R}\n"
  printf "  ${G}recon-fetch${R} [flags] [N]         Pull any slice of ES data into a table\n"
  printf "    Flags (all optional, combine freely):\n"
  printf "      ${Y}-p P0${R}              priority tier (repeat: -p P0 -p P1)\n"
  printf "      ${Y}-t jenkins${R}         technology (repeat for OR, case-insensitive)
      ${Y}-c takeover${R}        triage class (repeat for OR: -c takeover -c rce)\n"
  printf "      ${Y}-P hackerone_prog${R}  program name contains (partial match)\n"
  printf "      ${Y}--kev${R}              KEV-matched hosts only\n"
  printf "      ${Y}--js${R}               JS secrets or endpoints only\n"
  printf "      ${Y}--fresh${R}            true-fresh hosts only\n"
  printf "      ${Y}--pays${R}             paying in-scope only\n"
  printf "      ${Y}--ignored${R}          show ignored hosts\n"
  printf "      ${Y}--hosts${R}            output hostnames only (pipe to nuclei/httpx)\n"
  printf "      ${Y}-o <file>  --save${R}  save results to file\n"
  printf "    Examples:\n"
  printf "      recon-fetch -p P0 --pays\n"
  printf "      recon-fetch -t jenkins -t confluence --pays\n"
  printf "      recon-fetch --fresh -p P0 -p P1 --hosts\n"
  printf "      recon-fetch --kev --pays --hosts\n"
  printf "      recon-fetch --class takeover --pays\n"
  printf "      recon-fetch --takeover --hosts\n\n"

  printf "${B}── TARGETS ─────────────────────────────────────────────────────────${R}\n"
  printf "  ${G}recon-top${R} [N]                  Top N triage leads (default 15)\n"
  printf "  ${G}recon-fresh${R} [--new] [--save] [--all|N] [--out <file>]\n"
  printf "                             True-fresh P0/P1 in-scope targets from ES\n"
  printf "    ${Y}recon-fresh-new${R}              Only hosts not seen in a previous query\n"
  printf "    ${Y}recon-fresh-save${R}             Top 50, auto-saved to ~/recon/fresh/\n"
  printf "    ${Y}recon-fresh-all${R}              All true-fresh P0/P1 (no cap)\n"
  printf "  ${G}recon-tech${R} <name[,name2]> [--apex] [--pays] [--no-save] [--out <file>] [N]\n"
  printf "                             All hosts matching technology (always saves)\n"
  printf "             --apex         Root domains only (no subdomains)\n"
  printf "             --pays         In-scope paying targets only\n"
  printf "             --out <file>   Save to specific file\n"
  printf "             e.g.  recon-tech wordpress --apex --pays\n"
  printf "                   recon-tech \"F5 BigIP\" --out ~/Desktop/f5.txt\n"
  printf "                   recon-tech nginx,apache 50\n"
  printf "  ${G}recon-kev${R}                      KEV-matched targets in your data\n"
  printf "  ${G}recon-js${R} [N]                   JS secrets + interesting endpoints (ES)\n"
  printf "  ${G}recon-ignored${R} [N]               Ignored hosts (triage_ignored=true in ES)\n"
  printf "  ${G}recon-confirmed${R}                Latest confirmed nuclei findings\n"
  printf "  ${G}recon-vuln${R} [status|top|refresh] Passive vuln intelligence queue\n\n"

  printf "${B}── BULK DISCOVERY (enumerate all in-scope targets) ──────────────────${R}\n"
  printf "  ${G}recon-bulk${R}                     Scope coverage vs ES host counts\n"
  printf "  ${G}recon-bulk-dry${R}                 Preview: list domains that would be enumerated\n"
  printf "  ${G}recon-bulk-run${R} [opts]           Subfinder all paying wildcards → queue → ES\n"
  printf "             --all          Include non-paying programs too\n"
  printf "             --threads N    Subfinder goroutines per domain (default 10, low RAM)\n"
  printf "             --batch N      Hosts per queue batch file (default 300)\n"
  printf "             N              Limit to first N domains (for test runs)\n"
  printf "             e.g.  recon-bulk-run --dry-run\n"
  printf "                   recon-bulk-run 5          (test: first 5 domains)\n"
  printf "                   recon-bulk-run             (full run, all paying wildcards)\n"
  printf "                   recon-bulk-run --threads 5 (lower RAM mode)\n\n"

  printf "${B}── SCOPE ───────────────────────────────────────────────────────────${R}\n"
  printf "  ${G}recon-scope${R} <host>             Check host against all program scopes\n"
  printf "  ${G}recon-verify${R} list|<#>|<host>   Claude-verify a digest lead (safe unauth probes, FP-kill)\n"
  printf "  ${G}recon-programs${R}                 Program summary from scope DB\n"
  printf "  ${G}recon-params${R} <class> [N]       Sus-params catalog by vuln class\n"
  printf "             classes: sqli xss ssrf lfi ssti cmdi debug rce redirect idor img-traversal\n"
  printf "  ${G}recon-params candidates${R} [--class xss|sqli|both]  Ranked dup-proof XSS/SQLi worklist (rs0n lane)\n"
  printf "  ${G}recon-params crawl-host${R} <host> [url] [--cookie/--header]  On-demand crawl ONE host NOW (queue-bypass; --cookie=AUTHED)\n"
  printf "  ${G}recon-params arjun${R} <host> [url]   crawl-host + ACTIVE hidden-param discovery (arjun; polite, live traffic, on-demand)\n"
  printf "  ${G}recon-params confirm${R} <xss|sqli> [host] [N] [--cookie/--header]  Confirm — xss=dalfox(executes) sqli=SAFE %s vs %s; --cookie=AUTHED(own session)\n" "'" "''"
  printf "  ${G}recon-mood${R} <mood> [--top N]    Hunt-by-mood worklist: xss/sqli/api/wordpress/php/jira/… (recon-mood --list)\n"
  printf "  ${G}recon-buckets${R} [scan|check <b> [prov]|writecheck <b> [region]|results]  Cloud-bucket exposure (S3Scanner; provenance-seeded, read-only)\n"
  printf "  ${G}recon-graphql${R} [scan|check <url>|results]  GraphQL schema→worklist (read-only introspection; sensitive ops + IDOR/injectable args)\n"
  printf "  ${G}recon-wcd${R} [scan|confirm <host>|purge <host>|results]   Web-cache deception/poisoning LEADs (detect-only) + Varnish unauth-PURGE confirm\n"
  printf "  ${G}recon-blindxss${R} [status|test <host>|collector|correlate|plant]  Blind/stored-XSS lane (persistent interactsh + XSS Hunter; fires days later → gated #review)\n"
  printf "  ${G}recon-research${R} <tooling|vulns|kb-enrich|detect-tune|all>  Claude research routine → digest + KB (auto-commit; keeps the system updated)\n"
  printf "  ${G}recon-research program <name>${R}                           On-demand pre-hunt brief: disclosed reports, tech stack, top attack classes for a specific target\n"
  printf "  ${G}recon-account${R} create <name> --url <signup> --platform <bc|h1|ywh|gmail> [--label a]  Semi-auto test-account provisioner (you solve CAPTCHA+submit)\n\n"

  printf "${B}── PORT SCAN ────────────────────────────────────────────────────────${R}\n"
  printf "  ${G}recon-ports${R} [N]               All hosts with open non-standard ports (from ES)\n"
  printf "  ${G}recon-exposed${R}                 Critical-only: Docker/Redis/MongoDB/K8s/etcd exposed\n"
  printf "  ${G}recon-portscan${R}                Trigger a port scan cycle now (daemon runs every 90m)\n\n"

  printf "${B}── TAKEOVERS ───────────────────────────────────────────────────────${R}\n"
  printf "  ${G}recon-takeovers${R}                ES-confirmed + claim file (deduped by CNAME target)\n"
  printf "  ${G}recon-watching${R}                 Medium-confidence watch queue with age + provider breakdown\n"
  printf "  ${G}recon-takeover-check${R} <host>    Manual single-host probe (bypasses SEEN dedup)\n"
  printf "  ${G}recon-takeover-dedup${R}           Unique CNAME targets — one row = one real opportunity\n\n"

  printf "${B}── ACTIONS ─────────────────────────────────────────────────────────${R}\n"
  printf "  ${G}recon-submit${R} <host> <class>    Log a submission (dampens future scoring)\n"
  printf "  ${G}recon-ignore${R} <host> [reason]   Penalise host in triage for 7 days\n"
  printf "  ${G}recon-fp${R} <host> <template>     Mark nuclei finding as false positive\n"
  printf "  ${G}recon-inspect${R} <host>           Full triage view: ES + scope + KEV + probe\n"
  printf "  ${G}recon-dupes${R} [pattern]          Submission history (filter by host pattern)\n"
  printf "  ${G}recon-ai${R}                       AI review layer status + packet counts\n\n"

  printf "${B}── FIRST-BLOOD: enumerate ALL bug bounty targets ───────────────────────${R}\n"
  printf "  Sources integrated (auto-refresh, no action needed):\n"
  printf "    ${Y}Chaos${R}     projectdiscovery.io/chaos — refreshed every 4h\n"
  printf "    ${Y}arkadiyt${R}  github.com/arkadiyt/bounty-targets-data — every 6h\n"
  printf "              HackerOne + Bugcrowd + Intigriti + YesWeHack scopes\n"
  printf "    ${Y}subfinder${R} passive multi-source — every 12h, paying targets first\n"
  printf "    ${Y}CT logs${R}   gungnir real-time cert transparency — ≤15 min detection\n"
  printf "\n  Full one-shot sweep of ALL programs NOW:\n"
  printf "    ${G}recon-v2 refresh-scope${R}               Pull latest scope from BB platforms\n"
  printf "    ${G}recon-bulk-run${R}                       Subfinder all paying wildcards → ES\n"
  printf "    ${G}recon-bulk-run --all${R}                 Include non-paying / VDP programs\n"
  printf "    ${G}recon-bulk-run --all --threads 5${R}     Low-RAM mode\n"
  printf "\n  Detection latency (daemon must be running):\n"
  printf "    New cert in CT log  → ES:  ≤15 min  (gungnir → true_fresh)\n"
  printf "    Chaos/arkadiyt push → ES:  ≤4-6h    (discovery cycle)\n"
  printf "    Subfinder paying    → ES:  ≤12h     (discovery cycle)\n"
  printf "    Takeover confirmed  → alert: ≤30s after discovery\n\n"

  printf "${B}── MAINTENANCE ─────────────────────────────────────────────────────────${R}\n"
  printf "  ${G}recon-up${R}                        Start ES (Windows Docker) + daemon together\n"
  printf "  ${G}recon-es-start${R}                  Start Elasticsearch (Windows Docker Desktop)\n"
  printf "  ${G}recon-es-stop${R}                   Stop Elasticsearch\n"
  printf "  ${G}recon-es-status${R}                 ES health + doc count\n"
  printf "  ${G}recon-vpn${R}                       Check Mullvad VPN exit\n"
  printf "  ${G}recon-clean${R}                     Archive stale spool + old done/ files\n"
  printf "  ${G}recon-view${R}                      Full live pipeline dashboard\n"
  printf "  ${G}recon-v2${R} <subcmd>               V2 module control\n"
  printf "             status                  Module health overview\n"
  printf "             enable/disable <mod>    scope|cve|vuln_feed|nuclei|cloudrecon|dast|params\n"
  printf "             refresh-scope/cve/vuln  Run a module pass now\n"
  printf "             scan-now                Run nuclei pass immediately\n\n"

  printf "${B}── SPEED TIPS (stop being scooped) ─────────────────────────────────────${R}\n"
  printf "  • Keep daemon running 24/7 — CT path is ≤15 min when up\n"
  printf "  • ${G}recon-fresh-new${R}  — first thing every session (new P0/P1 since last look)\n"
  printf "  • ${G}recon-takeovers${R}  — check claim file; act immediately on HIGH/CRITICAL\n"
  printf "  • ${G}recon-boost${R}      — full scan rate during active hunting sessions\n"
  printf "  • Run ${G}recon-bulk-run${R} weekly to re-enumerate all paying wildcards from scratch\n"
  printf "  • ${G}recon-ai top${R}     — highest AI-scored leads right now\n\n"
}

case "${1:-}" in
  start)        cmd_start ;;
  stop)         cmd_stop ;;
  verify|v)     shift; bash "$(script_path recon_verify_host.sh)" "$@" ;;
  maintenance|maint) shift; cmd_maintenance "$@" ;;
  status|st)    cmd_status ;;
  rate)         shift; cmd_rate "$@" ;;
  queue|q)      cmd_queue ;;
  logs)         shift; cmd_logs "$@" ;;
  top)          shift; cmd_top "$@" ;;
  takeovers|to) shift; cmd_takeovers "$@" ;;
  watching|w)   cmd_watching ;;
  takeover-check|tc) shift; cmd_takeover_check "$@" ;;
  takeover-dedup|tdd) bash "$(script_path recon_takeover_hunter.sh)" dedup ;;
  dupes)        shift; cmd_dupes "$@" ;;
  submit)       shift; cmd_submit "$@" ;;
  health)       cmd_health ;;
  space)        cmd_space ;;
  clean)        cmd_clean ;;
  clean-start)  shift; cmd_clean_start "$@" ;;
  reset-queue)  cmd_reset_queue ;;
  ""|-h|--help|help) usage ;;
  kev)          cmd_kev ;;
  scope)        shift; cmd_scope "$@" ;;
  programs)     cmd_programs ;;
  confirmed)    cmd_confirmed ;;
  vuln)         shift; cmd_vuln "$@" ;;
  fresh)        shift; cmd_fresh "$@" ;;
  tech)         shift; cmd_tech "$@" ;;
  params)
    shift
    case "${1:-}" in
      "")       bash "$SCRIPT_DIR/recon_params.sh" list ;;
      list)     shift; bash "$SCRIPT_DIR/recon_params.sh" list "$@" ;;
      enqueue)  sudo -n -u reconrun env HOME="$HOME" BASE_DIR="$BASE_DIR" bash "$SCRIPT_DIR/recon_params.sh" enqueue ;;
      crawl)    sudo -n -u reconrun env HOME="$HOME" BASE_DIR="$BASE_DIR" bash "$SCRIPT_DIR/recon_params.sh" crawl ;;
      crawl-host) shift  # on-demand single-host crawl — queue bypass for the hunt
                sudo -n -u reconrun env HOME="$HOME" BASE_DIR="$BASE_DIR" bash "$SCRIPT_DIR/recon_params.sh" crawl-host "$@" ;;
      arjun)    shift  # crawl-host + ACTIVE hidden-param discovery (arjun; live traffic, on-demand)
                sudo -n -u reconrun env HOME="$HOME" BASE_DIR="$BASE_DIR" bash "$SCRIPT_DIR/recon_params.sh" arjun "$@" ;;
      collect)  # manual one-shot: refill the queue then crawl a single job
                sudo -n -u reconrun env HOME="$HOME" BASE_DIR="$BASE_DIR" bash "$SCRIPT_DIR/recon_params.sh" enqueue
                sudo -n -u reconrun env HOME="$HOME" BASE_DIR="$BASE_DIR" bash "$SCRIPT_DIR/recon_params.sh" crawl ;;
      candidates) shift; bash "$SCRIPT_DIR/recon_params.sh" candidates "$@" ;;
      confirm|verify) shift; sudo -n -u reconrun env HOME="$HOME" BASE_DIR="$BASE_DIR" bash "$SCRIPT_DIR/recon_params.sh" confirm "$@" ;;
      *)        bash "$SCRIPT_DIR/recon_params.sh" list "$@" ;;
    esac
    ;;
  mood)         shift; python3 "$SCRIPT_DIR/recon_mood.py" "$@" ;;
  targets)      # Under-Hunted Target Board: ranked program-selection menu + auto-onboard.
                # Pure data (no target traffic) → runs as d0k. default = show the board.
                shift; bash "$SCRIPT_DIR/recon_targets.sh" "${@:-show}" ;;
  buckets)      # cloud-bucket exposure (S3Scanner). target-facing → reconrun (Mullvad egress);
                # default = one scan cycle. check/writecheck/results/seed pass through.
                shift
                sudo -n -u reconrun env HOME="$HOME" BASE_DIR="$BASE_DIR" \
                  bash "$SCRIPT_DIR/recon_bucket_scanner.sh" "${@:-scan}" ;;
  graphql|gql)  # GraphQL schema→worklist lane (read-only introspection). target-facing → reconrun.
                shift
                sudo -n -u reconrun env HOME="$HOME" BASE_DIR="$BASE_DIR" \
                  bash "$SCRIPT_DIR/recon_graphql.sh" "${@:-scan}" ;;
  wcd)          # web-cache deception/poisoning surfacer (detect-only, cache-busted). reconrun.
                shift
                sudo -n -u reconrun env HOME="$HOME" BASE_DIR="$BASE_DIR" \
                  bash "$SCRIPT_DIR/recon_wcd.sh" "${@:-scan}" ;;
  blindxss|bx)  # Blind/stored-XSS lane. status/test = read-only (d0k); collector = persistent
                # interactsh-client (d0k, foreground — normally the daemon runs it); correlate +
                # plant write findings.db / are target-facing → reconrun (db ownership + egress gate).
                shift
                case "${1:-status}" in
                  status|"")  bash "$SCRIPT_DIR/recon_blindxss.sh" status ;;
                  test)       shift; bash "$SCRIPT_DIR/recon_blindxss.sh" test "$@" ;;
                  collector)  bash "$SCRIPT_DIR/recon_blindxss.sh" collector ;;
                  correlate)  sudo -n -u reconrun env HOME="$HOME" BASE_DIR="$BASE_DIR" \
                                bash "$SCRIPT_DIR/recon_blindxss.sh" correlate ;;
                  plant)      sudo -n -u reconrun env HOME="$HOME" BASE_DIR="$BASE_DIR" DAST_BLIND_ONLY=1 \
                                bash "$SCRIPT_DIR/recon_dast.sh" ;;
                  *)          bash "$SCRIPT_DIR/recon_blindxss.sh" status ;;
                esac ;;
  permute)      # permutation-DNS lane (alterx→puredns via PUBLIC resolvers = NOT target traffic) → d0k.
                bash "$SCRIPT_DIR/recon_permute.sh" ;;
  kr|kiterunner)  # API-route discovery (kiterunner) on bare-API in-scope hosts. target-facing → reconrun.
                sudo -n -u reconrun env HOME="$HOME" BASE_DIR="$BASE_DIR" bash "$SCRIPT_DIR/recon_kr.sh" ;;
  uncover)      # surface expansion (uncover Shodan/Censys dorks, budget-capped). 3rd-party API → d0k.
                shift; bash "$SCRIPT_DIR/recon_uncover.sh" "${@:-cycle}" ;;
  cognito)      # AWS Cognito unauth cred-issuance lane (bucket/JS→pool→guest creds). host-JS fetch +
                # AWS cognito-identity/sts → reconrun (Mullvad egress). guest-only, read-only, stops at
                # role ARN; --assess = SAFE list_/describe_ blast-radius only. bare = results (read-only).
                shift
                sudo -n -u reconrun env HOME="$HOME" BASE_DIR="$BASE_DIR" \
                  bash "$SCRIPT_DIR/recon_cognito.sh" "${@:-results}" ;;
  hunter|ai-hunter)  # the Claude HUNTER (seeded per-target loop). Claude=d0k OAuth, probes=safe_probe.
                shift; bash "$SCRIPT_DIR/recon_ai_hunter.sh" "${@:-status}" ;;
  research)     # standing Claude research routine. Web research (not target traffic) → runs as d0k.
                shift
                bash "$SCRIPT_DIR/recon_research.sh" "${@:-vulns}" ;;
  backup)       # ES snapshot backup (recon_alive corpus). Local ES admin, not target traffic → d0k.
                shift; bash "$SCRIPT_DIR/recon_es_backup.sh" "${@:-status}" ;;
  account)      shift; python3 "$SCRIPT_DIR/recon_account.py" "$@" ;;
  domxss)       shift; python3 "$SCRIPT_DIR/recon_domxss.py" "$@" ;;
  ai)           shift; cmd_ai "$@" ;;
  outcome)      shift; cmd_outcome "$@" ;;
  view|dashboard) shift; cmd_view "$@" ;;
  js)           shift; cmd_js "$@" ;;
  ignored)      shift; cmd_ignored "$@" ;;
  ports)        shift; cmd_ports "$@" ;;
  exposed)      cmd_exposed ;;
  portscan)     cmd_portscan_now ;;
  bypass)       shift; cmd_bypass "$@" ;;
  bypass-now)   cmd_bypass_now ;;
  revalidate)   cmd_revalidate_now ;;
  digest-now)   cmd_digest_now ;;
  leads)        cmd_leads ;;
  leads-post)   cmd_leads_post ;;
  screenshot|shot)       cmd_screenshot_now ;;
  screenshot-backfill|shot-backfill) shift; cmd_screenshot_backfill "$@" ;;
  screenshot-test|shot-test)         shift; cmd_screenshot_test "$@" ;;
  screenshot-install|shot-install)   cmd_screenshot_install ;;
  screenshots|shots)    shift; cmd_screenshots "$@" ;;
  gallery)              shift; cmd_gallery "$@" ;;
  fetch|get|pull) shift; cmd_fetch "$@" ;;
  bulk)         shift; cmd_bulk "$@" ;;
  fp)           shift; cmd_fp "$@" ;;
  ignore)       shift; cmd_ignore "$@" ;;
  note)         shift; cmd_note "$@" ;;
  v2)           shift; cmd_v2 "$@" ;;
  inspect)      shift; cmd_inspect "$@" ;;
  ui)           # local web control plane (FastAPI + SPA on 127.0.0.1:8787). read-only w.r.t. pipeline.
                shift; bash "$SCRIPT_DIR/../tools/start_ui.sh" "${@:-start}" ;;
  *) echo "Unknown: $1"; usage; exit 1 ;;
esac

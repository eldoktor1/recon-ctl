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

mkdir -p "$STATE_DIR"

c() { printf '\033[%sm%s\033[0m' "$1" "$2"; }
hdr() { printf '\n\033[1;36m== %s ==\033[0m\n' "$1"; }

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

cmd_start() {
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
    local mexit
    mexit="$(timeout 8 curl -sS --max-time 7 https://am.i.mullvad.net/json 2>/dev/null | jq -r '.mullvad_exit_ip // "null"' 2>/dev/null)"
    if [[ "$mexit" != "true" ]]; then
      echo "REFUSING to start: egress is NOT a confirmed Mullvad exit (mullvad_exit_ip=$mexit)."
      echo "Reconnect Mullvad and retry.  (override for testing: RECON_SKIP_VPN_CHECK=1)"
      return 1
    fi
    echo "VPN OK — Mullvad exit confirmed."
  fi
  nohup bash "$DAEMON" >/dev/null 2>&1 &
  sleep 1
  if [[ -s "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "Started (pid $(cat "$PID_FILE"))"
  else
    echo "Failed to start. Check $LOG_DIR/recon_daemon.log"; return 1
  fi
}

cmd_stop() {
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
  local LOOP_PAT='recon_(validate|discovery|hot_seed|scope_watch|takeover_hunter|discord_bot|scope_db|cve_intel|vuln_feed|nuclei|true_fresh|fresh_modules|cloudrecon|dast|params|vpnguard|brain|ai_score)\.sh'
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
    curl -fsS -m 5 -u "$ES_USER:$ES_PASS" "$ES_URL/_cluster/health" 2>/dev/null \
      | jq -r '"  status=\(.status) nodes=\(.number_of_nodes) docs?\(.active_primary_shards) shards"' || echo "  ES unreachable"
    local count; count="$(curl -fsS -m 5 -u "$ES_USER:$ES_PASS" "$ES_URL/$INDEX_NAME/_count" 2>/dev/null | jq -r '.count // "?"')"
    echo "  $INDEX_NAME doc count: $count"
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
  local lines="${1:-50}"
  hdr "recon_daemon.log (last $lines)"
  tail -n "$lines" "$LOG_DIR/recon_daemon.log" 2>/dev/null || echo "(no log)"
}

cmd_top() {
  local n="${1:-15}"
  hdr "Top $n triage targets"
  local f="$TRIAGE_DIR/agent_targets.jsonl"
  [[ -s "$f" ]] || { echo "No targets file"; return; }
  jq -r '[.priority,.score,.host,(.vuln_classes//[]|join(","))] | @tsv' "$f" \
    | head -n "$n" | column -t -s $'\t'
}

cmd_takeovers() {
  hdr "TAKEOVERS — claim file"
  local f="$FB_DIR/takeovers_to_claim.tsv"
  if [[ ! -s "$f" ]]; then echo "No takeover candidates yet."; return; fi
  echo "Format: ts | host | service | cname | confidence | stages | difficulty | notes"
  echo "------"
  tail -n 50 "$f" | awk -F'\t' '{printf "%s  %s\n  → %s via %s [%s] %s %s\n  %s\n\n", $1, $2, $3, $4, $5, $6, $7, $8}'
}

cmd_watching() {
  hdr "TAKEOVERS — watching"
  local f="$FB_DIR/takeovers_watching.tsv"
  [[ -s "$f" ]] || { echo "Empty"; return; }
  tail -n 30 "$f" | awk -F'\t' '{printf "%s  %s → %s [%s]\n", $1, $2, $3, $5}'
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
    "nuclei:recon_nuclei.sh" \
    "vuln-feed:recon_vuln_feed.sh"; do
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
  hdr "KEV-matched targets"
  local f="$HOME/recon/cve/kev_targets.jsonl"
  [[ ! -s "$f" ]] && { echo "  none yet (CVE intel not yet run)"; return; }
  jq -r '"  \(.host)  [\(.matched_signal)]  CVEs: \([.matched_cves[] | select(.kev) | .id] | join(\",\"))"' "$f" | head -30
  echo
  echo "  total: $(wc -l < "$f")"
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
  # --new: always fetch a large pool so we can filter unseen before capping at N
  local fetch_n="$n"
  [[ "$new_only" -eq 1 && "$n" -lt 500 ]] && fetch_n=500

  local FRESH_DIR="$BASE_DIR/fresh"
  local SEEN_FILE="$STATE_DIR/fresh_seen.txt"
  mkdir -p "$FRESH_DIR"
  touch "$SEEN_FILE"

  local ES_PASS_VAL; ES_PASS_VAL="$(tr -d '[:space:]' < "$HOME/.recon_es_pass" 2>/dev/null || true)"
  local resp
  resp="$(curl -sS -m30 -u "$ES_USER:$ES_PASS_VAL" \
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

  # --new: filter to hosts not in seen file, cap at N after filtering
  local new_hosts="" shown_rows="" count=0
  if [[ "$new_only" -eq 1 ]]; then
    while IFS=$'\t' read -r icon pri score tier host prog sigs date; do
      [[ -z "$host" ]] && continue
      [[ "$count" -ge "$n" ]] && break
      if ! grep -qxF "$host" "$SEEN_FILE"; then
        shown_rows="${shown_rows}${icon}	${pri}	${score}	${tier}	${host}	${prog}	${sigs}	${date}"$'\n'
        new_hosts="${new_hosts}${host}"$'\n'
        count=$(( count + 1 ))
      fi
    done <<< "$rows"
  else
    shown_rows="$rows"
    while IFS=$'\t' read -r icon pri score tier host prog sigs date; do
      [[ -n "$host" ]] && new_hosts="${new_hosts}${host}"$'\n'
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

  # Record newly seen hosts
  if [[ -n "$new_hosts" ]]; then
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
        printf "%-3s %-4s %-8s %-55s %-25s %s  %s\n", $2,$3,$4,$5,$6,$7,$8
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
  local ES_PASS_VAL; ES_PASS_VAL="$(tr -d '[:space:]' < "$HOME/.recon_es_pass" 2>/dev/null || true)"

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
  resp="$(curl -sS -m30 -u "$ES_USER:$ES_PASS_VAL" \
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
      (if .triage_true_fresh then "⚡fresh" else "" end),
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

cmd_ai() {
  hdr "AI review layer"
  local ai_dir="$HOME/recon/ai_review"
  local scored="$ai_dir/ai_scored.jsonl"
  local pending="$ai_dir/pending"
  local model="${OLLAMA_MODEL_LEAD:-llama3.1:8b-instruct-q4_K_M}"
  local enabled="${ENABLE_OLLAMA_AI:-1}"
  echo "  enabled by default: $enabled"
  echo "  model: $model"
  if command -v ollama >/dev/null 2>&1 && curl -fsS -m 2 "${OLLAMA_URL:-http://127.0.0.1:11434}/api/tags" >/dev/null 2>&1; then
    if ollama list 2>/dev/null | awk '{print $1}' | grep -qxF "$model"; then
      echo "  ollama: reachable, model installed"
    else
      echo "  ollama: reachable, model missing ($model)"
    fi
  else
    echo "  ollama: not reachable"
  fi
  local scored_count=0
  [[ -f "$scored" ]] && scored_count="$(wc -l < "$scored" 2>/dev/null || echo 0)"
  echo "  scored leads: $scored_count"
  echo "  pending packets: $(find "$pending" -maxdepth 1 -type f -name '*.md' 2>/dev/null | wc -l | tr -d ' ')"
  local latest
  latest="$(find "$pending" -maxdepth 1 -type f -name '*.md' -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -1 | cut -d' ' -f2-)"
  [[ -n "$latest" ]] && echo "  latest packet: $latest"
  if [[ -s "$scored" ]]; then
    echo
    echo "  latest scored:"
    tail -5 "$scored" | jq -r '"    [AI=\(.ai.ai_relevance_score // "?") route=\(.ai.route // "?")] \(.host) — \(.ai.recommendation // "?")"' 2>/dev/null
  fi
}

cmd_vuln() {
  local sub="${1:-status}"
  case "$sub" in
    refresh)
      bash "$(script_path recon_vuln_feed.sh)" all
      ;;
    status)
      hdr "Vuln intelligence"
      if [[ -x "$(script_path recon_vuln_feed.sh)" ]]; then
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
  echo "Ignored $host (7 days)  — $reason"
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
      for k in v2_scope v2_cve v2_vuln_feed v2_nuclei; do
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

  printf "${B}── RATE / MODE ─────────────────────────────────────────────────────${R}\n"
  printf "  ${G}recon-rate${R} [preset|N M]        Live rate control (no restart needed)\n"
  printf "             presets: light easy medium full reset\n"
  printf "             raw:     recon-rate 80 60\n"
  printf "  ${G}recon-boost${R}                    Switch to boost/power mode\n"
  printf "  ${G}recon-browse${R}                   Switch to light browse mode\n\n"

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
  printf "  ${G}recon-confirmed${R}                Latest confirmed nuclei findings\n"
  printf "  ${G}recon-vuln${R} [status|top|refresh] Passive vuln intelligence queue\n\n"

  printf "${B}── SCOPE ───────────────────────────────────────────────────────────${R}\n"
  printf "  ${G}recon-scope${R} <host>             Check host against all program scopes\n"
  printf "  ${G}recon-programs${R}                 Program summary from scope DB\n"
  printf "  ${G}recon-params${R} <class> [N]       Sus-params catalog by vuln class\n"
  printf "             classes: sqli xss ssrf lfi ssti cmdi redirect idor\n\n"

  printf "${B}── TAKEOVERS ───────────────────────────────────────────────────────${R}\n"
  printf "  ${G}recon-takeovers${R}                High-confidence CLAIM file\n"
  printf "  ${G}recon-watching${R}                 Medium-confidence WATCH file (recheck queue)\n\n"

  printf "${B}── ACTIONS ─────────────────────────────────────────────────────────${R}\n"
  printf "  ${G}recon-submit${R} <host> <class>    Log a submission (dampens future scoring)\n"
  printf "  ${G}recon-ignore${R} <host> [reason]   Penalise host in triage for 7 days\n"
  printf "  ${G}recon-fp${R} <host> <template>     Mark nuclei finding as false positive\n"
  printf "  ${G}recon-inspect${R} <host>           Full triage view: ES + scope + KEV + probe\n"
  printf "  ${G}recon-dupes${R} [pattern]          Submission history (filter by host pattern)\n"
  printf "  ${G}recon-ai${R}                       AI review layer status + packet counts\n\n"

  printf "${B}── MAINTENANCE ─────────────────────────────────────────────────────${R}\n"
  printf "  ${G}recon-clean${R}                    Archive stale spool + old done/ files\n"
  printf "  ${G}recon-v2${R} <subcmd>              V2 module control\n"
  printf "             status                 Module health overview\n"
  printf "             enable/disable <mod>   scope | cve | vuln_feed | nuclei\n"
  printf "             refresh-scope/cve/vuln Run a module pass now\n"
  printf "             scan-now               Run nuclei pass immediately\n"
}

case "${1:-}" in
  start)        cmd_start ;;
  stop)         cmd_stop ;;
  status|st)    cmd_status ;;
  rate)         shift; cmd_rate "$@" ;;
  queue|q)      cmd_queue ;;
  logs)         shift; cmd_logs "$@" ;;
  top)          shift; cmd_top "$@" ;;
  takeovers|to) cmd_takeovers ;;
  watching|w)   cmd_watching ;;
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
      "")       bash "$SCRIPT_DIR/recon_params.sh" list ;;   # show usage/classes
      list)     shift; bash "$SCRIPT_DIR/recon_params.sh" list "$@" ;;
      collect)  bash "$SCRIPT_DIR/recon_params.sh" collect ;;
      *)        bash "$SCRIPT_DIR/recon_params.sh" list "$@" ;; # shorthand: class [N]
    esac
    ;;
  ai)           cmd_ai ;;
  fp)           shift; cmd_fp "$@" ;;
  ignore)       shift; cmd_ignore "$@" ;;
  v2)           shift; cmd_v2 "$@" ;;
  inspect)      shift; cmd_inspect "$@" ;;
  *) echo "Unknown: $1"; usage; exit 1 ;;
esac

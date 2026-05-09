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
MODE_FILE="$HOME/.recon_mode"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

script_path() { printf '%s\n' "$SCRIPT_DIR/$1"; }

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
  mkdir -p "$TRIAGE_DIR" "$BASE_DIR/fresh" "$BASE_DIR/nuclei"

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

  local fresh_seen="$BASE_DIR/fresh/.seen_keys"
  touch "$fresh_seen" 2>/dev/null || true
  if [[ -s "$BASE_DIR/fresh/fresh_confirmed.jsonl" && -w "$fresh_seen" ]]; then
    jq -r '[.host // "", ((.fresh_kinds // []) | sort | join(","))] | @tsv' \
      "$BASE_DIR/fresh/fresh_confirmed.jsonl" 2>/dev/null \
      | while IFS=$'\t' read -r host kinds; do
          [[ -n "$host" && -n "$kinds" ]] || continue
          printf '%s|%s' "$host" "$kinds" | sha256sum | awk '{print $1}'
        done >> "$fresh_seen"
    sort -u "$fresh_seen" -o "$fresh_seen" 2>/dev/null || true
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
  nohup bash "$DAEMON" >/dev/null 2>&1 &
  sleep 1
  if [[ -s "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "Started (pid $(cat "$PID_FILE"))"
  else
    echo "Failed to start. Check $LOG_DIR/recon_daemon.log"; return 1
  fi
}

cmd_stop() {
  if [[ -s "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    local pid; pid="$(cat "$PID_FILE")"
    echo "Stopping pid $pid (graceful)"
    kill -TERM "$pid"
    for i in 1 2 3 4 5 6 7 8 9 10; do
      kill -0 "$pid" 2>/dev/null || break
      sleep 1
    done
    if kill -0 "$pid" 2>/dev/null; then
      echo "Force-killing"
      kill -KILL "$pid" 2>/dev/null || true
    fi
    rm -f "$PID_FILE"
    pkill -f 'recon_(validate|discovery|hot_seed|scope_watch|takeover_hunter|discord_bot|scope_db|cve_intel|nuclei|fresh_confirm|schedule)\.sh' 2>/dev/null || true
    pkill -f 'triage\.sh' 2>/dev/null || true
    pkill -f 'httpx|subfinder|assetfinder|nuclei.*-target' 2>/dev/null || true
    echo "Stopped."
  else
    echo "Not running"
  fi
}

cmd_status() {
  hdr "Daemon"
  if [[ -s "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    local pid; pid="$(cat "$PID_FILE")"
    local etime; etime="$(ps -o etime= -p "$pid" 2>/dev/null | tr -d ' ')"
    echo "Running (pid $pid, uptime $etime)"
    echo "Mode: $(cat "$MODE_FILE" 2>/dev/null || echo browse)"
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

cmd_mode() {
  local m="${1:-}"
  if [[ -z "$m" ]]; then
    echo "Current mode: $(cat "$MODE_FILE" 2>/dev/null || echo browse)"
    return
  fi
  case "$m" in
    night) m="boost" ;;
  esac
  case "$m" in
    browse|boost) echo "$m" > "$MODE_FILE"; echo "Mode → $m (effective next cycle)" ;;
    *) echo "Usage: recon_ctl mode browse|boost"; return 1 ;;
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
  command -v httpx >/dev/null 2>&1 && echo "  httpx: $(httpx -version 2>&1 | head -1)" || echo "  httpx: MISSING"
  command -v subfinder >/dev/null 2>&1 && echo "  subfinder: $(subfinder -version 2>&1 | head -1)" || echo "  subfinder: MISSING"
  command -v assetfinder >/dev/null 2>&1 && echo "  assetfinder: present" || echo "  assetfinder: missing"
  command -v jq >/dev/null 2>&1 && echo "  jq: $(jq --version)" || echo "  jq: MISSING"
  command -v dig >/dev/null 2>&1 && echo "  dig: present" || echo "  dig: MISSING"
  command -v docker >/dev/null 2>&1 && echo "  docker: $(docker --version | head -1)" || echo "  docker: missing (ok if ES via systemd)"
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
  - fresh-confirm active results, reports, evidence, and cooldown markers
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
  archive_matching "$archive_root" "fresh" "fresh_confirmed.jsonl" "report_*.md" ".last_*"
  archive_matching "$archive_root" "fresh/evidence" "*"
  archive_matching "$archive_root" "nuclei" "confirmed.jsonl"
  archive_matching "$archive_root" "nuclei/results" "run_*"
  archive_matching "$archive_root" "logs" "*.log"

  mkdir -p "$QUEUE_DIR/inbox" "$QUEUE_DIR/processing" "$QUEUE_DIR/done" \
           "$BASE_DIR/spool/pending" "$BASE_DIR/spool/sent" "$BASE_DIR/spool/failed" \
           "$TRIAGE_DIR" "$BASE_DIR/fresh/evidence" "$BASE_DIR/nuclei/results"

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

cmd_confirmed() {
  hdr "Latest confirmed nuclei findings"
  local f="$HOME/recon/nuclei/confirmed.jsonl"
  [[ ! -s "$f" ]] && { echo "  none yet"; return; }
  tail -20 "$f" | jq -r '"  [\(.info.severity // \"?\")] \(.host) — \(.\"template-id\") (program: \(.scope.program // \"?\"))"'
}

cmd_fresh() {
  hdr "Fresh confirmed queue"
  local f="$HOME/recon/fresh/fresh_confirmed.jsonl"
  [[ ! -s "$f" ]] && { echo "  none yet"; return; }
  tail -20 "$f" | jq -r '"  [\(.fresh_score)] \(.host)  \(.fresh_kinds | join(","))  scope=\(.scope.program // "?")  url=\(.verified_url)"'
  echo
  local latest
  latest="$(ls -t "$HOME/recon/fresh"/report_*.md 2>/dev/null | head -1)"
  [[ -n "$latest" ]] && echo "  latest report: $latest"
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
      for k in v2_scope v2_cve v2_nuclei v2_fresh; do
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
      for f in "scope/programs.json" "cve/kev.json" "cve/tech_cve_map.json" "cve/kev_targets.jsonl"; do
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
      local mod="${1:-}"; [[ -z "$mod" ]] && { echo "Usage: recon_ctl v2 enable {scope|cve|nuclei}"; return 1; }
      rm -f "$V21_KILL_DIR/v2_$mod"; echo "$mod re-enabled"
      ;;
    disable)
      local mod="${1:-}"; shift || true
      [[ -z "$mod" ]] && { echo "Usage: recon_ctl v2 disable {scope|cve|nuclei} [reason]"; return 1; }
      mkdir -p "$V21_KILL_DIR"
      echo "${*:-manual}" > "$V21_KILL_DIR/v2_$mod"; echo "$mod disabled"
      ;;
    refresh-scope) bash "$(script_path recon_scope_db.sh)" ;;
    refresh-cve)   bash "$(script_path recon_cve_intel.sh)" all ;;
    scan-now)      bash "$(script_path recon_nuclei.sh)" ;;
    *)
      echo "v2 subcommands: status | enable <mod> | disable <mod> [reason] | refresh-scope | refresh-cve | scan-now"
      ;;
  esac
}

cmd_inspect() {
  local host="${1:-}"
  if [[ -z "$host" ]]; then echo "Usage: recon_ctl inspect <host>"; return 1; fi
  bash "$(script_path recon_inspect.sh)" "$host"
}

cmd_schedule_status() {
  local tz="America/Los_Angeles"
  local dow hour min time_mins
  dow="$(TZ=$tz date +%u)"
  hour="$(TZ=$tz date +%H)"
  min="$(TZ=$tz date +%M)"
  time_mins=$(( 10#$hour * 60 + 10#$min ))
  local browse_start=1050 browse_end=1410  # 17:30-23:30

  hdr "Schedule status"
  echo "  Current PT time: $(TZ=$tz date '+%A %H:%M')"
  echo "  Current mode:    $(cat "$MODE_FILE" 2>/dev/null || echo browse)"
  local weekend_boost_start=180 weekend_boost_end=600
  if [[ "$dow" -ge 6 && "$time_mins" -ge "$weekend_boost_start" && "$time_mins" -lt "$weekend_boost_end" ]]; then
    echo "  Weekend boost window: ACTIVE (until 10:00 AM PT)"
  elif [[ "$dow" -ge 6 ]]; then
    echo "  Weekend: manual mode preserved outside 3:00 AM-10:00 AM PT boost window (use: recon_ctl mode browse|boost)"
  elif [[ "$time_mins" -ge "$browse_start" && "$time_mins" -lt "$browse_end" ]]; then
    echo "  Weekday browse window: ACTIVE (until 11:30 PM PT)"
  else
    echo "  Boost mode window: ACTIVE"
    if [[ "$time_mins" -lt "$browse_start" ]]; then
      mins_until=$(( browse_start - time_mins ))
      echo "  Browse starts in: ${mins_until}m (at 5:30 PM PT)"
    else
      echo "  Next browse window: tomorrow 5:30 PM PT"
    fi
  fi
  echo "  Schedule: weekdays 5:30pm-11:30pm=browse, weekday off-hours=boost, weekends 3am-10am=boost"
}

cmd_schedule_check() {
  bash "$(script_path recon_schedule.sh)" && echo "Schedule check OK"
  echo "Mode is now: $(cat "$HOME/.recon_mode" 2>/dev/null || echo browse)"
}

usage() {
cat <<EOF
recon_ctl — pipeline control

  start                  Launch daemon
  stop                   Stop daemon + children
  status                 Daemon, queue, ES, FB summary
  mode [browse|boost]    Show or set mode (night remains an alias)
  queue                  Show queue counts
  logs [N]               Tail daemon log (default 50)
  top [N]                Top N triage targets (default 15)
  takeovers              Show CLAIM file (high-confidence takeovers)
  watching               Show WATCH file (medium-confidence, periodic recheck)
  dupes [pattern]        Show submission history (filter by host pattern)
  submit <host> <class>  Log a submission (dampens future scoring)
  health                 Tool versions + status
  space                  Disk usage
  clean                  Archive stale sent spool and old done/
  clean-start [--yes]    Archive stale active views for a clean restart
  reset-queue            Archive and clear queue (with confirmation)

  V2 commands:
  kev                    Show KEV-matched targets in your data
  scope <host>           Check if a host is in any program scope
  programs               Summary of programs in scope DB
  confirmed              Latest confirmed nuclei findings
  fresh                  Latest fresh in-scope confirmed candidates
  fp <host> <tmpl>       Mark a nuclei finding as false positive
  v2 status              V2 module health
  v2 enable <mod>        Re-enable killed module (scope|cve|nuclei)
  v2 disable <mod> [r]   Manually disable module
  v2 refresh-scope       Run scope DB now
  v2 refresh-cve         Run CVE intel now
  v2 scan-now            Run nuclei pass now
  inspect <host>         Full triage view (ES + scope + KEV + live probe)
  schedule               Show schedule status and current window
  schedule-check         Force run schedule check now
EOF
}

case "${1:-}" in
  start)        cmd_start ;;
  stop)         cmd_stop ;;
  status|st)    cmd_status ;;
  mode)         shift; cmd_mode "$@" ;;
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
  fresh)        cmd_fresh ;;
  fp)           shift; cmd_fp "$@" ;;
  v2)           shift; cmd_v2 "$@" ;;
  inspect)      shift; cmd_inspect "$@" ;;
  schedule)      cmd_schedule_status ;;
  schedule-check) cmd_schedule_check ;;
  *) echo "Unknown: $1"; usage; exit 1 ;;
esac

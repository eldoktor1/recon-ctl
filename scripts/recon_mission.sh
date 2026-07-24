#!/usr/bin/env bash
# =============================================================================
# recon_mission.sh — MISSION CONTROL: live self-refreshing terminal dashboard.
#
# The primary operator interface. Shows everything happening in the pipeline
# in one view — confirmed findings, tonight's targets, lane health, research
# alerts, corpus stats, VPN/daemon state — auto-refreshing every N seconds.
#
# Keys: R=refresh now  B=briefing  T=top targets  F=fresh hosts  L=logs  Q=quit
# Usage: recon_mission [--interval N]   (default 30s)
# =============================================================================
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/recon_net.sh" 2>/dev/null || true
type setup_es_netrc >/dev/null 2>&1 && setup_es_netrc || true

BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
LOG_DIR="${LOG_DIR:-$BASE_DIR/logs}"
QUEUE_DIR="${QUEUE_DIR:-$BASE_DIR/queue}"
BRIEF_DIR="${BRIEF_DIR:-$BASE_DIR/briefings}"
RESEARCH_DIR="$REPO_DIR/docs/research"
NETRC="$HOME/.recon_es_netrc"
ES="http://127.0.0.1:9200/recon_alive"
V3_DB="${V3_DB:-$BASE_DIR/v3/findings.db}"
PID_FILE="${PID_FILE:-$STATE_DIR/recon_daemon.pid}"
DAEMON_LOG="$LOG_DIR/recon_daemon.log"
MISSION_INTERVAL="${MISSION_INTERVAL:-30}"

# Parse args
while [[ "${1:-}" == --* ]]; do
  case "$1" in
    --interval) MISSION_INTERVAL="$2"; shift 2 ;;
    *) shift ;;
  esac
done

# ── Color palette ──────────────────────────────────────────────────────────────
B='\033[1m'; R='\033[0m'
CY='\033[1;36m'; GR='\033[0;32m'; YE='\033[1;33m'; RD='\033[0;31m'
DIM='\033[2m'; BL='\033[1;34m'; MG='\033[1;35m'; WH='\033[1;37m'

# ── Helpers ────────────────────────────────────────────────────────────────────
es_q() { curl -sS -m20 --netrc-file "$NETRC" -H 'Content-Type: application/json' \
           -X POST "$ES/_search" -d "$1" 2>/dev/null; }
es_count() { curl -sS -m15 --netrc-file "$NETRC" -H 'Content-Type: application/json' \
               -X POST "$ES/_count" -d "{\"query\":$1}" 2>/dev/null | jq -r '.count // 0'; }
pad() { printf "%-${2}s" "${1:0:$2}"; }  # pad/truncate to width

# ── Lane status: parse daemon log for last activity ────────────────────────────
lane_status() {
  local lane="$1" last_ts now_ts age_s symbol color label
  now_ts="$(date +%s)"
  # Look for last log line containing [<lane>]
  last_ts="$(grep -m1 "" "$DAEMON_LOG" 2>/dev/null | wc -c)"  # existence check
  last_ts="$(grep "\[$lane\]" "$DAEMON_LOG" 2>/dev/null | tail -1 | \
             grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z' | tail -1)"
  if [[ -z "$last_ts" ]]; then
    printf "${DIM}  ⚫ %-18s  no log${R}" "$lane"
    return
  fi
  age_s=$(( now_ts - $(date -d "$last_ts" +%s 2>/dev/null || echo $now_ts) ))
  if   (( age_s < 7200  )); then color="$GR"; symbol="🟢"
  elif (( age_s < 21600 )); then color="$YE"; symbol="🟡"
  else                            color="$RD"; symbol="🔴"; fi
  local age_fmt
  if   (( age_s < 60   )); then age_fmt="${age_s}s"
  elif (( age_s < 3600 )); then age_fmt="$(( age_s/60 ))m"
  else                          age_fmt="$(( age_s/3600 ))h$(( (age_s%3600)/60 ))m"; fi
  printf "${color}  %s %-18s  %s ago${R}" "$symbol" "$lane" "$age_fmt"
}

# ── Research alerts ────────────────────────────────────────────────────────────
research_alerts() {
  local cutoff; cutoff="$(date -d '24 hours ago' '+%Y-%m-%dT%H:%M:%S' 2>/dev/null || echo '')"
  local new_digests=() pending_proposals=0
  # New digests in last 24h
  for f in "$RESEARCH_DIR"/*.md; do
    [[ -f "$f" ]] || continue
    [[ "$f" == *proposals* ]] && continue
    if [[ -n "$cutoff" ]] && [[ "$(stat -c %Y "$f" 2>/dev/null || echo 0)" -gt \
          "$(date -d '24 hours ago' +%s 2>/dev/null || echo 0)" ]]; then
      local topic; topic="$(basename "$f" | sed 's/_[0-9-]*\.md//')"
      local headline; headline="$(grep -m1 '^## [0-9]\.' "$f" 2>/dev/null | sed 's/^## [0-9]*\. //' | cut -c1-55)"
      new_digests+=("${topic}: ${headline:-new digest}")
    fi
  done
  # Unapplied proposals
  pending_proposals="$(find "$RESEARCH_DIR/proposals" -name "*.md" \
                        -not -path "*/applied/*" 2>/dev/null | wc -l | tr -d ' ')"
  printf '%s\n' "${new_digests[@]}"
  [[ "$pending_proposals" -gt 0 ]] && printf '%s proposals pending apply\n' "$pending_proposals"
}

# ── Tonight's targets from latest briefing ─────────────────────────────────────
tonight_targets() {
  # Try 2IC_tonight first, then tonight_
  local brief; brief="$(ls -t "$BRIEF_DIR"/2IC_tonight_*.md "$BRIEF_DIR"/tonight_*.md 2>/dev/null | head -1)"
  [[ -f "$brief" ]] || { echo "  run: recon-briefing"; return; }
  # Extract HUNT THESE or top IDOR/BAC section
  grep -A30 'HUNT THESE\|TONIGHT\|BAC/IDOR\|🎯\|## 1\.' "$brief" 2>/dev/null | \
    grep -E '^\s*[0-9]\.|^> |^- |^\*\*|program|Program|target|Target' | \
    head -6 | sed 's/^[[:space:]]*/  /' || echo "  (briefing ready — run [B])"
}

# ── Confirmed findings needing action ─────────────────────────────────────────
confirmed_findings() {
  # Check findings.db for real verdicts not yet submitted
  if command -v python3 >/dev/null 2>&1 && [[ -f "$V3_DB" ]]; then
    python3 - <<'PY' 2>/dev/null
import sqlite3, os
db = os.path.expanduser('~/recon/v3/findings.db')
if not os.path.exists(db): exit()
c = sqlite3.connect(db)
try:
    rows = c.execute("""
        SELECT host, vuln_class, severity, program
        FROM findings
        WHERE ai_verdict='real' AND (state IS NULL OR state NOT IN ('submitted','reported'))
        ORDER BY created_at DESC LIMIT 5
    """).fetchall()
    for h,v,s,p in rows:
        print(f"  🔴 [{s or '?'}] {(h or '')[:40]} — {(v or '')[:25]} ({(p or '')[:20]})")
except Exception:
    pass
PY
  fi
  # Also check cognito confirmed_real.jsonl
  local cf="$BASE_DIR/cognito/confirmed_real.jsonl"
  if [[ -s "$cf" ]]; then
    while IFS= read -r line; do
      local prov prog; prov="$(jq -r '.provenance//"?"' <<<"$line" 2>/dev/null)"
      prog="$(jq -r '.program//"?"' <<<"$line" 2>/dev/null)"
      echo "  🔴 [cognito] ${prov:0:40} (${prog:0:25})"
    done < "$cf"
  fi
}

# ── Draw the full dashboard ────────────────────────────────────────────────────
draw() {
  local COLS; COLS="$(tput cols 2>/dev/null || echo 120)"
  local LEFT_W=$(( COLS * 58 / 100 ))  # ~58% left
  local RIGHT_W=$(( COLS - LEFT_W - 3 )) # remaining right
  local TMP; TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' RETURN

  # ── Gather data in parallel ─────────────────────────────────────────────────
  {
    # VPN state
    if [[ -f "$STATE_DIR/vpn_down" ]]; then echo "❌ VPN DOWN"
    elif [[ -f "$STATE_DIR/vpn_status.json" ]]; then
      jq -r 'if .mullvad==true then "🟢 "+.ip else "❌ NOT MULLVAD ("+.ip+")" end' \
        "$STATE_DIR/vpn_status.json" 2>/dev/null || echo "❓ unknown"
    else echo "❓ unknown"; fi
  } > "$TMP/vpn" &

  {
    # Daemon state
    if [[ -s "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
      local up; up="$(ps -o etime= -p "$(cat "$PID_FILE")" 2>/dev/null | tr -d ' ')"
      echo "🟢 DAEMON UP ${up}"
    elif systemctl is-active --quiet recon-daemon.service 2>/dev/null; then
      echo "🟢 DAEMON UP (systemd)"
    else
      echo "🔴 DAEMON DOWN"
    fi
  } > "$TMP/daemon" &

  {
    # Queue depth
    local inbox proc
    inbox="$(find "$QUEUE_DIR/inbox"      -maxdepth 1 -name '*.txt' 2>/dev/null | wc -l | tr -d ' ')"
    proc="$(find  "$QUEUE_DIR/processing" -maxdepth 1 -name '*.txt' 2>/dev/null | wc -l | tr -d ' ')"
    echo "Q inbox:${inbox} proc:${proc}"
  } > "$TMP/queue" &

  {
    # ES counts in parallel
    es_count '{"term":{"triage_priority":"P0"}}' > "$TMP/p0" &
    es_count '{"term":{"triage_priority":"P1"}}' > "$TMP/p1" &
    es_count '{"match_all":{}}' > "$TMP/es_total" &
    es_count '{"term":{"triage_true_fresh":true}}' > "$TMP/fresh" &
    es_count '{"term":{"triage_kev_match":true}}' > "$TMP/kev" &
    es_count '{"bool":{"should":[{"term":{"js_secret_hit":true}},{"term":{"js_endpoint_hit":true}}],"minimum_should_match":1}}' > "$TMP/js" &
    wait
  } &

  # True-fresh hosts (last 24h)
  {
    es_q '{"size":4,"_source":["host","triage_program","triage_priority","triage_score"],
           "query":{"bool":{"filter":[{"term":{"triage_pays":true}},{"term":{"triage_in_scope":true}},
             {"term":{"triage_true_fresh":true}}],"must_not":[{"range":{"ignore_expires_at":{"gt":"now"}}}]}},
           "sort":[{"triage_score":{"order":"desc"}}]}' > "$TMP/fresh_hosts"
  } &

  # Research alerts
  { research_alerts > "$TMP/research"; } &

  # Tonight's targets
  { tonight_targets > "$TMP/targets"; } &

  # Confirmed findings
  { confirmed_findings > "$TMP/confirmed"; } &

  wait

  # ── Render ──────────────────────────────────────────────────────────────────
  local vpn_s daemon_s queue_s es_total p0 p1 fresh kev js ts
  vpn_s="$(cat "$TMP/vpn"    2>/dev/null || echo '?')"
  daemon_s="$(cat "$TMP/daemon" 2>/dev/null || echo '?')"
  queue_s="$(cat "$TMP/queue"  2>/dev/null || echo '?')"
  es_total="$(cat "$TMP/es_total" 2>/dev/null || echo '?')"
  p0="$(cat "$TMP/p0" 2>/dev/null || echo '?')"
  p1="$(cat "$TMP/p1" 2>/dev/null || echo '?')"
  fresh="$(cat "$TMP/fresh" 2>/dev/null || echo '?')"
  kev="$(cat "$TMP/kev" 2>/dev/null || echo '?')"
  js="$(cat "$TMP/js"   2>/dev/null || echo '?')"
  ts="$(date '+%Y-%m-%d %H:%M:%S')"

  # ── Header bar ──────────────────────────────────────────────────────────────
  tput clear 2>/dev/null || printf '\033[2J\033[H'
  local title="  RECON MISSION CONTROL  ·  $ts  "
  local status_line="  ${vpn_s}  ·  ${daemon_s}  ·  ES ${es_total}  ·  ${queue_s}  "
  local sep; sep="$(printf '═%.0s' $(seq 1 $COLS))"

  printf "${CY}${B}╔${sep:0:$((COLS-2))}╗${R}\n"
  printf "${CY}${B}║${R}${WH}${B}%-*s${R}${CY}${B}║${R}\n" $((COLS-2)) "$title"
  printf "${CY}${B}║${R}%-*s${CY}${B}║${R}\n" $((COLS-2)) "$status_line"

  # ── Column headers ───────────────────────────────────────────────────────────
  local hsep_l; hsep_l="$(printf '═%.0s' $(seq 1 $LEFT_W))"
  local hsep_r; hsep_r="$(printf '═%.0s' $(seq 1 $RIGHT_W))"
  printf "${CY}${B}╠${hsep_l}╦${hsep_r}╣${R}\n"

  local LHDR="${B}  🗺  CONFIRMED & TARGETS${R}"
  local RHDR="${B}  📡 LANE STATUS${R}"
  printf "${CY}${B}║${R}$(printf '%-*b' $((LEFT_W)) "$LHDR")${CY}${B}║${R}$(printf '%-*b' $((RIGHT_W)) "$RHDR")${CY}${B}║${R}\n"
  printf "${CY}${B}║${R}%-*s${CY}${B}║${R}%-*s${CY}${B}║${R}\n" $LEFT_W "" $RIGHT_W ""

  # ── Build left lines ─────────────────────────────────────────────────────────
  local -a LEFT=()
  # Confirmed findings
  LEFT+=("${GR}${B}  ✅ CONFIRMED (action needed):${R}")
  local confirmed_lines; confirmed_lines="$(cat "$TMP/confirmed" 2>/dev/null)"
  if [[ -z "$confirmed_lines" ]]; then
    LEFT+=("${DIM}  none pending${R}")
  else
    while IFS= read -r line; do LEFT+=("${RD}${line}${R}"); done <<<"$confirmed_lines"
  fi
  LEFT+=("")

  # Tonight's targets
  LEFT+=("${YE}${B}  🎯 TONIGHT'S TARGETS:${R}")
  while IFS= read -r line; do LEFT+=("${line}"); done < "$TMP/targets"
  LEFT+=("")

  # Fresh surface
  LEFT+=("${BL}${B}  ⚡ FRESH SURFACE (new paying hosts):${R}")
  local fhits; fhits="$(jq -r '.hits.hits[]._source | "  › \(.host) (\(.triage_program//"?") \(.triage_priority//"?") s:\(.triage_score//"0"))"' \
    "$TMP/fresh_hosts" 2>/dev/null)"
  if [[ -n "$fhits" ]]; then
    while IFS= read -r line; do LEFT+=("$line"); done <<<"$fhits"
  else
    LEFT+=("${DIM}  none right now${R}")
  fi
  LEFT+=("")

  # Corpus stats
  LEFT+=("${DIM}${B}  📊 CORPUS:${R}")
  LEFT+=("${DIM}  P0:${p0}  P1:${p1}  total:${es_total}  fresh:${fresh}  KEV:${kev}  JS:${js}${R}")

  # ── Build right lines ─────────────────────────────────────────────────────────
  local -a RIGHT=()

  # Key lanes
  local KEY_LANES=(cognito jsintel params blindxss-plant graphql buckets nday \
                   permute ai-hunter research-vulns research-tooling)
  for lane in "${KEY_LANES[@]}"; do
    RIGHT+=("$(lane_status "$lane")")
  done
  RIGHT+=("")

  # Research alerts
  RIGHT+=("${MG}${B}  📚 RESEARCH ALERTS:${R}")
  local ralerts; ralerts="$(cat "$TMP/research" 2>/dev/null)"
  if [[ -z "$ralerts" ]]; then
    RIGHT+=("${DIM}  all clear${R}")
  else
    while IFS= read -r line; do
      RIGHT+=("  ${MG}${line}${R}")
    done <<<"$ralerts"
  fi

  # ── Print columns side by side ────────────────────────────────────────────────
  local max_rows=$(( ${#LEFT[@]} > ${#RIGHT[@]} ? ${#LEFT[@]} : ${#RIGHT[@]} ))
  for (( i=0; i<max_rows; i++ )); do
    local lline="${LEFT[$i]:-}"
    local rline="${RIGHT[$i]:-}"
    # Strip ANSI for length calculation
    local lvis; lvis="$(printf '%b' "$lline" | sed 's/\x1b\[[0-9;]*m//g')"
    local rvis; rvis="$(printf '%b' "$rline" | sed 's/\x1b\[[0-9;]*m//g')"
    local lpad=$(( LEFT_W - ${#lvis} ))
    local rpad=$(( RIGHT_W - ${#rvis} ))
    printf "${CY}${B}║${R}%b%*s${CY}${B}║${R}%b%*s${CY}${B}║${R}\n" \
      "$lline" $lpad "" "$rline" $rpad ""
  done

  # ── Footer / key legend ───────────────────────────────────────────────────────
  local div_l; div_l="$(printf '═%.0s' $(seq 1 $LEFT_W))"
  local div_r; div_r="$(printf '═%.0s' $(seq 1 $RIGHT_W))"
  printf "${CY}${B}╠${div_l}╩${div_r}╣${R}\n"

  local keys="  [R]efresh  [B]riefing  [T]op targets  [F]resh  [L]ogs  [V]erify  [Q]uit  · auto-refresh ${MISSION_INTERVAL}s"
  printf "${CY}${B}║${R}${DIM}%-*s${R}${CY}${B}║${R}\n" $((COLS-2)) "$keys"
  printf "${CY}${B}╚${sep:0:$((COLS-2))}╝${R}\n"
}

# ── Action handlers ────────────────────────────────────────────────────────────
do_briefing() {
  tput clear 2>/dev/null || printf '\033[2J\033[H'
  printf "${CY}${B}═══ TONIGHT'S BRIEFING ═══${R}\n\n"
  local brief; brief="$(ls -t "$BRIEF_DIR"/tonight_*.md "$BRIEF_DIR"/2IC_tonight_*.md 2>/dev/null | head -1)"
  if [[ -f "$brief" ]]; then
    cat "$brief"
  else
    printf "${YE}No briefing for today yet. Generating...${R}\n"
    BRIEFING_FORCE=1 bash "$SCRIPT_DIR/recon_briefing.sh" 2>/dev/null || \
      printf "${RD}Briefing generation failed. Check: recon-logs${R}\n"
  fi
  printf "\n${DIM}Press any key to return...${R}"
  read -rn1 2>/dev/null || true
}

do_top() {
  tput clear 2>/dev/null || printf '\033[2J\033[H'
  bash "$SCRIPT_DIR/recon_ctl.sh" top 20 2>/dev/null
  printf "\n${DIM}Press any key to return...${R}"
  read -rn1 2>/dev/null || true
}

do_fresh() {
  tput clear 2>/dev/null || printf '\033[2J\033[H'
  bash "$SCRIPT_DIR/recon_ctl.sh" fresh 2>/dev/null
  printf "\n${DIM}Press any key to return...${R}"
  read -rn1 2>/dev/null || true
}

do_logs() {
  tput clear 2>/dev/null || printf '\033[2J\033[H'
  printf "${CY}${B}═══ DAEMON LOG — live (Ctrl-C to return) ═══${R}\n"
  tail -f "$DAEMON_LOG" 2>/dev/null || tail -n50 "$DAEMON_LOG" 2>/dev/null
}

do_verify() {
  tput clear 2>/dev/null || printf '\033[2J\033[H'
  printf "${CY}${B}═══ VERIFY FINDINGS ═══${R}\n"
  bash "$SCRIPT_DIR/recon_ctl.sh" verify list 2>/dev/null
  printf "\n${DIM}Enter host/# to verify (or press Enter to cancel): ${R}"
  local target; read -r target 2>/dev/null || true
  [[ -n "$target" ]] && bash "$SCRIPT_DIR/recon_ctl.sh" verify "$target" 2>/dev/null
  printf "\n${DIM}Press any key to return...${R}"
  read -rn1 2>/dev/null || true
}

# ── Main loop ──────────────────────────────────────────────────────────────────
main() {
  # Ensure clean terminal on exit
  trap 'tput cnorm 2>/dev/null; tput rmcup 2>/dev/null; stty echo 2>/dev/null; echo' EXIT INT TERM
  tput smcup 2>/dev/null || true
  tput civis 2>/dev/null || true
  stty -echo 2>/dev/null || true

  while true; do
    draw

    # Wait for keypress or timeout
    local key=""
    IFS= read -r -s -n1 -t "$MISSION_INTERVAL" key 2>/dev/null || key="__timeout__"

    case "${key,,}" in
      r|__timeout__) continue ;;       # refresh
      b) tput cnorm 2>/dev/null; tput rmcup 2>/dev/null; stty echo 2>/dev/null
         do_briefing
         tput smcup 2>/dev/null; tput civis 2>/dev/null; stty -echo 2>/dev/null ;;
      t) tput cnorm 2>/dev/null; tput rmcup 2>/dev/null; stty echo 2>/dev/null
         do_top
         tput smcup 2>/dev/null; tput civis 2>/dev/null; stty -echo 2>/dev/null ;;
      f) tput cnorm 2>/dev/null; tput rmcup 2>/dev/null; stty echo 2>/dev/null
         do_fresh
         tput smcup 2>/dev/null; tput civis 2>/dev/null; stty -echo 2>/dev/null ;;
      l) tput cnorm 2>/dev/null; tput rmcup 2>/dev/null; stty echo 2>/dev/null
         do_logs
         tput smcup 2>/dev/null; tput civis 2>/dev/null; stty -echo 2>/dev/null ;;
      v) tput cnorm 2>/dev/null; tput rmcup 2>/dev/null; stty echo 2>/dev/null
         do_verify
         tput smcup 2>/dev/null; tput civis 2>/dev/null; stty -echo 2>/dev/null ;;
      q|$'\x03') break ;;              # quit / Ctrl-C
    esac
  done
}

main "$@"

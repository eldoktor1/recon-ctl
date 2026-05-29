#!/usr/bin/env bash
# =============================================================================
# weekly_bulk.sh — full scope refresh + subfinder bulk sweep, all BB programs.
# Called from Windows Task Scheduler every Sunday at 3 AM (via VBS, hidden).
# Lock file prevents overlapping runs. Logs to ~/recon/logs/bulk_weekly.log.
# Task Scheduler owns the process — runs foreground so status shows "Running".
# =============================================================================
set -uo pipefail

BASE_DIR="${BASE_DIR:-$HOME/recon}"
LOG_DIR="$BASE_DIR/logs"
STATE_DIR="$BASE_DIR/state"
CTL="/home/d0k/recon-pipeline/scripts/recon_ctl.sh"
BULK_LOG="$LOG_DIR/bulk_weekly.log"
LOCK_FILE="$STATE_DIR/bulk_weekly.running"

mkdir -p "$LOG_DIR"
ts()  { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
log() { printf '[%s BULK] %s\n' "$(ts)" "$*" | tee -a "$BULK_LOG"; }

# Auto-rotate log at 20 MB
if [[ -f "$BULK_LOG" ]]; then
  sz="$(du -sm "$BULK_LOG" 2>/dev/null | awk '{print $1}')"
  [[ "${sz:-0}" -gt 20 ]] && tail -n 5000 "$BULK_LOG" > "$BULK_LOG.tmp" && mv "$BULK_LOG.tmp" "$BULK_LOG"
fi

log "=== weekly bulk start ==="

# ── 1. Lock check — skip if previous run still active ─────────────────────
if [[ -f "$LOCK_FILE" ]]; then
  prev_pid="$(cat "$LOCK_FILE" 2>/dev/null || true)"
  if [[ -n "$prev_pid" ]] && kill -0 "$prev_pid" 2>/dev/null; then
    log "SKIP — previous bulk run still active (pid=$prev_pid). Will retry next week."
    exit 0
  else
    log "Stale lock (pid=${prev_pid:-?}) — clearing and proceeding"
    rm -f "$LOCK_FILE"
  fi
fi

# ── 2. VPN gate — never enumerate targets without Mullvad ─────────────────
vpn_resp="$(timeout 8 curl -sS --max-time 7 https://am.i.mullvad.net/json 2>/dev/null || true)"
mullvad_exit="$(printf '%s' "$vpn_resp" | jq -r '.mullvad_exit_ip // "null"' 2>/dev/null || echo "null")"
if [[ "$mullvad_exit" != "true" ]]; then
  log "ABORT — VPN not on Mullvad (mullvad_exit_ip=$mullvad_exit). Connect VPN and retry manually."
  exit 1
fi
exit_host="$(printf '%s' "$vpn_resp" | jq -r '.mullvad_exit_ip_hostname // "?"' 2>/dev/null)"
log "VPN OK (exit=$exit_host)"

# ── 3. ES gate — bulk is useless if ES is down ────────────────────────────
if [[ -f "$HOME/.recon_es_pass" ]]; then
  ep="$(tr -d '[:space:]' < "$HOME/.recon_es_pass" 2>/dev/null || true)"
  es_status="$(curl -fsS -m5 --netrc-file "$HOME/.recon_es_netrc" http://127.0.0.1:9200/_cluster/health 2>/dev/null \
    | jq -r '.status // "unreachable"' 2>/dev/null || echo "unreachable")"
  if [[ "$es_status" != "green" && "$es_status" != "yellow" ]]; then
    log "ABORT — ES unreachable (status=$es_status). Start from Docker Desktop first."
    exit 1
  fi
  log "ES OK (status=$es_status)"
fi

# ── 4. Scope refresh ──────────────────────────────────────────────────────
log "Refreshing scope DB from all BB platforms..."
bash "$CTL" v2 refresh-scope >> "$BULK_LOG" 2>&1
log "Scope refresh done"

# ── 5. Bulk sweep — foreground, Task Scheduler owns process tree ──────────
echo $$ > "$LOCK_FILE"
log "Bulk sweep starting (all programs, 5 threads/domain)..."

bash "$CTL" bulk run --all --threads 5 >> "$BULK_LOG" 2>&1
rc=$?
rm -f "$LOCK_FILE"

# ── 6. Result ─────────────────────────────────────────────────────────────
if [[ "$rc" -eq 0 ]]; then
  log "=== weekly bulk done OK ==="
else
  log "=== weekly bulk FAILED (exit=$rc) ==="
fi
exit "$rc"

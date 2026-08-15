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
CTL="/home/d0k/recon-ctl/scripts/recon_ctl.sh"
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

# ── 2. VPN gate — never enumerate targets without Mullvad (cached multi-method check) ─────
# Fail-closed via the ONE cached checker (recon_vpn_check.sh): rc 0 = Mullvad-confirmed;
# any other rc (leak / unconfirmed) aborts. Uses the local known-IP cache so it does NOT
# hammer am.i.mullvad.
_bulk_vpn="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../scripts/recon_vpn_check.sh"
if [[ -f "$_bulk_vpn" ]]; then
  vpn_word="$(STATE_DIR="$STATE_DIR" bash "$_bulk_vpn" 2>/dev/null)"; vpn_rc=$?
else
  vpn_word="no-checker"; vpn_rc=2
fi
if [[ "$vpn_rc" -ne 0 ]]; then
  log "ABORT — Mullvad egress not confirmed ($vpn_word). Connect VPN and retry manually."
  exit 1
fi
log "VPN OK ($vpn_word)"

# ── 3. ES gate — bulk is useless if ES is down ────────────────────────────
_bulk_net="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../scripts/recon_net.sh"
[[ -f "$_bulk_net" ]] && source "$_bulk_net" && setup_es_netrc 2>/dev/null || true
es_status="$(curl -fsS -m5 --netrc-file "$HOME/.recon_es_netrc" http://127.0.0.1:9200/_cluster/health 2>/dev/null \
  | jq -r '.status // "unreachable"' 2>/dev/null || echo "unreachable")"
if [[ "$es_status" != "green" && "$es_status" != "yellow" ]]; then
  log "ABORT — ES unreachable (status=$es_status). Start from Docker Desktop first."
  exit 1
fi
log "ES OK (status=$es_status)"

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

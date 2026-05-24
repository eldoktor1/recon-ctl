#!/usr/bin/env bash
# =============================================================================
# recon_vpnguard.sh — VPN leak guard (FAIL-CLOSED)
#
# Single-shot; the daemon runs it every VPNGUARD_INTERVAL via supervise_loop.
# It confirms WSL egress is a Mullvad exit (am.i.mullvad.net is authoritative:
# {"mullvad_exit_ip": true|false, ...}). Posture is FAIL-CLOSED — if egress is
# NOT a confirmed Mullvad exit (a leak), OR we cannot confirm at all (network
# error / ambiguous) for FAIL_THRESHOLD consecutive checks, it:
#   1. sets the global vpn_down flag ($STATE_DIR/vpn_down), which the daemon's
#      supervise_loop honours to stop launching ANY loop, and
#   2. immediately kills every egressing recon process (reconrun scanners +
#      tools + gungnir + the passive d0k feeds) so the real IP is never exposed.
# When Mullvad is reconfirmed it clears the flag → the pipeline auto-resumes.
#
# NOTE (defense in depth): the recovery check itself is the ONE request allowed
# to egress while down, and it only goes to Mullvad's own diagnostic endpoint.
# For TRUE zero-exposure the moment a tunnel drops, also enable Mullvad's
# "Lockdown mode" in the Windows app — that blocks all traffic at the OS/network
# layer, which is something WSL cannot enforce on its own (the tunnel lives on
# Windows). This guard bounds exposure to one check interval and halts the run.
# =============================================================================
set -uo pipefail

BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
LOG_DIR="$BASE_DIR/logs"
FLAG="$STATE_DIR/vpn_down"               # presence = egress blocked / pipeline paused
STREAK_FILE="$STATE_DIR/.vpnguard_streak"
SCANNER_USER="${SCANNER_USER:-reconrun}"
CHECK_URL="${VPN_CHECK_URL:-https://am.i.mullvad.net/json}"
TIMEOUT="${VPN_CHECK_TIMEOUT:-12}"
# A CONFIRMED leak (am.i.mullvad reached, says you're NOT on Mullvad — i.e. the
# VPN actually dropped) is authoritative → trip almost immediately.
LEAK_THRESHOLD="${VPN_LEAK_THRESHOLD:-1}"
# "unknown" = the check service itself was unreachable. This is usually a
# transient blip or rate-limit (the pipeline hammers the tunnel), NOT a leak —
# a real drop makes am.i.mullvad reachable via the fallback link and return
# false (=leak). So tolerate unknowns much longer; trip only as a backstop if we
# truly cannot confirm protection for a sustained period.
UNKNOWN_THRESHOLD="${VPN_UNKNOWN_THRESHOLD:-6}"
LEAK_STREAK_FILE="$STATE_DIR/.vpnguard_leak_streak"
UNK_STREAK_FILE="$STATE_DIR/.vpnguard_unknown_streak"

mkdir -p "$STATE_DIR" "$LOG_DIR"
log() { printf '[%s VPNGUARD] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

# echo one of: ok | leak | unknown. Retries a few times before giving up, so a
# single slow response under scan load doesn't read as "unknown".
check_mullvad() {
  command -v jq >/dev/null 2>&1 || { echo unknown; return; }
  local resp m attempt
  for attempt in 1 2 3; do
    resp="$(timeout "$TIMEOUT" curl -sS --max-time "$(( TIMEOUT > 2 ? TIMEOUT - 1 : TIMEOUT ))" "$CHECK_URL" 2>/dev/null)" || resp=""
    if [[ -n "$resp" ]]; then
      m="$(printf '%s' "$resp" | jq -r '.mullvad_exit_ip // "null"' 2>/dev/null)"
      case "$m" in
        true)  echo ok;   return ;;
        false) echo leak; return ;;
      esac
    fi
    sleep 2
  done
  echo unknown
}

# Kill everything that egresses (NOT the daemon master or this guard, so the
# daemon stays up to auto-resume once Mullvad returns). Reconrun-owned procs are
# killed AS reconrun via the passwordless sudo -u reconrun rule.
kill_egress() {
  local su="${SCANNER_USER:-reconrun}"
  local TOOLS='httpx|nuclei|katana|caduceus|dalfox|subfinder|assetfinder|dnsx|\bgau\b'
  sudo -n -u "$su" pkill -TERM -f "recon_(validate|discovery|nuclei|fresh_modules|cloudrecon|dast|scope_watch|takeover_hunter)\.sh|$TOOLS" 2>/dev/null || true
  pkill -TERM -f 'recon_(true_fresh|cve_intel|vuln_feed)\.sh' 2>/dev/null || true
  pkill -TERM -f 'recon_discord_bot\.sh' 2>/dev/null || true   # stops the Discord egress too
  # gungnir CT listener (setsid process group)
  if [[ -s "$STATE_DIR/true_fresh/gungnir.pid" ]]; then
    local g; g="$(cat "$STATE_DIR/true_fresh/gungnir.pid" 2>/dev/null)"
    [[ -n "$g" ]] && { kill -TERM -- "-$g" 2>/dev/null || true; }
    rm -f "$STATE_DIR/true_fresh/gungnir.pid"
  fi
  pkill -TERM -f 'gungnir -r' 2>/dev/null || true
  # force stragglers
  sleep 1
  sudo -n -u "$su" pkill -KILL -f "$TOOLS" 2>/dev/null || true
}

res="$(check_mullvad)"
case "$res" in
  ok)
    echo 0 > "$LEAK_STREAK_FILE" 2>/dev/null || true
    echo 0 > "$UNK_STREAK_FILE" 2>/dev/null || true
    if [[ -f "$FLAG" ]]; then
      log "Mullvad exit reconfirmed — clearing vpn_down; pipeline will resume"
      rm -f "$FLAG"
    fi
    ;;
  leak)
    # Authoritative: am.i.mullvad reached, says we are NOT on a Mullvad exit.
    echo 0 > "$UNK_STREAK_FILE" 2>/dev/null || true
    n=$(( $(cat "$LEAK_STREAK_FILE" 2>/dev/null || echo 0) + 1 ))
    echo "$n" > "$LEAK_STREAK_FILE" 2>/dev/null || true
    if (( n >= LEAK_THRESHOLD )); then
      if [[ ! -f "$FLAG" ]]; then
        log "CONFIRMED LEAK — egress is NOT a Mullvad exit (streak=$n) — TRIPPING vpn_down + killing all egress"
        printf 'status=leak tripped_at=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" > "$FLAG"
      fi
      kill_egress
    else
      log "leak detected (streak $n/$LEAK_THRESHOLD)"
    fi
    ;;
  unknown)
    # Check service unreachable — usually transient/rate-limit (a real drop
    # returns 'leak', not 'unknown'). Tolerate, but fail closed as a backstop if
    # we cannot confirm protection for a sustained run of checks.
    echo 0 > "$LEAK_STREAK_FILE" 2>/dev/null || true
    n=$(( $(cat "$UNK_STREAK_FILE" 2>/dev/null || echo 0) + 1 ))
    echo "$n" > "$UNK_STREAK_FILE" 2>/dev/null || true
    if (( n >= UNKNOWN_THRESHOLD )); then
      if [[ ! -f "$FLAG" ]]; then
        log "CANNOT CONFIRM MULLVAD for $n consecutive checks — failing closed: TRIPPING vpn_down + killing egress"
        printf 'status=unknown_backstop tripped_at=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" > "$FLAG"
      fi
      kill_egress
    else
      log "VPN check unreachable (unknown streak $n/$UNKNOWN_THRESHOLD) — VPN likely still up; not tripping"
    fi
    ;;
esac
exit 0

#!/usr/bin/env bash
# recon_daemon_keepalive.sh -- systemd-supervised keepalive (recon-daemon-keepalive.service).
# WHY: recon_daemon.sh is launched detached (nohup) but UNSUPERVISED and inside the
# d0k *user* session slice. If it dies nothing restarts it; once kali has zero
# processes WSL collapses the whole distro (cold reboot -> lost terminal/tmux); and
# a WSL user-session reset (every login churns user@1000) can kill everything in the
# user slice incl. the daemon. This keepalive runs in system.slice (immune to
# user-session churn), keeps the distro alive, and revives the daemon via
# start_recon_safe (preserving the VPN fail-closed gate). Respects
# state/daemon_disabled (set by recon-stop) and state/maintenance.
set -uo pipefail
REPO_DIR="/home/d0k/recon-pipeline"
HOME="${HOME:-/home/d0k}"
STATE_DIR="${STATE_DIR:-$HOME/recon/state}"
LOG_DIR="${LOG_DIR:-$HOME/recon/logs}"
INTERVAL="${KEEPALIVE_INTERVAL:-60}"
mkdir -p "$STATE_DIR" "$LOG_DIR" 2>/dev/null || true
log(){ printf '[%s KEEPALIVE] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "$LOG_DIR/keepalive.log" 2>&1; }
# Crash-loop circuit breaker (2026-06-24): a daemon that keeps dying (e.g. a
# recurring OOM) was otherwise revived every ${INTERVAL}s FOREVER, turning a single
# failure into a permanent thrash that degraded the whole VM (the 2026-06-24
# 2-min-restart loop). Track revive timestamps in a rolling window; if we revive
# more than MAX_RESTARTS times within WINDOW seconds, TRIP: stop reviving, record
# why, alert #ops — until an operator clears it (recon-start unlinks the trip file).
# This restores "fail and alert" instead of "thrash forever". State lives in files
# so it survives keepalive restarts.
MAX_RESTARTS="${KEEPALIVE_MAX_RESTARTS:-5}"
WINDOW="${KEEPALIVE_RESTART_WINDOW:-900}"          # >5 revives / 15min = crash loop -> trip
TRIP_FILE="$STATE_DIR/keepalive_tripped"
RESTART_LOG="$STATE_DIR/keepalive_restarts.log"
ops_alert(){  # best-effort #ops webhook; never fatal
  local hook; hook="$(cat "$HOME/.recon_discord_ops" 2>/dev/null || true)"
  [[ -n "$hook" ]] || return 0
  curl -fsS -m 10 -H 'Content-Type: application/json' \
       -d "$(jq -nc --arg c "$1" '{content:$c}' 2>/dev/null)" "$hook" >/dev/null 2>&1 || true
}

log "keepalive online (interval=${INTERVAL}s, pid $$)"
while :; do
  if [[ -f "$STATE_DIR/daemon_disabled" ]]; then
    :   # deliberate stop (recon-stop) — do not revive
  elif [[ -f "$STATE_DIR/maintenance" ]]; then
    :   # maintenance lock — do not revive
  elif [[ -f "$TRIP_FILE" ]]; then
    :   # circuit breaker tripped — refuse to thrash until an operator clears it
  elif ! pgrep -f 'recon_daemon\.sh' >/dev/null 2>&1; then
    now="$(date +%s)"; echo "$now" >> "$RESTART_LOG"
    cut=$(( now - WINDOW ))
    recent="$(awk -v c="$cut" '$1>=c' "$RESTART_LOG" 2>/dev/null)"
    printf '%s\n' "$recent" | sed '/^$/d' > "$RESTART_LOG"
    n="$(wc -l < "$RESTART_LOG" | tr -d ' ')"
    if (( n > MAX_RESTARTS )); then
      printf 'tripped %s: %s daemon revives within %ss = crash loop. Auto-restart DISABLED to protect the VM. Investigate (likely OOM: dmesg / recon_daemon.log). Clear with recon-start (or rm this file).\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$n" "$WINDOW" > "$TRIP_FILE"
      log "CIRCUIT BREAKER TRIPPED: $n revives in ${WINDOW}s — refusing to thrash; auto-restart DISABLED. Clear with recon-start."
      ops_alert "recon keepalive TRIPPED: daemon crash-looped ($n restarts / ${WINDOW}s). Auto-restart DISABLED to protect the VM — likely OOM. Check dmesg + recon_daemon.log; clear with recon-start."
    else
      log "daemon DOWN -> start_recon_safe ($n/${MAX_RESTARTS} revives in ${WINDOW}s)"
      if bash "$REPO_DIR/tools/start_recon_safe.sh" >> "$LOG_DIR/keepalive.log" 2>&1; then
        log "start_recon_safe OK"
      else
        log "start_recon_safe FAILED (will retry in ${INTERVAL}s)"
      fi
    fi
  fi
  sleep "$INTERVAL"
done

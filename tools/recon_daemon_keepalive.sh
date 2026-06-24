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
log "keepalive online (interval=${INTERVAL}s, pid $$)"
while :; do
  if [[ -f "$STATE_DIR/daemon_disabled" ]]; then
    :
  elif [[ -f "$STATE_DIR/maintenance" ]]; then
    :
  elif ! pgrep -f 'recon_daemon\.sh' >/dev/null 2>&1; then
    log "daemon DOWN -> start_recon_safe"
    if bash "$REPO_DIR/tools/start_recon_safe.sh" >> "$LOG_DIR/keepalive.log" 2>&1; then
      log "start_recon_safe OK"
    else
      log "start_recon_safe FAILED (will retry in ${INTERVAL}s)"
    fi
  fi
  sleep "$INTERVAL"
done

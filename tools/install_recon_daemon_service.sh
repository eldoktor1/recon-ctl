#!/usr/bin/env bash
# install_recon_daemon_service.sh — deploy the systemd-supervised recon daemon and
# retire the fragile shell-loop keepalive. RUN AS ROOT:  sudo bash tools/install_recon_daemon_service.sh
#
# WHY: the old recon-daemon-keepalive.service re-spawned the daemon via nohup with NO
# rate limit; in WSL the daemon tree gets reaped every ~2-3 min and the unbounded
# re-spawn churn overloaded the VM into Wsl/Service/E_UNEXPECTED. This installs a
# proper systemd unit with a hard restart-rate limit, a cgroup memory cap, and clean
# cgroup kills (no orphan accumulation). See tools/systemd/recon-daemon.service.
set -euo pipefail
[[ "$(id -u)" -eq 0 ]] || { echo "Run as root: sudo bash $0"; exit 1; }

REPO="/home/d0k/recon-ctl"
UNIT_SRC="$REPO/tools/systemd/recon-daemon.service"
UNIT_DST="/etc/systemd/system/recon-daemon.service"
SYSTEMCTL="$(command -v systemctl)"

echo "[1/6] Installing $UNIT_DST"
install -m 0644 "$UNIT_SRC" "$UNIT_DST"

echo "[2/6] Passwordless control for d0k (so recon-ctl start/stop work without a prompt)"
cat > /etc/sudoers.d/recon-daemon <<EOF
d0k ALL=(root) NOPASSWD: $SYSTEMCTL start recon-daemon.service, $SYSTEMCTL stop recon-daemon.service, $SYSTEMCTL restart recon-daemon.service, $SYSTEMCTL reset-failed recon-daemon.service
EOF
chmod 0440 /etc/sudoers.d/recon-daemon
visudo -cf /etc/sudoers.d/recon-daemon >/dev/null

echo "[3/6] Retiring the old keepalive (disable + stop)"
"$SYSTEMCTL" disable --now recon-daemon-keepalive.service 2>/dev/null || true

echo "[4/6] Stopping any orphaned daemon/loop processes left by the old keepalive"
pkill -KILL -f 'recon_daemon\.sh' 2>/dev/null || true
sudo -u reconrun pkill -KILL -f 'recon_' 2>/dev/null || true

echo "[5/6] systemd daemon-reload + enable recon-daemon (NOT starting yet)"
"$SYSTEMCTL" daemon-reload
"$SYSTEMCTL" enable recon-daemon.service

echo "[6/6] Done. recon-daemon is enabled but NOT started."
echo
echo "  Next (watch it come up cleanly):"
echo "    sudo systemctl start recon-daemon       # or: recon-start"
echo "    systemctl status recon-daemon --no-pager"
echo "    journalctl -u recon-daemon -f           # watch; it should run continuously, not restart-loop"
echo
echo "  If it ever crash-loops, systemd stops after ${StartLimitBurst:-4} tries in 30min and leaves it"
echo "  'failed' (no VM thrash). Re-arm with: sudo systemctl reset-failed recon-daemon && sudo systemctl start recon-daemon"
echo
echo "  To pause across reboots: recon-ctl maintenance on   (daemon exits cleanly on the lock)"

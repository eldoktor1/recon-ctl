#!/usr/bin/env bash
# =============================================================================
# setup_mtu.sh — Lower WSL eth0 MTU to fit the Mullvad WireGuard tunnel.
#
# WHY  WSL eth0 defaults to MTU 1500, but the Windows-side Mullvad WireGuard
#   tunnel is ~1380. When a 1500-byte packet must cross the 1380 tunnel and
#   PMTUD/MSS-clamping doesn't catch it, the packet is silently dropped — a
#   PMTU blackhole that shows up as stalled TLS connections (and, with blocking
#   clients, WSL2 D-state hangs). Pinning eth0 to 1380 makes packets fit
#   end-to-end and removes that whole failure class.
#
# RUN  sudo bash scripts/setup_mtu.sh        (root needed: changes a NIC + adds
#   a tiny systemd unit so it persists across WSL restarts). Idempotent.
# =============================================================================
set -euo pipefail
MTU="${MTU:-1380}"
IFACE="${IFACE:-eth0}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "must run as root:  sudo bash scripts/setup_mtu.sh" >&2
  exit 1
fi

echo "[mtu] current: $(ip link show "$IFACE" | grep -o 'mtu [0-9]*')"

# 1) Apply immediately
ip link set dev "$IFACE" mtu "$MTU"
echo "[mtu] applied live: $IFACE -> $MTU"

# 2) Persist across WSL restarts via a systemd oneshot (systemd is enabled in
#    this distro per /etc/wsl.conf). Re-applies on every boot.
UNIT=/etc/systemd/system/wsl-mtu.service
cat > "$UNIT" <<UNITEOF
[Unit]
Description=Pin $IFACE MTU to $MTU for Mullvad WireGuard fit
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/ip link set dev $IFACE mtu $MTU
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNITEOF

systemctl daemon-reload
systemctl enable --now wsl-mtu.service >/dev/null 2>&1 || systemctl enable wsl-mtu.service
echo "[mtu] persisted via $UNIT (enabled)"
echo "[mtu] verify: $(ip link show "$IFACE" | grep -o 'mtu [0-9]*')"
echo "[mtu] done. If TLS stalls ever persist under heavy load, try MTU=1280."

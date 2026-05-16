#!/usr/bin/env bash
set -euo pipefail

USER_NAME="${1:-reconrun}"
USER_ID="$(id -u "$USER_NAME")"

# WSL2: Mullvad runs on the Windows host and protects all WSL2 egress via the
# virtual eth0 adapter. Applying an nftables kill-switch inside WSL2 would block
# reconrun from eth0 — the only path out — which defeats the scanner entirely.
if grep -qi 'microsoft\|WSL' /proc/version 2>/dev/null; then
  echo "[+] WSL2 detected — Windows Mullvad handles egress; kill-switch is a no-op here"
  nft delete table inet recon_killswitch 2>/dev/null || true
  exit 0
fi

ES_HOST_IP="${RECON_ES_HOST_IP:-}"
if [[ -z "$ES_HOST_IP" && -f /etc/resolv.conf ]]; then
  ES_HOST_IP="$(awk '/^nameserver / {print $2; exit}' /etc/resolv.conf)"
fi

WG_IFACE="${MULLVAD_IFACE:-wg-mullvad}"
echo "[+] Enabling recon kill switch for $USER_NAME uid=$USER_ID (iface=$WG_IFACE)"

nft add table inet recon_killswitch 2>/dev/null || true
nft 'add chain inet recon_killswitch output { type filter hook output priority -10; policy accept; }' 2>/dev/null || true
nft flush chain inet recon_killswitch output

nft add rule inet recon_killswitch output meta skuid "$USER_ID" ip daddr 127.0.0.0/8 accept
nft add rule inet recon_killswitch output meta skuid "$USER_ID" ip6 daddr ::1 accept
nft add rule inet recon_killswitch output meta skuid "$USER_ID" oif "$WG_IFACE" accept
if [[ "$ES_HOST_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ && "$ES_HOST_IP" != "127.0.0.1" ]]; then
  nft add rule inet recon_killswitch output meta skuid "$USER_ID" ip daddr "$ES_HOST_IP" tcp dport 9200 accept
  echo "[+] Allowing Windows-host Elasticsearch: $ES_HOST_IP:9200"
fi
nft add rule inet recon_killswitch output meta skuid "$USER_ID" reject

echo "[+] Kill switch enabled."
nft list chain inet recon_killswitch output

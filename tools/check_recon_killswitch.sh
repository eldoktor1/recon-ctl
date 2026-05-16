#!/usr/bin/env bash
set -euo pipefail

need_sudo() {
  if ! sudo -n true 2>/dev/null; then
    echo "ERROR: passwordless sudo is required for this check." >&2
    echo "Run from an approved sudo context, or verify /etc/sudoers.d/reconrun." >&2
    exit 1
  fi
}

need_sudo

echo "== nft rule =="
sudo -n nft list chain inet recon_killswitch output

echo
echo "== direct should fail =="
echo "Skipped live direct egress probe by default to avoid leaking your public IP."
echo "Rule inspection above must show a final 'meta skuid <reconrun-uid> reject'."
if [[ "${RECON_RUN_LIVE_LEAK_TEST:-0}" == "1" ]]; then
  sudo -n -u reconrun curl -s --max-time 5 https://ifconfig.me || echo "OK direct blocked"
fi

echo
echo "== VPN egress should work (and reveal a VPN IP, NOT your home IP) =="
# v2.5.6: Tor removed. The kill-switch should now permit reconrun egress only
# via the system VPN interface (assumed Mullvad WG). If this prints your home
# IP, the kill-switch is misconfigured and you have a leak. Update
# /usr/local/sbin/recon-safe-preflight + nftables rule accordingly.
sudo -n -u reconrun curl -s --max-time 20 https://ifconfig.me; echo
echo "(verify the IP above is your VPN's, not your home IP)"

echo
echo "== local ES should work =="
sudo -n -u reconrun curl -s --max-time 5 -u "elastic:$(tr -d '[:space:]' < ~/.recon_es_pass)" http://127.0.0.1:9200 | jq -r '.cluster_name // .name'

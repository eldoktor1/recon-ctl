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

# In WSL2, Mullvad runs on the Windows host and protects all egress via the
# virtual eth0 adapter. There is no local nftables kill-switch — that's correct.
if grep -qi 'microsoft\|WSL' /proc/version 2>/dev/null; then
  echo "== WSL2 detected — nftables kill-switch is a no-op (Windows Mullvad handles egress) =="
  echo ""
  echo "== VPN egress check — should show a Mullvad IP, NOT your home IP =="
  sudo -n -u reconrun curl -s --max-time 20 https://ifconfig.me; echo
  echo "(verify the IP above is your VPN exit, not your home IP)"
  echo ""
  echo "== local ES check =="
  sudo -n -u reconrun curl -s --max-time 5 --netrc-file "$HOME/.recon_es_netrc" http://127.0.0.1:9200 | jq -r '.cluster_name // .name'
  exit 0
fi

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
sudo -n -u reconrun curl -s --max-time 20 https://ifconfig.me; echo
echo "(verify the IP above is your VPN's, not your home IP)"

echo
echo "== local ES should work =="
sudo -n -u reconrun curl -s --max-time 5 --netrc-file "$HOME/.recon_es_netrc" http://127.0.0.1:9200 | jq -r '.cluster_name // .name'

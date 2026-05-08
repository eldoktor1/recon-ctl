#!/usr/bin/env bash
set -euo pipefail

USER_NAME="${1:-reconrun}"
USER_ID="$(id -u "$USER_NAME")"

echo "[+] Enabling recon kill switch for $USER_NAME uid=$USER_ID"

nft add table inet recon_killswitch 2>/dev/null || true
nft 'add chain inet recon_killswitch output { type filter hook output priority -10; policy accept; }' 2>/dev/null || true
nft flush chain inet recon_killswitch output

nft add rule inet recon_killswitch output meta skuid "$USER_ID" ip daddr 127.0.0.0/8 accept
nft add rule inet recon_killswitch output meta skuid "$USER_ID" ip6 daddr ::1 accept
nft add rule inet recon_killswitch output meta skuid "$USER_ID" reject

echo "[+] Kill switch enabled."
nft list chain inet recon_killswitch output

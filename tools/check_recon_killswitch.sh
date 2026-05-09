#!/usr/bin/env bash
set -euo pipefail

echo "== nft rule =="
sudo nft list chain inet recon_killswitch output

echo
echo "== direct should fail =="
echo "Skipped live direct egress probe by default to avoid leaking your public IP."
echo "Rule inspection above must show a final 'meta skuid <reconrun-uid> reject'."
if [[ "${RECON_RUN_LIVE_LEAK_TEST:-0}" == "1" ]]; then
  sudo -u reconrun curl -s --max-time 5 https://ifconfig.me || echo "OK direct blocked"
fi

echo
echo "== Tor should work =="
sudo -u reconrun curl -s --socks5-hostname 127.0.0.1:9050 --max-time 20 https://ifconfig.me; echo

echo
echo "== local ES should work =="
sudo -u reconrun curl -s --max-time 5 -u "elastic:$(tr -d '[:space:]' < ~/.recon_es_pass)" http://127.0.0.1:9200 | jq -r '.cluster_name // .name'

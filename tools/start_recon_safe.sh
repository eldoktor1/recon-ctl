#!/usr/bin/env bash
set -euo pipefail

cd "$HOME/recon-pipeline"

echo "[1/4] Enabling kill switch..."
sudo tools/enable_recon_killswitch.sh >/dev/null

echo "[2/4] Verifying direct outbound is blocked..."
if sudo -u reconrun curl -s --max-time 5 https://ifconfig.me >/dev/null; then
  echo "FATAL: reconrun direct outbound is NOT blocked. Refusing to start recon."
  exit 1
else
  echo "OK: direct outbound blocked"
fi

echo "[3/4] Verifying Tor + local ES..."
sudo -u reconrun curl -s --socks5-hostname 127.0.0.1:9050 --max-time 20 https://ifconfig.me >/dev/null
sudo -u reconrun curl -s --max-time 5 -u "elastic:$(tr -d '[:space:]' < "$HOME/.recon_es_pass")" http://127.0.0.1:9200 >/dev/null
echo "OK: Tor and ES work"

echo "[4/4] Starting recon safely..."
SCANNER_USER=reconrun USE_PROXYCHAINS=1 PROXY_URL=socks5://127.0.0.1:9050 "$HOME/recon_ctl.sh" start

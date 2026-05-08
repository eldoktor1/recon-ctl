#!/usr/bin/env bash
set -euo pipefail

cd "$HOME/recon-pipeline"

echo "[1/2] Running secure preflight..."
sudo -n /usr/local/sbin/recon-safe-preflight

echo "[2/2] Starting recon safely..."
SCANNER_USER=reconrun USE_PROXYCHAINS=1 PROXY_URL=socks5://127.0.0.1:9050 "$HOME/recon_ctl.sh" start

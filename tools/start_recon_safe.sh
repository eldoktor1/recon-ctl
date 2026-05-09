#!/usr/bin/env bash
set -euo pipefail

TOOL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$TOOL_DIR/.." && pwd)"
CTL_SCRIPT="$REPO_DIR/scripts/recon_ctl.sh"
[[ -f "$CTL_SCRIPT" ]] || CTL_SCRIPT="$HOME/recon_ctl.sh"

cd "$REPO_DIR"

echo "[1/2] Running secure preflight..."
sudo -n /usr/local/sbin/recon-safe-preflight

echo "[2/2] Starting recon safely..."
ES_URL="${ES_URL:-http://127.0.0.1:9200}" \
SCANNER_USER=reconrun \
USE_PROXYCHAINS=1 \
PROXY_URL="${PROXY_URL:-socks5h://127.0.0.1:9050}" \
bash "$CTL_SCRIPT" start

#!/usr/bin/env bash
set -euo pipefail

TOOL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$TOOL_DIR/.." && pwd)"
CTL_SCRIPT="$REPO_DIR/scripts/recon_ctl.sh"

cd "$REPO_DIR"

echo "[1/2] Running secure preflight..."
sudo -n /usr/local/sbin/recon-safe-preflight

echo "[2/2] Starting recon safely..."
# v2.5.6: Tor/proxychains removed. Egress is now the host's default route,
# expected to be Mullvad WireGuard, enforced by the nftables kill-switch
# on the reconrun uid (operator-managed in /usr/local/sbin/recon-safe-preflight).
ES_URL="${ES_URL:-http://127.0.0.1:9200}" \
SCANNER_USER=reconrun \
USE_PROXYCHAINS=0 \
PROXY_URL="" \
bash "$CTL_SCRIPT" start

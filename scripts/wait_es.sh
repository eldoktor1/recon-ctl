#!/usr/bin/env bash
# wait_es.sh — poll ES until it's up (max 120s)
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/recon_net.sh"
setup_es_netrc

echo "Polling ES (max 120s)..."
for i in $(seq 1 30); do
  result="$(curl -fsS -m5 --netrc-file "$HOME/.recon_es_netrc" http://127.0.0.1:9200/_cluster/health 2>/dev/null)"
  if printf '%s' "$result" | grep -q '"status"'; then
    echo ""
    echo "ES UP after $((i*4))s"
    printf '%s\n' "$result"
    exit 0
  fi
  printf '.'
  sleep 4
done
echo ""
echo "ES did not come up within 120s"
exit 1

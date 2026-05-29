#!/usr/bin/env bash
# wait_es.sh — poll ES until it's up, then start the recon daemon
ep="$(tr -d '[:space:]' < ~/.recon_es_pass 2>/dev/null)"
echo "ES pass length: ${#ep}"
echo "Polling ES (max 120s)..."
for i in $(seq 1 30); do
  result="$(curl -fsS -m5 -u "elastic:${ep}" http://127.0.0.1:9200/_cluster/health 2>/dev/null)"
  if echo "$result" | grep -q '"status"'; then
    echo ""
    echo "✅ ES UP after $((i*4))s"
    echo "$result"
    exit 0
  fi
  printf '.'
  sleep 4
done
echo ""
echo "❌ ES did not come up within 120s"
exit 1

#!/usr/bin/env bash
# Fix: discord webhook files not readable by reconrun + known_hosts not touchable by d0k
# Run as d0k: bash ~/recon-ctl/tools/fix_perms.sh

set -euo pipefail

echo "=== Fixing discord webhook group ownership ==="
sudo chown d0k:reconrun \
  ~/.recon_discord_fresh \
  ~/.recon_discord_takeovers \
  ~/.recon_discord_vulns \
  ~/.recon_discord_cve \
  ~/.recon_discord_health
chmod 640 \
  ~/.recon_discord_fresh \
  ~/.recon_discord_takeovers \
  ~/.recon_discord_vulns \
  ~/.recon_discord_cve \
  ~/.recon_discord_health
echo "Webhook files:"
ls -la ~/.recon_discord_{fresh,takeovers,vulns,cve,health}

echo ""
echo "=== Fixing known_hosts.txt (reconrun owns, d0k can't touch) ==="
sudo chmod 664 ~/recon/state/known_hosts.txt
ls -la ~/recon/state/known_hosts.txt

echo ""
echo "=== Verify reconrun can read fresh webhook ==="
sudo -u reconrun sh -c 'wc -c < ~/.recon_discord_fresh'
echo "bytes (>0 = OK)"

echo ""
echo "=== All done. Triage Discord alerts should now work. ==="

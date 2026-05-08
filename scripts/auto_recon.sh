#!/usr/bin/env bash
# auto_recon.sh — Compat shim. Calls discovery once then validate once.
# The proper way to run is `recon_ctl start` (daemon), but old crons may hit this.
set -uo pipefail
HERE="${HERE:-$HOME}"
echo "[auto_recon] one-shot discovery+validate (use 'recon_ctl start' for daemon mode)"
bash "$HERE/recon_discovery.sh" || echo "[auto_recon] discovery non-zero"
bash "$HERE/recon_validate.sh"  || echo "[auto_recon] validate non-zero"
echo "[auto_recon] done"

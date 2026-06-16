#!/usr/bin/env bash
# =============================================================================
# recon_selfaudit.sh — recon-audit entrypoint (the standing self-audit).
#
# Runs the codified invariant battery (engine/selfaudit.py) that turns the manual
# docs/audit_*.md into a repeatable check. DRY-RUN by default: it only DETECTS and
# reports (docs/audit_<date>.md + ~/recon/state/selfaudit_latest.json) and fires a
# cooled-down #ops summary for anything that needs a brain.
#
#   recon_selfaudit.sh            dry-run report
#   recon_selfaudit.sh --apply    dry-run + the item-2 reversible-state whitelist
#                                  (operator-only; the daemon NEVER passes --apply)
#   recon_selfaudit.sh --json     machine-readable to stdout
#   recon_selfaudit.sh --no-ops   skip the Discord post (testing)
#
# HARD BOUNDARY: --apply may ONLY touch the whitelist (stale locks, dead PID file,
# known-good perms, spool retry, log rotation). It NEVER edits code/config, touches
# egress/Mullvad/nftables, clears vpn_down, disables a gate, or restarts the daemon.
# Live-restart-safe. Exit non-zero if any HIGH check is unresolved.
# =============================================================================
set -uo pipefail

BASE_DIR="${BASE_DIR:-$HOME/recon}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SELFAUDIT_PY="$REPO_DIR/engine/selfaudit.py"

[[ -f "$SELFAUDIT_PY" ]] || { echo "[recon-audit] missing $SELFAUDIT_PY" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "[recon-audit] python3 not found" >&2; exit 2; }

export BASE_DIR RECON_REPO_DIR="$REPO_DIR"
exec python3 "$SELFAUDIT_PY" "$@"

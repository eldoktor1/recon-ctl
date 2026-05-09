#!/usr/bin/env bash
# =============================================================================
# recon_killswitch.sh — Helper to check V2 module status from any script
#
# Usage:
#   recon_killswitch.sh check <module>     # exit 0 if active, 1 if killed
#   recon_killswitch.sh trip <module> <reason>
#   recon_killswitch.sh reset <module>
#   recon_killswitch.sh list
# =============================================================================

set -u

KILL_DIR="${HOME}/recon/state/kill"
mkdir -p "$KILL_DIR"

case "${1:-}" in
  check)
    mod="${2:-}"
    [[ -z "$mod" ]] && exit 2
    [[ -f "$KILL_DIR/v2_$mod" ]] && exit 1
    exit 0
    ;;
  trip)
    mod="${2:-}"
    reason="${*:3}"
    [[ -z "$mod" ]] && exit 2
    echo "${reason:-manual}" > "$KILL_DIR/v2_$mod"
    echo "tripped: v2_$mod"
    ;;
  reset)
    mod="${2:-}"
    [[ -z "$mod" ]] && exit 2
    rm -f "$KILL_DIR/v2_$mod"
    echo "reset: v2_$mod"
    ;;
  list)
    for k in "$KILL_DIR"/v2_*; do
      [[ -f "$k" ]] && printf "%s — %s\n" "$(basename "$k")" "$(cat "$k")"
    done
    ;;
  *)
    echo "usage: $0 {check|trip|reset|list} <module> [reason]"
    exit 2
    ;;
esac

#!/usr/bin/env bash
# walk_stale.sh — list program walks whose document is older than its workspace.
# A stale walk document is a BUG, not a quiet degrade: the board is the record.
set -uo pipefail
stale=0
for ws in /home/d0k/recon/workspaces/*.json; do
  key=$(basename "$ws" .json)
  doc="/home/d0k/recon-ctl/evidence/$key/${key}_walk.html"
  [[ -f "$doc" ]] || continue
  if [[ "$ws" -nt "$doc" ]]; then
    printf 'STALE  %-14s workspace %s > document %s\n' "$key" \
      "$(date -r "$ws" +%Y-%m-%dT%H:%M)" "$(date -r "$doc" +%Y-%m-%dT%H:%M)"
    stale=$((stale+1))
  else
    printf 'fresh  %-14s %s\n' "$key" "$(date -r "$doc" +%Y-%m-%dT%H:%M)"
  fi
done
[[ $stale -gt 0 ]] && { echo; echo "$stale stale walk document(s) — run: tools/walk_publish.sh <key>"; exit 1; }
echo; echo "all walk documents current"

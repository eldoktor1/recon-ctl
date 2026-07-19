#!/usr/bin/env bash
# =============================================================================
# recon_es_backup.sh — Elasticsearch snapshot backup mechanism for recon_alive.
#
# WHY: the ~2.8M-doc recon_alive corpus (crawl/triage enrichment + host_notes/
# ignore mutations) lives ONLY in ES. The flat files (host_notes.jsonl /
# ignored.jsonl) are a durable write-log for notes/ignores, but the enriched
# corpus is not in git and is not otherwise reproducible. Before 2026-07-19 ES
# had NO backup at all (no snapshot repo, no SLM, path.repo unset, single-node
# 0-replica). This script is the committed, idempotent mechanism.
#
# ONE-TIME HOST PREREQ (NOT in this repo — the compose file is on the Windows
# side at C:\recon\recon_database\docker-compose.yml, outside the git tree):
#   Under service `elasticsearch`, add:
#     environment:
#       - path.repo=/snapshots
#     volumes:
#       - C:/recon/es_snapshots:/snapshots     # host dir for snapshot files
#   then recreate:  docker compose up -d elasticsearch
#   Snapshot files then land on the host at C:\recon\es_snapshots.
#   NOTE: sync that host dir OFF-box (external/cloud) so a disk failure can't
#   take the backups with the live data — snapshots on the same disk protect
#   against corruption/bad-writes/deletion, NOT drive loss.
#
# THIS SCRIPT WRITES NO DATA TO THE REPO. Snapshots live on the ES host only.
#
# Subcommands:
#   setup            register the `recon_backup` fs repo + `recon-daily` SLM
#                    policy (idempotent — safe to re-run).
#   now              trigger a snapshot immediately via the SLM policy.
#   list             list all snapshots in the repo (name/state/time).
#   status           repo + SLM policy status (last success/failure, next run).
#   restore <snap>   restore a named snapshot (PROMPTS — closes target indices).
#
# ES conn follows repo convention: RECON_ES_URL (default http://127.0.0.1:9200)
# + RECON_ES_NETRC (default ~/.recon_es_netrc). If the WSL->Windows localhost
# hop is down, set RECON_ES_URL or run from where ES is reachable.
# =============================================================================
set -euo pipefail

ES_URL="${RECON_ES_URL:-http://127.0.0.1:9200}"
ES_NETRC="${RECON_ES_NETRC:-$HOME/.recon_es_netrc}"
REPO="${RECON_ES_BACKUP_REPO:-recon_backup}"
POLICY="${RECON_ES_BACKUP_POLICY:-recon-daily}"
LOCATION="${RECON_ES_BACKUP_LOCATION:-/snapshots}"   # path.repo subdir in the ES container

_es() {  # <curl-args...> ; prints body, returns curl status
  curl -fsS -m 30 --netrc-file "$ES_NETRC" -H 'Content-Type: application/json' "$@"
}

_require() {
  command -v curl >/dev/null 2>&1 || { echo "curl not found" >&2; exit 1; }
  [[ -f "$ES_NETRC" ]] || { echo "ES netrc not found: $ES_NETRC" >&2; exit 1; }
}

cmd_setup() {
  _require
  echo "[*] registering fs repository '$REPO' -> $LOCATION"
  _es -X PUT "$ES_URL/_snapshot/$REPO" -d "$(cat <<JSON
{"type":"fs","settings":{"location":"$LOCATION","compress":true}}
JSON
)"; echo
  echo "[*] verifying repository (checks path.repo is set + writable)"
  _es -X POST "$ES_URL/_snapshot/$REPO/_verify" >/dev/null && echo "    ok"
  echo "[*] creating SLM policy '$POLICY' (daily 01:30, indices recon_alive*, retention 14d)"
  _es -X PUT "$ES_URL/_slm/policy/$POLICY" -d "$(cat <<JSON
{"schedule":"0 30 1 * * ?",
 "name":"<recon-{now/d}>",
 "repository":"$REPO",
 "config":{"indices":["recon_alive*"],"ignore_unavailable":true,"include_global_state":false},
 "retention":{"expire_after":"14d","min_count":5,"max_count":30}}
JSON
)"; echo
  echo "[+] setup complete. Trigger a first snapshot with: $0 now"
}

cmd_now() {
  _require
  echo "[*] executing SLM policy '$POLICY' now"
  _es -X POST "$ES_URL/_slm/policy/$POLICY/_execute"; echo
  echo "    watch with: $0 list"
}

cmd_list() {
  _require
  _es "$ES_URL/_snapshot/$REPO/_all?filter_path=snapshots.snapshot,snapshots.state,snapshots.start_time,snapshots.shards"
  echo
}

cmd_status() {
  _require
  echo "=== repository ==="; _es "$ES_URL/_snapshot/$REPO?pretty"; echo
  echo "=== SLM policy ===";  _es "$ES_URL/_slm/policy/$POLICY?pretty"; echo
}

cmd_restore() {
  _require
  local snap="${1:-}"
  [[ -n "$snap" ]] || { echo "usage: $0 restore <snapshot-name>  (see: $0 list)" >&2; exit 1; }
  echo "!!! RESTORE '$snap' will CLOSE and overwrite matching recon_alive* indices."
  read -r -p "    Type the snapshot name again to confirm: " confirm
  [[ "$confirm" == "$snap" ]] || { echo "aborted." >&2; exit 1; }
  _es -X POST "$ES_URL/_snapshot/$REPO/$snap/_restore" -d '{"indices":"recon_alive*"}'; echo
}

case "${1:-status}" in
  setup)   cmd_setup ;;
  now)     cmd_now ;;
  list)    cmd_list ;;
  status)  cmd_status ;;
  restore) shift; cmd_restore "$@" ;;
  *) echo "usage: $0 {setup|now|list|status|restore <snap>}" >&2; exit 1 ;;
esac

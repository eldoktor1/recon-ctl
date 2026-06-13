#!/usr/bin/env bash
# =============================================================================
# recon_ledger_es.sh — mirror the flat-file ledgers (host_notes.jsonl /
# ignored.jsonl) into the ES `recon_alive` index so ES is the SINGLE SOURCE
# OF TRUTH. Sourced by recon_notes.sh (and therefore recon_ctl.sh).
#
# Every note_add / cmd_ignore writes back to ALL ES docs for the host via two
# stored painless scripts (recon_note_push / recon_ignore_push). The flat files
# remain the durable write-log; ES becomes the queryable mirror agents read.
#
# Fields written on recon_alive: host_notes[] {note,source,created_at},
#   host_notes_count, host_notes_text, ignore_active, ignore_reason,
#   ignore_added_at, ignore_expires_at, ledger_synced_at.
#
# Best-effort + non-fatal: never fails the caller. Disable with
# RECON_ES_WRITEBACK=0. AUTHORITATIVE "actively benched" check for a querying
# agent = range ignore_expires_at > now (self-correcting past the 7d TTL);
# ignore_active is the write-time snapshot.
# =============================================================================
_LEDGER_ES_URL="${RECON_ES_URL:-http://127.0.0.1:9200}"
_LEDGER_ES_NETRC="${RECON_ES_NETRC:-$HOME/.recon_es_netrc}"
_LEDGER_ES_INDEX="${RECON_ES_INDEX:-recon_alive}"

_ledger_es_uq() {  # JSON body on stdin -> _update_by_query (best-effort)
  [[ "${RECON_ES_WRITEBACK:-1}" == "1" ]] || return 0
  command -v jq   >/dev/null 2>&1 || return 0
  command -v curl >/dev/null 2>&1 || return 0
  [[ -f "$_LEDGER_ES_NETRC" ]] || return 0
  curl -fsS -m 8 --netrc-file "$_LEDGER_ES_NETRC" \
    -H 'Content-Type: application/json' \
    "$_LEDGER_ES_URL/$_LEDGER_ES_INDEX/_update_by_query?conflicts=proceed&refresh=false" \
    --data-binary @- >/dev/null 2>&1 || true
}

es_note_push() {  # <host> <note> [source] [created_at]
  local host="${1:-}" note="${2:-}" source="${3:-manual}" created="${4:-}"
  [[ -n "$host" && -n "$note" ]] || return 0
  local now; now="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  [[ -n "$created" ]] || created="$now"
  jq -nc --arg host "$host" --arg note "$note" --arg source "$source" \
         --arg created "$created" --arg now "$now" \
    '{query:{term:{host:$host}},
      script:{id:"recon_note_push",
        params:{note:$note,source:$source,created:$created,now:$now}}}' \
    | _ledger_es_uq
}

es_ignore_push() {  # <host> <reason> [added_at] [expires_at]
  local host="${1:-}" reason="${2:-}" added="${3:-}" expires="${4:-}"
  [[ -n "$host" ]] || return 0
  local now; now="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  [[ -n "$added" ]] || added="$now"
  jq -nc --arg host "$host" --arg reason "$reason" --arg added "$added" \
         --arg expires "$expires" --arg now "$now" \
    '{query:{term:{host:$host}},
      script:{id:"recon_ignore_push",
        params:{reason:$reason,added:$added,expires:$expires,now:$now}}}' \
    | _ledger_es_uq
}

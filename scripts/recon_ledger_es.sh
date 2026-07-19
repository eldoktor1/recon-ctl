#!/usr/bin/env bash
# =============================================================================
# recon_ledger_es.sh — mirror the flat-file ledgers (host_notes.jsonl /
# ignored.jsonl) into the ES `recon_alive` index so ES is the SINGLE SOURCE
# OF TRUTH. Sourced by recon_notes.sh (and therefore recon_ctl.sh).
#
# Every note_add / cmd_ignore UPSERTS the host's recon_alive doc (keyed
# _id=host, one doc/host) via a single-doc _update with scripted_upsert
# (stored painless scripts recon_note_push / recon_ignore_push).
# CREATE-IF-MISSING: a note/ignore on a host the pipeline never enumerated
# (e.g. a manual private-program host) STILL lands in ES as a fresh doc — so
# note-taking is ALWAYS consistent and ES stays the queryable source of truth.
# (Previously used _update_by_query, which no-op'd when no doc existed for the
# host — that silently dropped notes for manually-worked hosts. Fixed 2026-07-19.)
# The flat files remain the durable write-log.
#
# Fields written on recon_alive: host_notes[] {note,source,created_at},
#   host_notes_count, host_notes_text, ignore_active, ignore_reason,
#   ignore_added_at, ignore_expires_at, ledger_synced_at. New docs also seed
#   host, root_domain, first_seen, last_seen, source.
#
# Best-effort + non-fatal: never fails the caller. Disable with
# RECON_ES_WRITEBACK=0. AUTHORITATIVE "actively benched" check for a querying
# agent = range ignore_expires_at > now (self-correcting past the 7d TTL);
# ignore_active is the write-time snapshot.
# =============================================================================
_LEDGER_ES_URL="${RECON_ES_URL:-http://127.0.0.1:9200}"
_LEDGER_ES_NETRC="${RECON_ES_NETRC:-$HOME/.recon_es_netrc}"
_LEDGER_ES_INDEX="${RECON_ES_INDEX:-recon_alive}"

_ledger_es_rootdomain() {  # last two labels (matches the engine's _root_domain)
  awk -F. '{ if (NF>=2) printf "%s.%s\n",$(NF-1),$NF; else print $0 }' <<<"${1:-}"
}

_ledger_es_upsert() {  # <host> ; _update body (script+upsert+scripted_upsert) on stdin
  [[ "${RECON_ES_WRITEBACK:-1}" == "1" ]] || return 0
  command -v jq   >/dev/null 2>&1 || return 0
  command -v curl >/dev/null 2>&1 || return 0
  [[ -f "$_LEDGER_ES_NETRC" ]] || return 0
  local host="${1:-}"; [[ -n "$host" ]] || return 0
  # _id=host; hostnames are URL-path-safe (a-z0-9.-). scripted_upsert runs the
  # stored script on both create and update, so the note/ignore always lands.
  curl -fsS -m 8 --netrc-file "$_LEDGER_ES_NETRC" \
    -H 'Content-Type: application/json' \
    "$_LEDGER_ES_URL/$_LEDGER_ES_INDEX/_update/$host?refresh=false&retry_on_conflict=5" \
    --data-binary @- >/dev/null 2>&1 || true
}

es_note_push() {  # <host> <note> [source] [created_at]
  local host="${1:-}" note="${2:-}" source="${3:-manual}" created="${4:-}"
  [[ -n "$host" && -n "$note" ]] || return 0
  local now rd; now="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"; rd="$(_ledger_es_rootdomain "$host")"
  [[ -n "$created" ]] || created="$now"
  jq -nc --arg host "$host" --arg rd "$rd" --arg note "$note" --arg source "$source" \
         --arg created "$created" --arg now "$now" \
    '{scripted_upsert:true,
      script:{id:"recon_note_push",
        params:{note:$note,source:$source,created:$created,now:$now}},
      upsert:{host:$host, root_domain:$rd, first_seen:$now, last_seen:$now, source:"note-upsert"}}' \
    | _ledger_es_upsert "$host"
}

es_ignore_push() {  # <host> <reason> [added_at] [expires_at]
  local host="${1:-}" reason="${2:-}" added="${3:-}" expires="${4:-}"
  [[ -n "$host" ]] || return 0
  local now rd; now="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"; rd="$(_ledger_es_rootdomain "$host")"
  [[ -n "$added" ]] || added="$now"
  jq -nc --arg host "$host" --arg rd "$rd" --arg reason "$reason" --arg added "$added" \
         --arg expires "$expires" --arg now "$now" \
    '{scripted_upsert:true,
      script:{id:"recon_ignore_push",
        params:{reason:$reason,added:$added,expires:$expires,now:$now}},
      upsert:{host:$host, root_domain:$rd, first_seen:$now, last_seen:$now, source:"ignore-upsert"}}' \
    | _ledger_es_upsert "$host"
}

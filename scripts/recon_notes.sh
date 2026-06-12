#!/usr/bin/env bash
# =============================================================================
# recon_notes.sh — PERMANENT host notes (worked-knowledge). Sourced lib.
#
# Distinct from ignored.jsonl (a willing 7-DAY TTL penalty): notes NEVER expire.
# When a host resurfaces, its notes announce what I already found / tested-clean.
#
# Store: ~/recon/state/host_notes.jsonl (append-only, never TTL'd). One JSON/line:
#   {host, root_domain, program, note, source(ignore|triage|manual|2ic), created_at}
#
# API (source this file):
#   note_add <host> <note> [source] [created_at] [program] [root_domain]
#       upsert a note; dedups on (host, note). root_domain auto = last 2 labels;
#       program auto-filled from recon_scope_check.sh unless given or NOTES_NO_SCOPE=1.
#   note_get <host>   -> matching notes (host- AND root-domain-level), newest first (JSONL)
#   note_has <host>   -> exit 0 if any note for the host or its root_domain
# =============================================================================
NOTES_FILE="${NOTES_FILE:-$HOME/recon/state/host_notes.jsonl}"
_NOTES_SCOPE_CHECK="${_NOTES_SCOPE_CHECK:-$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)/recon_scope_check.sh}"

_note_root_domain() {  # last two labels (matches the engine's _root_domain)
  awk -F. '{ if (NF>=2) printf "%s.%s\n",$(NF-1),$NF; else print $0 }' <<<"${1:-}"
}

note_add() {  # <host> <note> [source] [created_at] [program] [root_domain]
  local host="${1:-}" note="${2:-}" source="${3:-manual}" created_at="${4:-}" program="${5:-}" rd="${6:-}"
  [[ -n "$host" && -n "$note" ]] || return 1
  command -v jq >/dev/null 2>&1 || return 1
  mkdir -p "$(dirname "$NOTES_FILE")" 2>/dev/null || true
  touch "$NOTES_FILE" 2>/dev/null || true
  [[ -n "$created_at" ]] || created_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  [[ -n "$rd" ]] || rd="$(_note_root_domain "$host")"
  if [[ -z "$program" && "${NOTES_NO_SCOPE:-0}" != "1" && -f "$_NOTES_SCOPE_CHECK" ]]; then
    program="$(bash "$_NOTES_SCOPE_CHECK" "$host" 2>/dev/null | jq -r '.program // empty' 2>/dev/null || true)"
  fi
  (
    flock -w 5 9 || exit 0
    # dedup on (host, note): identical pair already present -> no-op
    if jq -e --arg h "$host" --arg n "$note" 'select(.host==$h and .note==$n)' "$NOTES_FILE" >/dev/null 2>&1; then
      exit 0
    fi
    jq -nc --arg host "$host" --arg rd "$rd" --arg program "$program" \
           --arg note "$note" --arg source "$source" --arg created_at "$created_at" \
      '{host:$host, root_domain:$rd, program:(($program|select(.!=""))//null),
        note:$note, source:$source, created_at:$created_at}' >> "$NOTES_FILE"
  ) 9>>"$NOTES_FILE.lock"
}

note_get() {  # <host> -> host- and root-domain-level notes, newest first
  local host="${1:-}"; [[ -n "$host" && -s "$NOTES_FILE" ]] || return 0
  local rd; rd="$(_note_root_domain "$host")"
  jq -c --arg h "$host" --arg rd "$rd" 'select(.host==$h or .root_domain==$rd)' "$NOTES_FILE" 2>/dev/null \
    | jq -s -c 'sort_by(.created_at)|reverse|.[]' 2>/dev/null
}

note_has() {  # <host> -> exit 0 if any note for the host or its root_domain
  local host="${1:-}"; [[ -n "$host" && -s "$NOTES_FILE" ]] || return 1
  local rd; rd="$(_note_root_domain "$host")"
  jq -e --arg h "$host" --arg rd "$rd" 'select(.host==$h or .root_domain==$rd)' "$NOTES_FILE" >/dev/null 2>&1
}

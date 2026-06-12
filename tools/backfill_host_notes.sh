#!/usr/bin/env bash
# =============================================================================
# backfill_host_notes.sh — one-time (idempotent) backfill of host_notes.jsonl.
#
# Two reason sources, both already-persisted:
#   1. ~/recon/state/ignored.jsonl — append-only, never pruned (the 7d TTL is a read-time
#      filter only), so it holds EVERY recon-ignore reason ever typed (active or expired).
#      For each entry with a REAL reason (reason != "manual") -> note_add source="ignore",
#      created_at = entry.added_at. ("manual" = the no-reason default -> skipped, no signal.)
#   2. ES recon_alive docs with triage_ignored=true -> field triage_ignored_reason: the
#      pipeline's AUTO-ignores -> note_add source="triage" (distinct from reasons I typed).
# note_add dedups on (host, note), so a second run adds nothing. Read-only on ES.
# =============================================================================
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../scripts/recon_notes.sh"
export NOTES_NO_SCOPE=1          # don't run scope_check per row (program filled from ES for triage)

IGNORED="${IGNORED_FILE:-$HOME/recon/state/ignored.jsonl}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"
INDEX="${INDEX_NAME:-recon_alive}"
NETRC="$HOME/.recon_es_netrc"
command -v jq >/dev/null 2>&1 || { echo "jq required" >&2; exit 1; }

ign=0
if [[ -s "$IGNORED" ]]; then
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    h="$(jq -r '.host // empty' <<<"$line" 2>/dev/null)"
    r="$(jq -r '.reason // empty' <<<"$line" 2>/dev/null)"
    a="$(jq -r '.added_at // empty' <<<"$line" 2>/dev/null)"
    [[ -n "$h" && -n "$r" ]] || continue
    note_add "$h" "$r" "ignore" "$a" && ign=$((ign+1))
  done < <(jq -c 'select((.reason // "manual") != "manual")' "$IGNORED" 2>/dev/null)
fi
echo "ignore reasons processed: $ign"

tri=0
if [[ -f "$NETRC" ]]; then
  resp="$(curl -sS --netrc-file "$NETRC" -H 'Content-Type: application/json' \
    "$ES_URL/$INDEX/_search" -d '{"size":10000,"_source":["host","triage_ignored_reason","triage_program","first_seen","last_seen"],"query":{"term":{"triage_ignored":true}}}' 2>/dev/null || echo '')"
  total="$(jq -r '.hits.total.value // 0' <<<"$resp" 2>/dev/null || echo 0)"
  [[ "${total:-0}" -gt 10000 ]] && echo "WARN: $total triage_ignored docs, capped at 10000 (re-run or raise size)"
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    h="$(jq -r '.host // empty' <<<"$line" 2>/dev/null)"
    r="$(jq -r '.triage_ignored_reason // empty' <<<"$line" 2>/dev/null)"
    p="$(jq -r '.triage_program // empty' <<<"$line" 2>/dev/null)"
    c="$(jq -r '(.first_seen // .last_seen // "") | tostring' <<<"$line" 2>/dev/null)"
    [[ -n "$h" && -n "$r" ]] || continue
    note_add "$h" "$r" "triage" "$c" "$p" && tri=$((tri+1))
  done < <(printf '%s' "$resp" | jq -c '.hits.hits[]?._source | select((.triage_ignored_reason // "") != "")' 2>/dev/null)
fi
echo "triage auto-ignore reasons processed: $tri"
echo "host_notes.jsonl total lines: $(wc -l < "$NOTES_FILE" 2>/dev/null || echo 0)"

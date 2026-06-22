#!/usr/bin/env bash
# =============================================================================
# recon_restale.sh — Re-queue stale P0/P1 hosts for fresh re-validation
#
# PROBLEM
#   The pipeline discovers new hosts continuously but never re-probes old
#   high-value ones. A P1 host from 3 weeks ago might now have:
#     - A new admin panel that appeared on the root path
#     - Changed tech stack (e.g., switched to a framework with known vulns)
#     - Status change (302 → 200 with real attack surface)
#     - New HTTP response headers revealing service info
#
# SOLUTION
#   P0/P1 hosts not re-validated in >RESTALE_DAYS are written back into the
#   inbox queue as a normal batch file. The existing validate pipeline
#   (httpx → ES ingest → triage) handles the rest automatically.
#   No special handling required — ES upsert overwrites stale fields.
#
# INTERVAL: 8h  |  BATCH: 200 hosts per injection
# =============================================================================
set -uo pipefail
IFS=$'\n\t'

log() { printf '[%s RESTALE] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/recon_net.sh"
setup_es_netrc
ES_AUTH=(--netrc-file "$HOME/.recon_es_netrc")

BASE_DIR="${BASE_DIR:-$HOME/recon}"
INBOX_DIR="${INBOX_DIR:-$BASE_DIR/queue/inbox}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"
INDEX_NAME="${INDEX_NAME:-recon_alive}"

RESTALE_BATCH="${RESTALE_BATCH:-200}"        # hosts injected per run
RESTALE_DAYS="${RESTALE_DAYS:-14}"           # re-validate threshold (days)
RESTALE_MIN_SCORE="${RESTALE_MIN_SCORE:-8}"  # P1+ only (score >= 8)
RESTALE_INBOX_CAP="${RESTALE_INBOX_CAP:-1000}"  # backpressure: skip re-stale while validate queue is already deep

LOCK_FILE="$BASE_DIR/state/restale.lock"
exec 9>"$LOCK_FILE"
flock -n 9 || { log "restale already running"; exit 0; }

# Backpressure: never pile onto an already-deep validator queue. Without this guard restale
# accumulated a 33k-file backlog that starved the new discovery lanes; validate drains the
# queue before we add more refresh churn (restale hosts re-stale naturally and get re-picked).
_iq="$(find "$INBOX_DIR" -maxdepth 1 -name '*.txt' 2>/dev/null | wc -l | tr -d ' ')"
[[ "${_iq:-0}" -ge "$RESTALE_INBOX_CAP" ]] && { log "inbox already deep (${_iq} >= ${RESTALE_INBOX_CAP}) — skip re-stale (backpressure)"; exit 0; }

cutoff="$(date -u -d "-${RESTALE_DAYS} days" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || \
  python3 -c "
from datetime import datetime, timedelta
print((datetime.utcnow()-timedelta(days=${RESTALE_DAYS})).strftime('%Y-%m-%dT%H:%M:%SZ'))
")"

# Query: P0/P1 in-scope paying hosts, last_seen older than cutoff OR no last_seen
query="$(jq -nc \
  --arg cutoff "$cutoff" \
  --argjson min_score "$RESTALE_MIN_SCORE" \
  --argjson size "$RESTALE_BATCH" '{
    size: $size,
    _source: ["host","triage_priority","triage_score","last_seen"],
    query: {bool: {
      filter: [
        {terms: {triage_priority: ["P0","P1"]}},
        {term: {triage_in_scope: true}},
        {term: {triage_pays: true}},
        {range: {triage_score: {gte: $min_score}}}
      ],
      should: [
        {range: {last_seen: {lte: $cutoff}}},
        {bool: {must_not: {exists: {field: "last_seen"}}}}
      ],
      minimum_should_match: 1
    }},
    sort: [{triage_score: {order: "desc"}}]
  }')"

resp="$(curl -sS -m30 "${ES_AUTH[@]}" -H 'Content-Type: application/json' \
  -X POST "$ES_URL/$INDEX_NAME/_search" -d "$query" 2>/dev/null)"

total="$(printf '%s' "$resp" | jq -r '.hits.total.value // 0')"
log "Stale P0/P1 hosts (not re-validated in >${RESTALE_DAYS}d): $total — re-queuing up to $RESTALE_BATCH"

[[ "$total" -eq 0 ]] && { log "Nothing stale this cycle"; exit 0; }

# Write to inbox — validate loop picks it up on its next cycle (max 2 min delay)
out="$INBOX_DIR/restale_$(date -u +%Y%m%dT%H%M%SZ).txt"
printf '%s' "$resp" | jq -r '.hits.hits[]._source.host' > "$out"
n="$(wc -l < "$out" | tr -d ' ')"
log "Re-queued $n stale hosts → $(basename "$out")"

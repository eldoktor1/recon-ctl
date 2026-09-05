#!/usr/bin/env bash
# =============================================================================
# recon_scope_resync.sh — re-derive the ES scope/pays fields from the scope DB
#
# WHY THIS EXISTS
#   triage.sh writes triage_pays / triage_in_scope / triage_out_of_scope /
#   triage_payout_tier / triage_program / triage_platform straight from
#   recon_scope_check.sh, so ES is only ever as current as the last time triage
#   happened to rotate that doc. FULL triage sorts most-stale-first under
#   TRIAGE_MAX_CANDIDATES, so on a ~500k-doc index a scope change takes several
#   cycles to reach every host — and `pays` is the money gate on every lane, so
#   a stale `true` means budget spent on surface that can never pay.
#
#   This is the one-shot correction: recompute every alive host against the
#   CURRENT scope DB and write back only the docs that actually differ. Run it
#   after any change to how scope is derived (a normalizer fix, a resolution
#   rule) — the daily feed drift is handled fine by triage rotation on its own.
#
# WHAT IT DOES NOT DO
#   It does not re-score. triage_score / triage_priority carry the payout-tier
#   and pays bonuses, and re-deriving those here would fork triage scoring math
#   into a second implementation. Scores self-correct on the next triage
#   rotation; the SCOPE GATES every lane reads are corrected immediately.
#
#   No target traffic, no egress: localhost ES + the local scope TSV only.
#
# USAGE
#   bash scripts/recon_scope_resync.sh              # dry-run: report drift only
#   bash scripts/recon_scope_resync.sh --apply      # write the corrections
#   bash scripts/recon_scope_resync.sh --apply --limit 5000
# =============================================================================

set -uo pipefail
IFS=$'\n\t'

log()  { printf '[%s RESYNC] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s RESYNC WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
die()  { printf '[%s RESYNC ERROR] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; exit 1; }

for c in curl jq python3; do command -v "$c" >/dev/null || die "missing: $c"; done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCOPE_CHECK="${SCOPE_CHECK:-$SCRIPT_DIR/recon_scope_check.sh}"
SCOPE_DIR="${SCOPE_DIR:-$HOME/recon/scope}"
INSCOPE_TSV="$SCOPE_DIR/inscope_patterns.tsv"
ES_URL="${ES_URL:-http://localhost:9200}"
INDEX_NAME="${INDEX_NAME:-recon_alive_v3}"
ES_PAGE_SIZE="${ES_PAGE_SIZE:-5000}"
BULK_CHUNK="${BULK_CHUNK:-2000}"

APPLY=0
LIMIT=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply)  APPLY=1; shift ;;
    --limit)  LIMIT="${2:-0}"; shift 2 ;;
    -h|--help) sed -n '2,34p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) die "unknown arg: $1" ;;
  esac
done

# ---- Safety: never resync off a missing or obviously broken scope DB --------
# A truncated TSV would mark the whole estate out-of-scope in one bulk write.
[[ -s "$INSCOPE_TSV" ]] || die "scope DB not populated ($INSCOPE_TSV) — run recon_scope_db.sh first"
PAT_COUNT="$(wc -l < "$INSCOPE_TSV" | tr -d ' ')"
MIN_PATTERNS="${MIN_PATTERNS:-10000}"
[[ "$PAT_COUNT" -ge "$MIN_PATTERNS" ]] \
  || die "scope DB has only $PAT_COUNT patterns (< $MIN_PATTERNS) — refusing to resync off a partial build"
[[ -f "$SCOPE_CHECK" ]] || die "scope_check missing: $SCOPE_CHECK"

ES_AUTH=()
if [[ -s "$HOME/.recon_es_pass" ]]; then
  ES_AUTH=(-u "elastic:$(cat "$HOME/.recon_es_pass")")
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ---- 1. current ES scope state ---------------------------------------------
log "Exporting scope state from $INDEX_NAME"
QUERY="$(jq -n --argjson size "$ES_PAGE_SIZE" '{
  size: $size,
  _source: ["host","triage_pays","triage_in_scope","triage_out_of_scope",
            "triage_payout_tier","triage_program","triage_platform"],
  query: {match_all: {}},
  sort: [{"host": {"order": "asc"}}]
}')"
: > "$WORK/es_state.jsonl"
after=""
while :; do
  if [[ -z "$after" ]]; then q="$QUERY"
  else q="$(echo "$QUERY" | jq --argjson a "$after" '. + {search_after: $a}')"
  fi
  resp="$(curl -fsS -m 120 "${ES_AUTH[@]}" -H 'Content-Type: application/json' \
          -X POST "$ES_URL/$INDEX_NAME/_search" -d "$q" 2>/dev/null)" \
    || die "ES query failed"
  cnt="$(echo "$resp" | jq '.hits.hits | length')"
  [[ "$cnt" == "0" ]] && break
  echo "$resp" | jq -c '.hits.hits[]._source' >> "$WORK/es_state.jsonl"
  after="$(echo "$resp" | jq -c '.hits.hits[-1].sort')"
  [[ -z "$after" || "$after" == "null" ]] && break
  if [[ "$LIMIT" -gt 0 && "$(wc -l < "$WORK/es_state.jsonl")" -ge "$LIMIT" ]]; then break; fi
done
TOTAL="$(wc -l < "$WORK/es_state.jsonl" | tr -d ' ')"
[[ "$TOTAL" -gt 0 ]] || die "no docs exported from $INDEX_NAME"
log "Exported $TOTAL docs"

# ---- 2. recompute against the current scope DB ------------------------------
jq -r '.host' "$WORK/es_state.jsonl" > "$WORK/hosts.txt"
log "Recomputing scope for $TOTAL hosts"
bash "$SCOPE_CHECK" --batch "$WORK/hosts.txt" > "$WORK/scope_new.jsonl" \
  || die "scope_check failed"
NEW_N="$(wc -l < "$WORK/scope_new.jsonl" | tr -d ' ')"
[[ "$NEW_N" == "$TOTAL" ]] \
  || die "scope_check returned $NEW_N lines for $TOTAL hosts — refusing to write a partial result"

# ---- 3. diff -> bulk update body -------------------------------------------
python3 - "$WORK" "$INDEX_NAME" <<'PY'
import json, os, sys

work, index = sys.argv[1], sys.argv[2]
cur = {}
with open(os.path.join(work, "es_state.jsonl"), encoding="utf-8") as fh:
    for line in fh:
        d = json.loads(line)
        cur[d["host"]] = d

FIELDS = (
    ("triage_pays",         "pays",         False),
    ("triage_in_scope",     "in_scope",     False),
    ("triage_out_of_scope", "out_of_scope", False),
    ("triage_payout_tier",  "payout_tier",  "none"),
    ("triage_program",      "program",      None),
    ("triage_platform",     "platform",     None),
)

changed = 0
counts = {}
out = open(os.path.join(work, "bulk.ndjson"), "w", encoding="utf-8")
with open(os.path.join(work, "scope_new.jsonl"), encoding="utf-8") as fh:
    for line in fh:
        s = json.loads(line)
        d = cur.get(s["host"])
        if d is None:
            continue
        doc = {}
        for es_key, sc_key, default in FIELDS:
            new = s.get(sc_key, default)
            if new is None:
                new = default
            old = d.get(es_key, default)
            if isinstance(default, bool):
                new, old = bool(new), bool(old)
            if old != new:
                doc[es_key] = new
                counts[es_key] = counts.get(es_key, 0) + 1
        if doc:
            changed += 1
            out.write(json.dumps({"update": {"_index": index, "_id": s["host"]}},
                                 separators=(",", ":")) + "\n")
            out.write(json.dumps({"doc": doc}, separators=(",", ":")) + "\n")
out.close()

with open(os.path.join(work, "summary.txt"), "w", encoding="utf-8") as fh:
    fh.write("docs needing correction: %d\n" % changed)
    for k in sorted(counts):
        fh.write("  %-22s %d\n" % (k, counts[k]))
PY

cat "$WORK/summary.txt" >&2
CHANGED="$(awk '/docs needing correction/ {print $NF}' "$WORK/summary.txt")"
CHANGED="${CHANGED:-0}"

if [[ "$CHANGED" == "0" ]]; then
  log "ES already matches the scope DB — nothing to do"
  exit 0
fi

# Guard against a scope DB that would rewrite the whole estate. A legitimate
# derivation fix touches a slice; 50%+ of the index means something is wrong
# with the TSV, not with ES.
PCT=$(( CHANGED * 100 / TOTAL ))
MAX_PCT="${MAX_PCT:-50}"
if [[ "$PCT" -ge "$MAX_PCT" ]]; then
  die "$CHANGED/$TOTAL docs (${PCT}%) would change — that is not a scope fix, it is a broken scope DB. Refusing. Override with MAX_PCT=<n>."
fi

if [[ "$APPLY" != "1" ]]; then
  log "DRY RUN — $CHANGED/$TOTAL docs (${PCT}%) differ. Re-run with --apply to write."
  exit 0
fi

# ---- 4. bulk apply ----------------------------------------------------------
log "Applying $CHANGED updates"
split -l "$(( BULK_CHUNK * 2 ))" "$WORK/bulk.ndjson" "$WORK/chunk_"
ok=0; failed=0
for chunk in "$WORK"/chunk_*; do
  resp="$(curl -fsS -m 120 "${ES_AUTH[@]}" -H 'Content-Type: application/x-ndjson' \
          -X POST "$ES_URL/_bulk" --data-binary "@$chunk" 2>/dev/null)"
  if [[ -z "$resp" ]] || ! echo "$resp" | jq -e '.items' >/dev/null 2>&1; then
    warn "bulk chunk $(basename "$chunk") failed (no/invalid response)"
    failed=$(( failed + 1 )); continue
  fi
  errs="$(echo "$resp" | jq '[.items[] | select(.update.error)] | length')"
  if [[ "$errs" != "0" ]]; then
    warn "bulk chunk $(basename "$chunk"): $errs item errors — first: $(echo "$resp" | jq -c '[.items[] | select(.update.error)][0].update.error')"
    failed=$(( failed + 1 ))
  fi
  ok=$(( ok + 1 ))
done
log "Bulk chunks: $ok applied, $failed with errors"
[[ "$failed" -eq 0 ]] || exit 1
log "Scope resync complete — $CHANGED docs corrected"

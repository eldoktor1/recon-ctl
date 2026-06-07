#!/usr/bin/env bash
# =============================================================================
# recon_es_reindex.sh — one-time clean reindex of the recon_alive index.
#
# ES can't drop or retype fields in place, so we reindex into a clean index with a
# corrected mapping, strip dead fields from each _source during the copy, verify the
# doc count matches EXACTLY, preserve the original (clone -> recon_alive_old), then
# atomically point the `recon_alive` name at the clean index via an ALIAS so every
# tool that reads/writes "recon_alive" keeps working unchanged.
#
# SAFETY: aborts on any count mismatch; never deletes the source until a verified
# clean copy AND a preserved clone both exist. Idempotent-ish (refuses if dest exists).
# Run with the pipeline STOPPED (maintenance lock). Default is a DRY RUN; pass --go.
# =============================================================================
set -uo pipefail
N="${NETRC:-$HOME/.recon_es_netrc}"
ES="${ES_URL:-http://127.0.0.1:9200}"
SRC="${INDEX_NAME:-recon_alive}"
DST="${DST_INDEX:-recon_alive_v3}"
OLD="${OLD_INDEX:-recon_alive_old}"
GO=0; [[ "${1:-}" == "--go" ]] && GO=1

log(){ printf '[%s REINDEX] %s\n' "$(date -u '+%H:%M:%SZ')" "$*"; }
die(){ printf '[%s REINDEX FATAL] %s\n' "$(date -u '+%H:%M:%SZ')" "$*" >&2; exit 1; }
ej(){ curl -fsS -m 60 --netrc-file "$N" -H 'Content-Type: application/json' "$@"; }

DROP='["ai_confidence","ai_model","ai_reason","ai_rec","ai_recommendation","ai_relevance_score","ai_reviewed_at","ai_risk_flags","ai_route","ai_safe_checks","ai_score","claude_rec","claude_note","final_score","claim_status","js_secret_lead","triage_pays_resync","nuclei_result","takeover_fp_reason","pattern_only","ignore_expires","ignore_reason","last_triaged","last_verified","nuclei_last_run","nuclei_last_run_ts"]'

command -v jq >/dev/null || die "jq required"
ej "$ES/$SRC/_count" >/dev/null 2>&1 || die "source index $SRC not reachable"
SRC_COUNT="$(ej "$ES/$SRC/_count" | jq -r '.count')"
[[ "$SRC_COUNT" =~ ^[0-9]+$ && "$SRC_COUNT" -gt 0 ]] || die "bad source count: $SRC_COUNT"
log "source $SRC has $SRC_COUNT docs"

# Build clean mapping from the live one: drop dead fields, fix the 3 wrong types.
CLEAN_MAP="$(ej "$ES/$SRC/_mapping" | jq -c --argjson drop "$DROP" '
  .[].mappings.properties
  | delpaths([ $drop[] | [.] ])
  | .claude_analysis        = {"type":"text"}
  | .claude_suggested_class = {"type":"keyword"}
  | .claude_analyze_model   = {"type":"keyword"}
  | {settings:{number_of_shards:1, number_of_replicas:0, refresh_interval:"-1"}, mappings:{properties:.}}
')"
KEPT="$(printf '%s' "$CLEAN_MAP" | jq '.mappings.properties|length')"
log "clean mapping built: $KEPT fields kept ($(printf '%s' "$DROP" | jq 'length') dropped)"
printf '%s' "$DROP" | jq -r '.[]' | sed 's/^/    drop: /'

if [[ "$GO" != "1" ]]; then
  log "DRY RUN (pass --go to execute). Would: create $DST, reindex+strip, verify==$SRC_COUNT, clone $SRC->$OLD, delete $SRC, alias $SRC->$DST."
  exit 0
fi

# --- create clean dest -------------------------------------------------------
ej "$ES/$DST" >/dev/null 2>&1 && die "dest $DST already exists — remove it first (DELETE /$DST) or set DST_INDEX"
ej -X PUT "$ES/$DST" -d "$CLEAN_MAP" >/dev/null || die "failed to create $DST"
log "created clean index $DST"

# --- reindex, stripping dead fields from _source -----------------------------
RBODY="$(jq -nc --arg src "$SRC" --arg dst "$DST" --argjson drop "$DROP" '
  {source:{index:$src}, dest:{index:$dst},
   script:{source:"for (f in params.drop) { ctx._source.remove(f) }", params:{drop:$drop}}}')"
TASK="$(ej -X POST "$ES/_reindex?wait_for_completion=false&slices=auto" -d "$RBODY" | jq -r '.task')"
[[ -n "$TASK" && "$TASK" != "null" ]] || die "reindex did not start"
log "reindex task $TASK started — polling..."
for i in $(seq 1 600); do
  done_st="$(ej "$ES/_tasks/$TASK" | jq -r '.completed')"
  [[ "$done_st" == "true" ]] && break
  sleep 2
done
[[ "$done_st" == "true" ]] || die "reindex did not complete in time (task $TASK still running)"
TASK_INFO="$(ej "$ES/_tasks/$TASK")"
FAIL="$(printf '%s' "$TASK_INFO" | jq -r '(.response.failures|length) // 0')"
CREATED="$(printf '%s' "$TASK_INFO" | jq -r '.response.created // .task.status.created // 0')"
log "reindex complete: created=$CREATED failures=$FAIL"
[[ "$FAIL" == "0" ]] || die "reindex had $FAIL failures — aborting BEFORE any destructive step ($DST left for inspection)"

ej -X POST "$ES/$DST/_refresh" >/dev/null || true
ej -X PUT "$ES/$DST/_settings" -d '{"index":{"refresh_interval":null}}' >/dev/null || true
DST_COUNT="$(ej "$ES/$DST/_count" | jq -r '.count')"
log "verify: source=$SRC_COUNT dest=$DST_COUNT"
[[ "$DST_COUNT" == "$SRC_COUNT" ]] || die "COUNT MISMATCH ($SRC_COUNT vs $DST_COUNT) — aborting, source untouched, $DST left for inspection"

# spot-check: a known host carries kept fields and none of the dropped ones
SPOT="$(ej "$ES/$DST/_search" -d '{"size":1,"query":{"exists":{"field":"triage_score"}}}' \
  | jq -c '.hits.hits[0]._source | {host, triage_score, has_dropped_ai:(has("ai_recommendation")), has_pattern_only:(has("pattern_only"))}')"
log "spot-check: $SPOT"

# --- preserve original via clone, then swap the name to an alias --------------
ej -X PUT "$ES/$SRC/_settings" -d '{"index":{"blocks":{"write":true}}}' >/dev/null || die "could not set source read-only for clone"
ej "$ES/$OLD" >/dev/null 2>&1 && { log "$OLD already exists — skipping clone"; } || {
  ej -X POST "$ES/$SRC/_clone/$OLD" >/dev/null || die "clone to $OLD failed (source still intact)"
  log "cloned original -> $OLD (7-day rollback copy)"
}
ej -X PUT "$ES/$SRC/_settings" -d '{"index":{"blocks":{"write":false}}}' >/dev/null || true
OLD_COUNT="$(ej "$ES/$OLD/_count" | jq -r '.count')"
[[ "$OLD_COUNT" == "$SRC_COUNT" ]] || die "clone count mismatch ($OLD_COUNT) — aborting before delete; $DST ready, $SRC intact"

# free the name and alias it to the clean index (single atomic alias add)
ej -X DELETE "$ES/$SRC" >/dev/null || die "could not delete $SRC (clean copy in $DST, original in $OLD)"
ej -X POST "$ES/_aliases" -d "$(jq -nc --arg s "$SRC" --arg d "$DST" \
  '{actions:[{add:{index:$d, alias:$s, is_write_index:true}}]}')" >/dev/null \
  || die "ALIAS ADD FAILED — recover: POST /_aliases add $DST as $SRC (data safe in $DST and $OLD)"
log "alias $SRC -> $DST created (is_write_index)"

# --- final verification via the alias ----------------------------------------
ALIAS_COUNT="$(ej "$ES/$SRC/_count" | jq -r '.count')"
log "DONE. $SRC (alias) -> $DST docs=$ALIAS_COUNT ; rollback copy=$OLD docs=$OLD_COUNT"
[[ "$ALIAS_COUNT" == "$SRC_COUNT" ]] || die "post-swap count via alias wrong ($ALIAS_COUNT)"
log "SUCCESS — clean index live. Delete $OLD after ~7 days: curl -XDELETE $ES/$OLD"

#!/usr/bin/env bash
# Bootstrap or reset the recon Elasticsearch index with the pipeline mapping.
set -Eeuo pipefail
IFS=$'\n\t'

log()  { printf '[%s ES] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
die()  { printf '[%s ES FATAL] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; exit 1; }

BASE_DIR="${BASE_DIR:-$HOME/recon}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"
INDEX_NAME="${INDEX_NAME:-recon_alive}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/recon_net.sh"
setup_es_netrc
ES_AUTH=(--netrc-file "$HOME/.recon_es_netrc")

VALIDATE="${VALIDATE:-$SCRIPT_DIR/recon_validate.sh}"

delete_recon_index() {
  curl -fsS -m 30 "${ES_AUTH[@]}" -X DELETE "$ES_URL/$INDEX_NAME" >/dev/null 2>&1 || true
  log "deleted index if present: $INDEX_NAME"
}

clear_derived_host_state() {
  local archive_root="$BASE_DIR/archive/es_reset_$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$archive_root/cve" "$archive_root/triage" "$archive_root/ai_review" "$archive_root/vuln"

  local f
  for f in \
    "$BASE_DIR/cve/kev_targets.jsonl" \
    "$BASE_DIR/vuln/vuln_targets.jsonl" \
    "$BASE_DIR/triage/agent_targets.jsonl" \
    "$BASE_DIR/ai_review/ai_scored.jsonl"; do
    if [[ -s "$f" ]]; then
      mv "$f" "$archive_root/${f#$BASE_DIR/}" 2>/dev/null || true
    else
      rm -f "$f" 2>/dev/null || true
    fi
  done

  if [[ -d "$BASE_DIR/ai_review/pending" ]]; then
    mkdir -p "$archive_root/ai_review/pending"
    find "$BASE_DIR/ai_review/pending" -maxdepth 1 -type f -name '*.md' \
      -exec mv -t "$archive_root/ai_review/pending" {} + 2>/dev/null || true
  fi

  : > "$BASE_DIR/cve/kev_targets.jsonl"
  mkdir -p "$BASE_DIR/vuln"
  : > "$BASE_DIR/vuln/vuln_targets.jsonl"
  log "cleared derived host state; archive=$archive_root"
}

bootstrap_mapping() {
  HOME="${HOME:-/home/d0k}" BASE_DIR="$BASE_DIR" ES_URL="$ES_URL" INDEX_NAME="$INDEX_NAME" \
    ES_USER="$ES_USER" BATCHES_PER_CYCLE=0 RUN_TRIAGE=0 \
    bash "$VALIDATE" >/dev/null
  log "bootstrapped mapping: $INDEX_NAME"
  apply_screenshot_mapping
}

# Idempotent: PUT explicit mappings for fields that must NOT be auto-detected.
# screenshot_thumb_b64 in particular — without this, ES dynamic mapping would
# pick `text` and the 5-8KB base64 strings would be analyzed + inverted-index'd,
# bloating the index by an order of magnitude. doc_values:false + store:false
# keeps the field _source-only (which is exactly how the gallery reads it).
apply_screenshot_mapping() {
  curl -fsS -m 30 "${ES_AUTH[@]}" -H 'Content-Type: application/json' \
    -X PUT "$ES_URL/$INDEX_NAME/_mapping" \
    -d '{
      "properties": {
        "screenshot_at":        {"type": "date"},
        "screenshot_status":    {"type": "keyword"},
        "screenshot_path":      {"type": "keyword"},
        "screenshot_title":     {"type": "text"},
        "screenshot_w":         {"type": "integer"},
        "screenshot_h":         {"type": "integer"},
        "screenshot_error":     {"type": "keyword", "ignore_above": 256},
        "screenshot_thumb_b64": {"type": "binary", "doc_values": false, "store": false}
      }
    }' >/dev/null
  log "applied screenshot_* mapping"
}

verify_mapping() {
  curl -fsS -m 30 "${ES_AUTH[@]}" "$ES_URL/$INDEX_NAME/_mapping" \
    | jq -e --arg idx "$INDEX_NAME" '
      .[$idx].mappings.properties as $p |
      ($p.host.type == "keyword") and
      ($p.status_code.type == "integer") and
      ($p.triage_score.type == "integer") and
      ($p.triage_pays.type == "boolean") and
      ($p.triage_kev_cves.type == "keyword") and
      ($p.v2_nuclei_status.type == "keyword") and
      ($p.ai_relevance_score.type == "integer") and
      ($p.ai_recommendation.type == "keyword")
    ' >/dev/null
  local count
  count="$(curl -fsS -m 30 "${ES_AUTH[@]}" "$ES_URL/$INDEX_NAME/_count" | jq -r '.count')"
  log "verified mapping: $INDEX_NAME docs=$count"
}

case "${1:-bootstrap}" in
  reset)
    delete_recon_index
    clear_derived_host_state
    bootstrap_mapping
    verify_mapping
    ;;
  bootstrap)
    bootstrap_mapping
    verify_mapping
    ;;
  verify)
    verify_mapping
    ;;
  *)
    echo "Usage: $(basename "$0") reset|bootstrap|verify" >&2
    exit 2
    ;;
esac

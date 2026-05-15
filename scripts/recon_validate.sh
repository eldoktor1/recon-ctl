#!/usr/bin/env bash
# =============================================================================
# recon_validate.sh — Drains queue/inbox/, runs httpx, ingests to ES,
# triggers takeover hunter on results, then triage.
#
# DESIGN
#   - Atomic claim: mv inbox/N → processing/N (no flock contention)
#   - Hard timeout on httpx (no more 5h zombies)
#   - Per-cycle error isolation: subshell + || warn (transient errors don't kill loop)
#   - Streams results to takeover hunter as they're written (first-blood path)
# =============================================================================
set -uo pipefail
IFS=$'\n\t'

log()  { printf '[%s VAL] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s VAL WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
die()  { printf '[%s VAL FATAL] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; exit 1; }

# Network command wrapper.
# If USE_PROXYCHAINS=1, target-facing tools MUST run through proxychains4.
# Fail closed if proxychains/Tor is not available.
proxy_required() { [[ "${USE_PROXYCHAINS:-1}" == "1" ]]; }

ensure_proxy_ready() {
  proxy_required || return 0
  command -v proxychains4 >/dev/null 2>&1 || die "USE_PROXYCHAINS=1 but proxychains4 is missing"
  ss -ltn 2>/dev/null | grep -q '127\.0\.0\.1:9050' || die "USE_PROXYCHAINS=1 but Tor SOCKS listener 127.0.0.1:9050 is not up"
}

run_net() {
  ensure_proxy_ready
  if proxy_required; then
    proxychains4 -q "$@"
  else
    "$@"
  fi
}


BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="$BASE_DIR/state"
QUEUE_DIR="$BASE_DIR/queue"
INBOX="$QUEUE_DIR/inbox"
PROCESSING="$QUEUE_DIR/processing"
DONE="$QUEUE_DIR/done"
SPOOL="$BASE_DIR/spool"
LOG_DIR="$BASE_DIR/logs"
LOCK_FILE="$STATE_DIR/validate.lock"
# Per-lane lock (set after we've parsed --prefix flags below) — fast + normal
# lanes must NOT block each other.
LANE_LOCK_FILE="$LOCK_FILE"

ES_URL="${ES_URL:-http://127.0.0.1:9200}"
INDEX_NAME="${INDEX_NAME:-recon_alive}"
ES_USER="${ES_USER:-elastic}"
ES_PASS="${ES_PASS:-}"
[[ -z "$ES_PASS" && -f "$HOME/.recon_es_pass" ]] && ES_PASS="$(tr -d '[:space:]' < "$HOME/.recon_es_pass" 2>/dev/null || true)"
[[ -z "$ES_PASS" ]] && die "ES password not set"
ES_AUTH=(-u "$ES_USER:$ES_PASS")

# httpx tuning (set by daemon based on mode)
HTTPX_THREADS="${HTTPX_THREADS:-15}"
HTTPX_RATE="${HTTPX_RATE:-15}"
HTTPX_TIMEOUT="${HTTPX_TIMEOUT:-10}"
HTTPX_MAX_RUNTIME="${HTTPX_MAX_RUNTIME:-900}"   # 15 min hard cap (browse)
BULK_LINES="${BULK_LINES:-5000}"

BATCHES_PER_CYCLE="${BATCHES_PER_CYCLE:-3}"
RUN_TAKEOVER="${RUN_TAKEOVER:-1}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
script_path() { printf '%s\n' "$SCRIPT_DIR/$1"; }
TAKEOVER_SCRIPT="${TAKEOVER_SCRIPT:-$(script_path recon_takeover_hunter.sh)}"
RUN_TRIAGE="${RUN_TRIAGE:-1}"
TRIAGE_SCRIPT="${TRIAGE_SCRIPT:-$(script_path triage.sh)}"

mkdir -p "$STATE_DIR" "$INBOX" "$PROCESSING" "$DONE" "$LOG_DIR" "$SPOOL/pending" "$SPOOL/sent" "$SPOOL/failed"

KNOWN_HOSTS="$STATE_DIR/known_hosts.txt"
ALIVE_HOSTS="$STATE_DIR/alive_hosts.txt"
touch "$KNOWN_HOSTS" "$ALIVE_HOSTS"

es_curl() { curl -sS -m 30 "${ES_AUTH[@]}" "$@"; }

es_check() {
  local code; code="$(curl -sS -o /dev/null -m 5 -w '%{http_code}' "${ES_AUTH[@]}" "$ES_URL" 2>/dev/null || echo 000)"
  [[ "$code" == "200" ]] || { warn "ES not reachable (HTTP $code)"; return 1; }
}

_INDEX_PROPERTIES='{
  "host":{"type":"keyword"},
  "url":{"type":"keyword","ignore_above":2048},
  "scheme":{"type":"keyword"},
  "port":{"type":"integer"},
  "status_code":{"type":"integer"},
  "content_length":{"type":"long"},
  "content_type":{"type":"keyword","ignore_above":512},
  "title":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":512}}},
  "tech":{"type":"keyword","ignore_above":256},
  "webserver":{"type":"keyword","ignore_above":512},
  "ip":{"type":"ip","ignore_malformed":true},
  "cname":{"type":"keyword","ignore_above":512},
  "cdn_name":{"type":"keyword","ignore_above":256},
  "cdn_type":{"type":"keyword","ignore_above":256},
  "favicon_hash":{"type":"keyword"},
  "final_url":{"type":"keyword","ignore_above":2048},
  "root_domain":{"type":"keyword"},
  "first_seen":{"type":"date"},
  "last_seen":{"type":"date"},

  "triage_score":{"type":"integer"},
  "triage_priority":{"type":"keyword"},
  "triage_signals":{"type":"keyword","ignore_above":256},
  "triage_classes":{"type":"keyword","ignore_above":256},
  "triage_at":{"type":"date"},
  "triage_program":{"type":"keyword","ignore_above":512},
  "triage_platform":{"type":"keyword","ignore_above":128},
  "triage_payout_tier":{"type":"keyword"},
  "triage_pays":{"type":"boolean"},
  "triage_in_scope":{"type":"boolean"},
  "triage_out_of_scope":{"type":"boolean"},
  "triage_kev_match":{"type":"boolean"},
  "triage_kev_signal":{"type":"keyword","ignore_above":256},
  "triage_kev_cves":{"type":"keyword"},

  "triage_true_fresh":{"type":"boolean"},
  "triage_true_fresh_bonus":{"type":"integer"},
  "triage_external_first_seen":{"type":"date"},
  "triage_breaking_vuln":{"type":"boolean"},
  "triage_breaking_vuln_bonus":{"type":"integer"},
  "triage_vuln_tier":{"type":"keyword"},
  "active_check_result":{"type":"keyword","ignore_above":128},
  "active_checked_at":{"type":"date"},
  "js_secret_hit":{"type":"boolean"},
  "js_endpoint_hit":{"type":"boolean"},
  "triage_ignored":{"type":"boolean"},
  "triage_ignored_reason":{"type":"keyword","ignore_above":512},

  "v2_nuclei_status":{"type":"keyword"},
  "v2_nuclei_template":{"type":"keyword","ignore_above":512},
  "v2_nuclei_severity":{"type":"keyword"},
  "v2_nuclei_run_at":{"type":"date"},

  "ai_relevance_score":{"type":"integer"},
  "ai_confidence":{"type":"keyword"},
  "ai_recommendation":{"type":"keyword"},
  "ai_route":{"type":"keyword"},
  "ai_reason":{"type":"text"},
  "ai_safe_checks":{"type":"keyword","ignore_above":1024},
  "ai_risk_flags":{"type":"keyword","ignore_above":512},
  "ai_model":{"type":"keyword","ignore_above":128},
  "ai_reviewed_at":{"type":"date"}
}'

ensure_index() {
  if ! es_curl -fsS "$ES_URL/$INDEX_NAME" >/dev/null 2>&1; then
    es_curl -fsS -X PUT "$ES_URL/$INDEX_NAME" -H 'Content-Type: application/json' \
      -d "$(jq -nc --argjson props "$_INDEX_PROPERTIES" '{
        settings:{number_of_shards:1, refresh_interval:"30s"},
        mappings:{dynamic:true, properties: $props}
      }')" >/dev/null
    log "Created index $INDEX_NAME"
  else
    # Idempotent additive mapping migration. ES allows adding new fields freely.
    es_curl -fsS -X PUT "$ES_URL/$INDEX_NAME/_mapping" -H 'Content-Type: application/json' \
      -d "$(jq -nc --argjson props "$_INDEX_PROPERTIES" '{properties: $props}')" >/dev/null 2>&1 || true
  fi
}

# ---- Queue lane filter (v2.5: dual-queue support) -------------------------
# CLI flags:
#   --prefix <str>          only claim batches whose basename starts with <str>
#   --exclude-prefix <str>  skip batches whose basename starts with <str>
# Used by the daemon to run two validators in parallel:
#   fast lane  (--prefix 00_)         claims 00_truefresh_*.txt
#   normal lane (--exclude-prefix 00_) skips them
CLAIM_PREFIX=""
CLAIM_EXCLUDE_PREFIX=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)         CLAIM_PREFIX="$2";         shift 2 ;;
    --exclude-prefix) CLAIM_EXCLUDE_PREFIX="$2"; shift 2 ;;
    --) shift; break ;;
    *) shift ;;
  esac
done

# Per-lane lock: each (prefix, exclude_prefix) combination gets its own lock.
# Without this, fast and normal validators would serialize on the same lock.
LANE_KEY="all"
[[ -n "$CLAIM_PREFIX"         ]] && LANE_KEY="prefix_${CLAIM_PREFIX//[^a-zA-Z0-9]/_}"
[[ -n "$CLAIM_EXCLUDE_PREFIX" ]] && LANE_KEY="excl_${CLAIM_EXCLUDE_PREFIX//[^a-zA-Z0-9]/_}"
LANE_LOCK_FILE="$STATE_DIR/validate.${LANE_KEY}.lock"
exec 9>"$LANE_LOCK_FILE"; flock -n 9 || { warn "validate (lane=$LANE_KEY) already running"; exit 0; }

# ---- Claim a batch atomically ----
claim_batch() {
  local pattern="*.txt"
  if [[ -n "$CLAIM_PREFIX" ]]; then
    pattern="${CLAIM_PREFIX}*.txt"
  fi
  local f
  while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    if [[ -n "$CLAIM_EXCLUDE_PREFIX" ]]; then
      local base; base="$(basename "$f")"
      [[ "$base" == "${CLAIM_EXCLUDE_PREFIX}"* ]] && continue
    fi
    local target="$PROCESSING/$(basename "$f")"
    if mv "$f" "$target" 2>/dev/null; then
      printf '%s\n' "$target"
      return 0
    fi
  done < <(find "$INBOX" -maxdepth 1 -name "$pattern" -type f 2>/dev/null | sort)
  return 1
}

# ---- Process one batch ----
process_batch() {
  local batch="$1"
  local batch_name; batch_name="$(basename "$batch")"
  local stem="${batch_name%.txt}"
  local tmpd; tmpd="$(mktemp -d)"
  local httpx_out="$tmpd/httpx.jsonl"
  local norm_out="$tmpd/normalized.jsonl"

  local count; count="$(wc -l < "$batch" | tr -d ' ')"
  log "Processing $batch_name ($count hosts) threads=$HTTPX_THREADS rate=$HTTPX_RATE timeout=${HTTPX_MAX_RUNTIME}s"

  # ---- httpx with HARD timeout ----
  if ! timeout --kill-after=30 "$HTTPX_MAX_RUNTIME" httpx \
        -http-proxy "$PROXY_URL" \
        -l "$batch" -silent -nc -json \
        -tech-detect -status-code -title -web-server \
        -content-type -content-length \
        -ip -cname -cdn -favicon -location \
        -threads "$HTTPX_THREADS" -rate-limit "$HTTPX_RATE" \
        -timeout "$HTTPX_TIMEOUT" -retries 1 \
        > "$httpx_out" 2>/dev/null; then
    # v2.5.4: bounded retry. Prior behaviour moved the batch back to inbox
    # forever — a single poisoned batch (DNS-flake host, hung TLS, etc.)
    # would bounce inbox↔processing on every cycle indefinitely. Now we
    # count retries via a .retry<N> filename suffix and after MAX_BATCH_RETRIES
    # we send the batch to spool/failed for postmortem instead of poisoning
    # the queue.
    local retry_max="${MAX_BATCH_RETRIES:-3}"
    local stem_base="${stem%.retry*}"
    local cur_retry=0
    if [[ "$stem" =~ \.retry([0-9]+)$ ]]; then
      cur_retry="${BASH_REMATCH[1]}"
    fi
    local next_retry=$(( cur_retry + 1 ))
    if (( next_retry >= retry_max )); then
      warn "httpx timed out or failed on $batch_name (giving up after $retry_max retries — moving to spool/failed)"
      mkdir -p "$SPOOL/failed"
      mv "$batch" "$SPOOL/failed/${stem_base}.poisoned.txt" 2>/dev/null || rm -f "$batch"
    else
      warn "httpx timed out or failed on $batch_name (retry $next_retry/$retry_max — moving to inbox)"
      mv "$batch" "$INBOX/${stem_base}.retry${next_retry}.txt" 2>/dev/null || true
    fi
    rm -rf "$tmpd"
    return 1
  fi

  local results; results="$(wc -l < "$httpx_out" | tr -d ' ')"
  log "  httpx: $results live hosts found"

  # Mark all probed hosts as known (live OR not — they got tested)
  cat "$batch" >> "$KNOWN_HOSTS.tmp" 2>/dev/null || true
  sort -u "$KNOWN_HOSTS.tmp" "$KNOWN_HOSTS" -o "$KNOWN_HOSTS" 2>/dev/null
  rm -f "$KNOWN_HOSTS.tmp"

  if [[ "$results" -gt 0 ]]; then
    # ---- Normalize for ES ----
    jq -c --arg ts "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" '
      select(type=="object") |
      .input as $raw |
      ($raw | ascii_downcase | gsub("^https?://";"") | gsub("/+$";"")) as $canon |
      ($canon | split(".") | (if length >= 2 then .[-2:] | join(".") else $canon end)) as $root |
      {
        host:$canon, url:(.url//""), scheme:(.scheme//""),
        port:((.port//0)|tonumber? // 0),
        status_code:((.status_code//0)|tonumber? // 0),
        content_length:((.content_length//0)|tonumber? // 0),
        content_type:(.content_type//""),
        title:(.title//""), tech:(.tech//[]), webserver:(.webserver//""),
        ip:((.a//[])[0] // null),
        cname:((.cname//[])[0] // ""),
        cdn_name:(.cdn_name//""), cdn_type:(.cdn_type//""),
        favicon_hash:((.favicon//"") | tostring),
        final_url:(.location // .final_url // ""),
        root_domain:$root, last_seen:$ts, first_seen:$ts
      } | with_entries(select(.value!=null and .value!="" and .value!=[]))
      | . + {host:$canon, last_seen:$ts, first_seen:$ts}
    ' "$httpx_out" > "$norm_out" 2>/dev/null || true

    # ---- Bulk ingest ES ----
    local spool="$SPOOL/pending/${stem}.jsonl"
    cp "$norm_out" "$spool"
    if ship_bulk "$spool"; then
      mv "$spool" "$SPOOL/sent/" 2>/dev/null || true
    else
      warn "ES ingest had failures for $batch_name"
    fi

    # Update alive_hosts list
    jq -r '.host' "$norm_out" 2>/dev/null | cat - "$ALIVE_HOSTS" | sort -u > "$ALIVE_HOSTS.new" \
      && mv "$ALIVE_HOSTS.new" "$ALIVE_HOSTS"

    # ---- Move httpx output to done/ for takeover hunter ----
    cp "$httpx_out" "$DONE/${stem}.jsonl"

    # ---- IMMEDIATE takeover hunter call (first-blood path) ----
    if [[ "$RUN_TAKEOVER" == "1" && -f "$TAKEOVER_SCRIPT" ]]; then
      ( DISCORD_WEBHOOK="${DISCORD_WEBHOOK:-}" \
        timeout --kill-after=10 600 bash "$TAKEOVER_SCRIPT" stream "$DONE/${stem}.jsonl" \
        || warn "takeover hunter exited non-zero on $stem" ) &
    fi
  fi

  # Move processed batch to done (record only, can prune later)
  mv "$batch" "$DONE/${stem}.txt.processed" 2>/dev/null || rm -f "$batch"
  rm -rf "$tmpd"
  return 0
}

ship_bulk() {
  local file="$1"
  [[ -s "$file" ]] || return 0
  local tmpdir; tmpdir="$(mktemp -d)"
  split -l "$BULK_LINES" "$file" "$tmpdir/chunk_"
  local ok_all=0
  shopt -s nullglob
  for part in "$tmpdir"/chunk_*; do
    jq -c --arg idx "$INDEX_NAME" '
      {"update":{"_index":$idx,"_id":.host}},
      {"doc": (. | del(.first_seen)), "upsert": .}
    ' "$part" > "$part.bulk"
    local ok=false resp
    for attempt in 1 2 3; do
      resp="$(es_curl -H 'Content-Type: application/x-ndjson' -X POST "$ES_URL/_bulk" --data-binary @"$part.bulk" 2>/dev/null)" || resp=""
      if [[ "$resp" == *'"errors":false'* ]]; then ok=true; break; fi
      sleep 2
    done
    if [[ "$ok" == false ]]; then
      cp "$part.bulk" "$SPOOL/failed/$(basename "$part").bulk" 2>/dev/null || true
      ok_all=1
    fi
  done
  shopt -u nullglob
  rm -rf "$tmpdir"
  return "$ok_all"
}

retry_failed_spool() {
  shopt -s nullglob
  local files=("$SPOOL/failed"/*.bulk)
  shopt -u nullglob
  [[ ${#files[@]} -eq 0 ]] && return 0
  local f resp
  for f in "${files[@]}"; do
    resp="$(es_curl -H 'Content-Type: application/x-ndjson' -X POST "$ES_URL/_bulk" --data-binary @"$f" 2>/dev/null)" || resp=""
    if [[ "$resp" == *'"errors":false'* ]]; then rm -f "$f"; fi
  done
}

prune_done() {
  # Keep active done/ small, but preserve old httpx evidence for later review.
  local archive_root="$BASE_DIR/archive/auto_done_$(date -u +%Y%m%d)"
  local f rel dest_dir
  while IFS= read -r -d '' f; do
    rel="${f#$BASE_DIR/}"
    dest_dir="$archive_root/$(dirname "$rel")"
    mkdir -p "$dest_dir"
    mv "$f" "$dest_dir/" 2>/dev/null || true
  done < <(find "$DONE" -type f -mmin +1440 -print0 2>/dev/null)
}

main() {
  log "=== validate cycle start ==="
  es_check || { warn "ES unreachable, aborting cycle"; exit 0; }
  ensure_index
  retry_failed_spool

  local processed=0
  for ((i=0; i<BATCHES_PER_CYCLE; i++)); do
    local batch
    batch="$(claim_batch)" || break
    ( process_batch "$batch" ) || warn "batch processing returned non-zero (continuing)"
    processed=$((processed + 1))
  done

  prune_done

  log "=== validate cycle done (processed=$processed) ==="

  # Chain to triage if anything was processed
  if [[ "$processed" -gt 0 && "$RUN_TRIAGE" == "1" && -f "$TRIAGE_SCRIPT" ]]; then
    log "Chaining to triage"
    ( DISCORD_WEBHOOK="${DISCORD_WEBHOOK:-}" ES_URL="$ES_URL" ES_USER="$ES_USER" ES_PASS="$ES_PASS" \
      INDEX_NAME="$INDEX_NAME" timeout --kill-after=30 1200 bash "$TRIAGE_SCRIPT" \
      || warn "triage exited non-zero" )
  fi
}

main "$@"

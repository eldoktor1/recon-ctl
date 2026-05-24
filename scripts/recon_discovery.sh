#!/usr/bin/env bash
# =============================================================================
# recon_discovery.sh — Bounded discovery (Chaos + subfinder + assetfinder)
# Outputs: ~/recon/queue/inbox/10_<ts>_<batch>.txt   (directory queue)
# Hot-seed/scope-watch use 00_/01_ prefixes for higher priority.
# =============================================================================
set -uo pipefail
IFS=$'\n\t'

log()  { printf '[%s DISC] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s DISC WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
die()  { printf '[%s DISC FATAL] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; exit 1; }

source "$(dirname "${BASH_SOURCE[0]}")/recon_net.sh"

BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="$BASE_DIR/state"
CACHE_DIR="$BASE_DIR/cache"
QUEUE_DIR="$BASE_DIR/queue"
INBOX="$QUEUE_DIR/inbox"
LOG_DIR="$BASE_DIR/logs"
LOCK_FILE="$STATE_DIR/discovery.lock"

# Cap inbox files so discovery doesn't run away if validator falls behind
INBOX_FILE_CAP="${INBOX_FILE_CAP:-200}"
BATCH_SIZE="${BATCH_SIZE:-2500}"

CHAOS_REFRESH_HOURS="${CHAOS_REFRESH_HOURS:-12}"
SUBFINDER_REFRESH_HOURS="${SUBFINDER_REFRESH_HOURS:-48}"

mkdir -p "$STATE_DIR" "$CACHE_DIR" "$INBOX" "$QUEUE_DIR/processing" "$QUEUE_DIR/done" "$LOG_DIR" "$CACHE_DIR/programs"
exec 9>"$LOCK_FILE"; flock -n 9 || { warn "discovery already running"; exit 0; }

CHAOS_CACHE="$CACHE_DIR/chaos_merged.txt"
CHAOS_INDEX="$CACHE_DIR/chaos_index.json"
SUB_CACHE="$CACHE_DIR/subfinder_merged.txt"
ASSET_CACHE="$CACHE_DIR/assetfinder_merged.txt"
ROOT_DOMAINS="$STATE_DIR/root_domains.txt"
INSCOPE_TSV="${INSCOPE_TSV:-$BASE_DIR/scope/inscope_patterns.tsv}"
KNOWN_HOSTS="$STATE_DIR/known_hosts.txt"
LAST_CHAOS="$STATE_DIR/last_chaos.epoch"
LAST_SUB="$STATE_DIR/last_subfinder.epoch"

touch "$KNOWN_HOSTS" "$ROOT_DOMAINS"
NOW=$(date +%s)

inbox_count() { find "$INBOX" -maxdepth 1 -name '*.txt' 2>/dev/null | wc -l | tr -d ' '; }

if [[ "$(inbox_count)" -ge "$INBOX_FILE_CAP" ]]; then
  log "Inbox full ($(inbox_count) files ≥ cap $INBOX_FILE_CAP) — pausing discovery"
  exit 0
fi

age_h() { local f="$1"; [[ -f "$f" ]] || { echo 999999; return; }; echo $(( (NOW - $(cat "$f" 2>/dev/null || echo 0)) / 3600 )); }

# ---- Chaos refresh (incremental) ----
refresh_chaos() {
  local age; age="$(age_h "$LAST_CHAOS")"
  if [[ -s "$CHAOS_CACHE" && "$age" -lt "$CHAOS_REFRESH_HOURS" ]]; then
    log "Chaos cache fresh (${age}h)"; return
  fi
  log "Refreshing Chaos"
  local tmp; tmp="$(mktemp -d)"; trap "rm -rf $tmp" RETURN
  if ! run_net timeout 60 wget -q "https://chaos-data.projectdiscovery.io/index.json" -O "$tmp/index.json"; then
    warn "Chaos index fetch failed"; return
  fi
  [[ -f "$CHAOS_INDEX" ]] || echo '[]' > "$CHAOS_INDEX"
  jq -r --slurpfile prev "$CHAOS_INDEX" '
    ($prev[0] // []) as $old |
    ($old | map({key:.name,value:.last_updated}) | from_entries) as $oldmap |
    .[] | select(.URL != null) |
    select(($oldmap[.name] // "") != (.last_updated // "")) |
    [.name, .URL] | @tsv
  ' "$tmp/index.json" > "$tmp/changed.tsv" 2>/dev/null || return

  local nchanged; nchanged="$(wc -l < "$tmp/changed.tsv" | tr -d ' ')"
  log "Chaos changed programs: $nchanged"
  if [[ "$nchanged" -gt 0 ]]; then
    mkdir -p "$tmp/zips"
    while IFS=$'\t' read -r name url; do
      [[ -z "$name" ]] && continue
      local safe="${name//\//_}"
      run_net timeout 90 wget -q "$url" -O "$tmp/zips/${safe}.zip" || continue
      local outdir="$CACHE_DIR/programs/${safe}"
      rm -rf "$outdir"; mkdir -p "$outdir"
      unzip -oq "$tmp/zips/${safe}.zip" -d "$outdir" 2>/dev/null || rm -rf "$outdir"
    done < "$tmp/changed.tsv"
  fi
  if find "$CACHE_DIR/programs" -type f -name '*.txt' -print -quit | grep -q .; then
    find "$CACHE_DIR/programs" -type f -name '*.txt' -print0 \
      | xargs -0 cat | tr '[:upper:]' '[:lower:]' \
      | sed -E 's#https?://##; s#/+$##; s#[[:space:]]##g' \
      | grep -E '^[a-z0-9.-]+\.[a-z]{2,}$' | sort -u > "$CHAOS_CACHE.new"
    mv "$CHAOS_CACHE.new" "$CHAOS_CACHE"
    cp "$tmp/index.json" "$CHAOS_INDEX"
    echo "$NOW" > "$LAST_CHAOS"
    log "Chaos cache: $(wc -l < "$CHAOS_CACHE") hosts"
  fi
}

# Root domains for subfinder/assetfinder. Union of two sources:
#   1. In-scope PAYING program apexes from the scope DB — the programs the
#      operator actually cares about. Listed FIRST so they're never starved.
#   2. Chaos-derived roots (ProjectDiscovery's public dataset) — broad coverage
#      but picked-over, lower priority.
# Pre-v2.6 this used Chaos ONLY, so fresh paying programs absent from Chaos were
# never enumerated — the opposite of the "fresh-first" goal.
extract_roots() {
  local chaos_roots paying_roots
  chaos_roots="$(mktemp)"; paying_roots="$(mktemp)"

  if [[ -s "$CHAOS_CACHE" ]]; then
    awk -F. '{ if (NF >= 2) print $(NF-1)"."$NF }' "$CHAOS_CACHE" \
      | grep -E '^[a-z0-9-]+\.[a-z]{2,}$' | sort -u > "$chaos_roots"
  fi

  if [[ -s "$INSCOPE_TSV" ]]; then
    awk -F'\t' '$4=="true" {
      pat=$1; sub(/^\*\./, "", pat)
      n=split(pat, p, "."); if (n >= 2) print p[n-1]"."p[n]
    }' "$INSCOPE_TSV" | grep -E '^[a-z0-9-]+\.[a-z]{2,}$' | sort -u > "$paying_roots"
  fi

  # Paying roots first, then chaos; dedup preserving first occurrence (priority).
  cat "$paying_roots" "$chaos_roots" | awk 'NF && !seen[$0]++' > "$ROOT_DOMAINS.new"
  mv "$ROOT_DOMAINS.new" "$ROOT_DOMAINS"
  local pn cn; pn="$(wc -l < "$paying_roots" | tr -d ' ')"; cn="$(wc -l < "$chaos_roots" | tr -d ' ')"
  rm -f "$chaos_roots" "$paying_roots"
  [[ -s "$ROOT_DOMAINS" ]] || { log "No roots (no chaos cache, no scope DB)"; return; }
  log "Roots: $(wc -l < "$ROOT_DOMAINS") (paying-scope: $pn first, chaos: $cn)"
}

# ---- Subfinder (refresh sparingly) ----
refresh_subfinder() {
  command -v subfinder >/dev/null 2>&1 || return
  [[ -s "$ROOT_DOMAINS" ]] || return
  local age; age="$(age_h "$LAST_SUB")"
  if [[ -s "$SUB_CACHE" && "$age" -lt "$SUBFINDER_REFRESH_HOURS" ]]; then
    log "subfinder fresh (${age}h)"; return
  fi
  log "Running subfinder ($(wc -l < "$ROOT_DOMAINS") roots)"
  local tmp; tmp="$(mktemp)"
  # NOTE: redirect stdout to /dev/null. In -silent mode subfinder prints results
  # to BOTH stdout and the -o file; without this redirect every discovered
  # subdomain leaks into the daemon log (hundreds of lines per run). We read
  # results from "$tmp" (the -o file), so dropping stdout is safe.
  if timeout 1800 subfinder -dL "$ROOT_DOMAINS" -all -silent -nc -timeout 30 -o "$tmp" >/dev/null 2>&1; then
    tr '[:upper:]' '[:lower:]' < "$tmp" | sed -E 's#[[:space:]]##g' \
      | grep -E '^[a-z0-9.-]+\.[a-z]{2,}$' | sort -u > "$SUB_CACHE.new"
    mv "$SUB_CACHE.new" "$SUB_CACHE"
    echo "$NOW" > "$LAST_SUB"
    log "subfinder cache: $(wc -l < "$SUB_CACHE")"
  fi
  rm -f "$tmp"
}

refresh_assetfinder() {
  command -v assetfinder >/dev/null 2>&1 || return
  [[ -s "$ROOT_DOMAINS" ]] || return
  log "Running assetfinder (parallel)"
  local tmpdir; tmpdir="$(mktemp -d)"
  local max_jobs="${ASSETFINDER_PARALLEL:-10}"
  local running=0
  while IFS= read -r d; do
    [[ -z "$d" ]] && continue
    local out="$tmpdir/${d//[^a-zA-Z0-9._-]/_}.txt"
    ( run_net timeout 60 assetfinder --subs-only "$d" 2>/dev/null > "$out" || true ) &
    running=$(( running + 1 ))
    if [[ "$running" -ge "$max_jobs" ]]; then
      wait; running=0
    fi
  done < "$ROOT_DOMAINS"
  wait
  cat "$tmpdir"/*.txt 2>/dev/null \
    | tr '[:upper:]' '[:lower:]' | sed -E 's#[[:space:]]##g' \
    | grep -E '^[a-z0-9.-]+\.[a-z]{2,}$' | sort -u > "$ASSET_CACHE.tmp" \
    && mv "$ASSET_CACHE.tmp" "$ASSET_CACHE"
  rm -rf "$tmpdir"
  log "assetfinder cache: $(wc -l < "$ASSET_CACHE")"
}

# ---- Wildcard pre-filter ----
# Remove hosts that resolve via a wildcard DNS record — probing them produces
# identical 200s for every subdomain and burns httpx threads for zero signal.
filter_wildcards() {
  local in="$1" out="$2"
  command -v dig >/dev/null 2>&1 || { cp "$in" "$out"; return; }
  : > "$out"
  # Extract unique root domains from the candidate list
  local roots_tmp; roots_tmp="$(mktemp)"
  awk -F. '{ if (NF >= 2) print $(NF-1)"."$NF }' "$in" | sort -u > "$roots_tmp"
  # For each root domain, check if *.root resolves (wildcard present)
  declare -A wildcard_roots=()
  while IFS= read -r root; do
    [[ -z "$root" ]] && continue
    # Query a random subdomain; if it gets an A record, root is wildcard
    local probe="recon-wc-probe-$$-$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n').${root}"
    local res
    res="$(timeout 5 dig +short +time=2 +tries=1 "$probe" A 2>/dev/null | head -1)"
    [[ -n "$res" ]] && wildcard_roots["$root"]=1
  done < "$roots_tmp"
  rm -f "$roots_tmp"
  if [[ "${#wildcard_roots[@]}" -eq 0 ]]; then
    cp "$in" "$out"; return
  fi
  while IFS= read -r host; do
    local root
    root="$(awk -F. '{print $(NF-1)"."$NF}' <<< "$host" 2>/dev/null)"
    [[ -z "${wildcard_roots[$root]+x}" ]] && printf '%s\n' "$host"
  done < "$in" > "$out"
  local removed=$(( $(wc -l < "$in") - $(wc -l < "$out") ))
  [[ "$removed" -gt 0 ]] && log "Wildcard filter: dropped $removed hosts (wildcard DNS roots: ${!wildcard_roots[*]})"
}

# ---- Build delta + emit batches ----
emit_batches() {
  local all delta filtered
  all="$(mktemp)"; delta="$(mktemp)"; filtered="$(mktemp)"
  trap "rm -f $all $delta $filtered" RETURN

  cat "$CHAOS_CACHE" "${SUB_CACHE:-/dev/null}" "${ASSET_CACHE:-/dev/null}" 2>/dev/null \
    | sort -u > "$all"
  # Shared lock: discovery, validate AND cloudrecon all rewrite known_hosts under
  # their own (different) per-loop locks, so without this they race and lose
  # entries. flock on a dedicated known_hosts.lock serialises the writers.
  flock "$KNOWN_HOSTS.lock" sort -u "$KNOWN_HOSTS" -o "$KNOWN_HOSTS"
  chmod 644 "$KNOWN_HOSTS" 2>/dev/null || true   # sort -o resets perms via tmp+rename; keep world-readable
  comm -23 "$all" "$KNOWN_HOSTS" > "$delta" || true

  filter_wildcards "$delta" "$filtered"
  delta="$filtered"

  local total_new; total_new="$(wc -l < "$filtered" | tr -d ' ')"
  log "Total: $(wc -l < "$all") | Delta new: $total_new"

  [[ "$total_new" -eq 0 ]] && return

  local available_slots free_slots
  free_slots=$(( INBOX_FILE_CAP - $(inbox_count) ))
  [[ "$free_slots" -le 0 ]] && { log "No inbox slots free"; return; }

  # Split delta into batches, emit up to free_slots files
  local tmpdir; tmpdir="$(mktemp -d)"
  split -l "$BATCH_SIZE" -d --additional-suffix=.txt "$delta" "$tmpdir/batch_"
  local emitted=0
  for batch in "$tmpdir"/batch_*.txt; do
    [[ "$emitted" -ge "$free_slots" ]] && break
    local ts; ts="$(date -u +%Y%m%dT%H%M%S)"
    local out="$INBOX/10_${ts}_$(basename "$batch")"
    mv "$batch" "$out"
    emitted=$((emitted + 1))
  done
  rm -rf "$tmpdir"
  log "Emitted $emitted batches to $INBOX (skipped $(( total_new - emitted * BATCH_SIZE )) for next cycle)"
}

main() {
  log "=== discovery cycle start ==="
  refresh_chaos
  extract_roots
  refresh_subfinder
  refresh_assetfinder
  emit_batches
  log "=== discovery cycle done ==="
}
main "$@"

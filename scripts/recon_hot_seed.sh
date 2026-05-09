#!/usr/bin/env bash
# =============================================================================
# recon_hot_seed.sh — Surfaces in-flight subfinder discoveries IMMEDIATELY
# Tails partial output from running subfinder processes and emits 00_* batches
# (highest priority — validator picks these first → fastest first-blood path)
# =============================================================================
set -uo pipefail
log()  { printf '[%s HOT] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s HOT WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

BASE_DIR="${BASE_DIR:-$HOME/recon}"
INBOX="$BASE_DIR/queue/inbox"
STATE_DIR="$BASE_DIR/state"
LOCK_FILE="$STATE_DIR/hot_seed.lock"
SEEN_FILE="$STATE_DIR/hot_seed_seen.txt"
KNOWN_HOSTS="$STATE_DIR/known_hosts.txt"

mkdir -p "$INBOX" "$STATE_DIR"
exec 9>"$LOCK_FILE"; flock -n 9 || { warn "hot_seed already running"; exit 0; }
touch "$SEEN_FILE" "$KNOWN_HOSTS"

# Find all live subfinder/assetfinder output files in /tmp/ (their default cache locations)
find_live_outputs() {
  # subfinder caches in ~/.config/subfinder/, but partials sometimes in /tmp
  # Also check process descriptors of running subfinder processes
  local pids
  pids="$(pgrep -f 'subfinder|assetfinder' 2>/dev/null || true)"
  [[ -z "$pids" ]] && return 0
  local pid
  for pid in $pids; do
    # /proc/PID/fd shows open file descriptors — find ones writing to text files
    find "/proc/$pid/fd/" -maxdepth 1 -type l 2>/dev/null | while read -r fd; do
      local target; target="$(readlink "$fd" 2>/dev/null)"
      [[ -z "$target" || ! -f "$target" ]] && continue
      # Heuristic: must be a writable text file in /tmp or ~/.config/subfinder
      [[ "$target" =~ ^/tmp/.+ || "$target" =~ subfinder ]] || continue
      printf '%s\n' "$target"
    done
  done | sort -u
}

main() {
  log "=== hot_seed cycle ==="
  local outputs; outputs="$(find_live_outputs)"
  [[ -z "$outputs" ]] && { log "No live subfinder/assetfinder processes"; exit 0; }

  local tmp; tmp="$(mktemp)"
  : > "$tmp"
  while IFS= read -r f; do
    [[ -z "$f" || ! -r "$f" ]] && continue
    cat "$f" 2>/dev/null >> "$tmp" || true
  done <<< "$outputs"

  # Normalize, dedup vs SEEN and KNOWN_HOSTS
  local fresh; fresh="$(mktemp)"
  tr '[:upper:]' '[:lower:]' < "$tmp" \
    | sed -E 's#https?://##; s#/+$##; s#[[:space:]]##g' \
    | grep -E '^[a-z0-9.-]+\.[a-z]{2,}$' \
    | sort -u > "$tmp.sorted"

  comm -23 "$tmp.sorted" <(sort -u "$SEEN_FILE") \
    | comm -23 - <(sort -u "$KNOWN_HOSTS") > "$fresh" || true

  local n; n="$(wc -l < "$fresh" | tr -d ' ')"
  log "Fresh hot-seed candidates: $n"

  if [[ "$n" -gt 0 ]]; then
    local ts; ts="$(date -u +%Y%m%dT%H%M%S)"
    local batch="$INBOX/00_${ts}_hot.txt"
    cp "$fresh" "$batch"
    cat "$fresh" >> "$SEEN_FILE"
    log "Emitted hot batch: $(basename "$batch") ($n hosts)"
  fi

  rm -f "$tmp" "$tmp.sorted" "$fresh"

  # Trim seen file to avoid unbounded growth
  if [[ "$(wc -l < "$SEEN_FILE")" -gt 500000 ]]; then
    tail -n 400000 "$SEEN_FILE" > "$SEEN_FILE.tmp" && mv "$SEEN_FILE.tmp" "$SEEN_FILE"
  fi
  log "=== hot_seed done ==="
}
main "$@"

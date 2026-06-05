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
touch "$SEEN_FILE" 2>/dev/null || true
touch "$KNOWN_HOSTS" 2>/dev/null || true   # may be reconrun-owned; non-fatal if it fails

# Find all live subfinder/assetfinder output files.
# Reads the -o argument directly from /proc/$pid/cmdline (null-delimited args).
# The old /proc/$pid/fd/ symlink approach silently returned nothing because:
#   (a) fd enumeration fails cross-UID even when pgrep succeeds, and
#   (b) the readlink races with process teardown.
# Reading cmdline is stable, cross-user readable, and doesn't race.
find_live_outputs() {
  local pids
  pids="$(pgrep -f 'subfinder|assetfinder' 2>/dev/null || true)"
  [[ -z "$pids" ]] && return 0
  local pid
  for pid in $pids; do
    # /proc/$pid/cmdline is null-delimited — convert to newlines then grep for -o arg.
    # 2>/dev/null must precede the input redirect: bash applies redirections
    # left-to-right, so if the process exited (the file open fails — a normal
    # race), a trailing 2> would not yet be in effect to swallow the open error.
    local args; args="$(tr '\0' '\n' 2>/dev/null < "/proc/$pid/cmdline")"
    [[ -z "$args" ]] && continue
    # The line after '-o' is the output file path
    local outfile; outfile="$(printf '%s\n' "$args" | grep -A1 '^-o$' | tail -1)"
    [[ -n "$outfile" && "$outfile" != "-o" && -f "$outfile" ]] && printf '%s\n' "$outfile"
  done | sort -u
}

main() {
  log "=== hot_seed cycle ==="
  local outputs; outputs="$(find_live_outputs)"
  [[ -z "$outputs" ]] && exit 0

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

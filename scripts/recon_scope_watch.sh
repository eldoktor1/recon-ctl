#!/usr/bin/env bash
# =============================================================================
# recon_scope_watch.sh — Watches scope changes from chaos-data + arkadiyt's
# bounty-targets-data feed. Emits 01_* batches for newly-added programs/domains
# (priority just below hot_seed — these are high first-blood value because
# nobody has scanned them yet).
# =============================================================================
set -uo pipefail
log()  { printf '[%s SCOPE] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s SCOPE WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
die()  { printf '[%s SCOPE FATAL] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; exit 1; }
# v2.5.6: Tor/proxychains removed. Egress via system route (Mullvad).
proxy_required()     { return 1; }
ensure_proxy_ready() { return 0; }
run_net()            { "$@"; }



BASE_DIR="${BASE_DIR:-$HOME/recon}"
INBOX="$BASE_DIR/queue/inbox"
STATE_DIR="$BASE_DIR/state"
CACHE_DIR="$BASE_DIR/cache"
LOCK_FILE="$STATE_DIR/scope_watch.lock"
SCOPE_CHECK="${SCOPE_CHECK:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/recon_scope_check.sh}"
PAYING_ONLY="${SCOPE_WATCH_PAYING_ONLY:-1}"

PREV_SCOPE="$STATE_DIR/scope_prev.txt"
CUR_SCOPE="$CACHE_DIR/scope_current.txt"

# arkadiyt feed — wildcard scope from HackerOne, Bugcrowd, Intigriti
ARK_URL="https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/domains.txt"

mkdir -p "$INBOX" "$STATE_DIR" "$CACHE_DIR"
exec 9>"$LOCK_FILE"; flock -n 9 || { warn "scope_watch already running"; exit 0; }
touch "$PREV_SCOPE"

main() {
  log "=== scope_watch cycle ==="
  local tmp; tmp="$(mktemp)"
  if ! run_net timeout 60 curl -fsS "$ARK_URL" -o "$tmp" 2>/dev/null; then
    warn "Failed to fetch arkadiyt scope"
    rm -f "$tmp"; exit 0
  fi

  tr '[:upper:]' '[:lower:]' < "$tmp" \
    | sed -E 's#^\*\.##; s#https?://##; s#/+$##; s#[[:space:]]##g' \
    | grep -E '^[a-z0-9.-]+\.[a-z]{2,}$' \
    | sort -u > "$CUR_SCOPE"
  rm -f "$tmp"

  log "Scope size: $(wc -l < "$CUR_SCOPE")"

  # Diff
  local new_domains; new_domains="$(mktemp)"
  comm -23 "$CUR_SCOPE" "$PREV_SCOPE" > "$new_domains" || true
  local n; n="$(wc -l < "$new_domains" | tr -d ' ')"

  if [[ "$n" -eq 0 ]]; then
    log "No scope changes"
    rm -f "$new_domains"
    cp "$CUR_SCOPE" "$PREV_SCOPE"
    exit 0
  fi

  log "New scope additions: $n"

  # For each new ROOT domain, attempt rapid subfinder enumeration (timeboxed)
  local enriched; enriched="$(mktemp)"
  : > "$enriched"

  if command -v subfinder >/dev/null 2>&1; then
    log "Enriching new scope with rapid subfinder (max 5min total)"
    timeout 300 subfinder -dL "$new_domains" -silent -nc -timeout 15 -t 50 \
      -all -o "$enriched" 2>/dev/null || warn "subfinder enrichment timed out"
  fi

  # Combine the new root domains themselves + any subfinder results
  cat "$new_domains" "$enriched" 2>/dev/null \
    | tr '[:upper:]' '[:lower:]' \
    | sed -E 's#[[:space:]]##g' \
    | grep -E '^[a-z0-9.-]+\.[a-z]{2,}$' \
    | sort -u > "$enriched.combined"

  if [[ "$PAYING_ONLY" == "1" && -f "$SCOPE_CHECK" ]]; then
    local paying_only; paying_only="$(mktemp)"
    bash "$SCOPE_CHECK" --filter in-scope-paying < "$enriched.combined" > "$paying_only" 2>/dev/null || : > "$paying_only"
    mv "$paying_only" "$enriched.combined"
    log "Paying-program filter enabled for new scope"
  fi

  local total; total="$(wc -l < "$enriched.combined" | tr -d ' ')"

  if [[ "$total" -gt 0 ]]; then
    local ts; ts="$(date -u +%Y%m%dT%H%M%S)"
    # Split into 5000-line batches
    local tmpd; tmpd="$(mktemp -d)"
    split -l 5000 -d --additional-suffix=.txt "$enriched.combined" "$tmpd/scope_"
    local emitted=0
    for batch in "$tmpd"/scope_*.txt; do
      local out="$INBOX/01_${ts}_$(basename "$batch")"
      mv "$batch" "$out"
      emitted=$((emitted + 1))
    done
    rm -rf "$tmpd"
    log "Emitted $emitted scope batches ($total hosts) — first-blood candidates"
  fi

  cp "$CUR_SCOPE" "$PREV_SCOPE"
  rm -f "$new_domains" "$enriched" "$enriched.combined"
  log "=== scope_watch done ==="
}
main "$@"

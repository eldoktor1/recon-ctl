#!/usr/bin/env bash
# =============================================================================
# recon_cloudrecon.sh — Caduceus neighbor cert-recon (v2.8)
#
# IDEA (from g0ldencybersec CloudRecon/Caduceus, DEF CON 31)
#   Inspect the TLS certificates served on IPs we ALREADY know host in-scope
#   assets. A single server commonly serves many virtual hosts; its cert SANs
#   reveal sibling/co-hosted domains that never appear in CT logs, DNS brute, or
#   subfinder. This finds "hidden gems" sitting next to known targets.
#
# WHY NOT asnmap ranges
#   Most targets are cloud-hosted, so asnmap returns the PROVIDER's ranges
#   (e.g. pismo.io -> 34.64.0.0/14 = all of Google Cloud). Scanning those is
#   infeasible and yields only other tenants' certs. Instead we seed from the
#   IPs of hosts the pipeline has ALREADY validated as in-scope (pulled from ES),
#   which are guaranteed to belong to our targets. Optional bounded /24 expansion
#   (CLOUDRECON_EXPAND_24=1) widens to the immediate neighborhood.
#
# OUTPUT  ~/recon/queue/inbox/11_cloudrecon_<ts>_<batch>.txt  (validator lane)
#
# EGRESS  Target-facing TLS handshakes. Invoked by the daemon via run_scanner
#   (sudo -u reconrun) so it egresses through Mullvad like every other scanner.
#   caduceus is a Go tool (epoll netpoller + per-handshake timeout) so it cannot
#   wedge in WSL2 D-state the way curl does.
# =============================================================================
set -uo pipefail
IFS=$'\n\t'

log()  { printf '[%s CLOUDRECON] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s CLOUDRECON WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCOPE_CHECK="${SCOPE_CHECK:-$SCRIPT_DIR/recon_scope_check.sh}"

BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
CR_DIR="$STATE_DIR/cloudrecon"
INBOX="$BASE_DIR/queue/inbox"
KNOWN_HOSTS="$STATE_DIR/known_hosts.txt"     # shared with discovery (delta source)
LOCK_FILE="$STATE_DIR/cloudrecon.lock"

ES_URL="${ES_URL:-http://127.0.0.1:9200}"
ES_USER="${ES_USER:-elastic}"
ES_PASS="${ES_PASS:-$(tr -d '[:space:]' < "$HOME/.recon_es_pass" 2>/dev/null || true)}"
INDEX_NAME="${INDEX_NAME:-recon_alive}"

CADUCEUS_BIN="${CADUCEUS_BIN:-$HOME/go/bin/caduceus}"
CLOUDRECON_BATCH_IPS="${CLOUDRECON_BATCH_IPS:-256}"   # IPs scanned per cycle (bounded)
CLOUDRECON_PORTS="${CLOUDRECON_PORTS:-443}"
CLOUDRECON_CONCURRENCY="${CLOUDRECON_CONCURRENCY:-100}"  # breadth: distinct IPs, ~1 handshake each
CLOUDRECON_TIMEOUT="${CLOUDRECON_TIMEOUT:-5}"          # per-handshake seconds
CLOUDRECON_EXPAND_24="${CLOUDRECON_EXPAND_24:-0}"      # 1 = scan each seed IP's /24
CLOUDRECON_IP_REFRESH="${CLOUDRECON_IP_REFRESH:-21600}" # re-pull in-scope IPs from ES every 6h
CLOUDRECON_MAX_RUNTIME="${CLOUDRECON_MAX_RUNTIME:-900}" # hard cap on a caduceus run
INBOX_FILE_CAP="${INBOX_FILE_CAP:-200}"
BATCH_SIZE="${BATCH_SIZE:-2500}"

IP_CACHE="$CR_DIR/inscope_ips.txt"
IDX_FILE="$CR_DIR/.ip_idx"
LAST_IP_REFRESH="$CR_DIR/.last_ip_refresh"

mkdir -p "$CR_DIR" "$INBOX"
touch "$KNOWN_HOSTS"

exec 9>"$LOCK_FILE"
flock -n 9 || { warn "cloudrecon already running"; exit 0; }
# FD_CLOEXEC so any exec'd child never inherits/holds the lock fd.
python3 -c "import fcntl; fcntl.fcntl(9, fcntl.F_SETFD, fcntl.FD_CLOEXEC)" 2>/dev/null || true

command -v jq >/dev/null 2>&1 || { warn "jq missing"; exit 0; }
[[ -x "$CADUCEUS_BIN" ]] || { warn "caduceus not found at $CADUCEUS_BIN — go install github.com/g0ldencybersec/Caduceus/cmd/caduceus@latest"; exit 0; }

inbox_count() { find "$INBOX" -maxdepth 1 -name '*.txt' 2>/dev/null | wc -l | tr -d ' '; }
if [[ "$(inbox_count)" -ge "$INBOX_FILE_CAP" ]]; then
  log "Inbox full ($(inbox_count) ≥ $INBOX_FILE_CAP) — pausing cloudrecon"
  exit 0
fi

# ---- 1. Refresh the in-scope IP seed list from ES (bounded, cached) --------
es_curl() { curl -sS -m 30 -u "$ES_USER:$ES_PASS" "$@"; }

refresh_inscope_ips() {
  local last age
  last="$(cat "$LAST_IP_REFRESH" 2>/dev/null || echo 0)"
  age=$(( $(date +%s) - last ))
  if [[ -s "$IP_CACHE" && "$age" -lt "$CLOUDRECON_IP_REFRESH" ]]; then
    return 0
  fi
  # ES up?
  local code
  code="$(curl -sS -o /dev/null -m 5 -w '%{http_code}' -u "$ES_USER:$ES_PASS" "$ES_URL" 2>/dev/null || echo 000)"
  if [[ "$code" != "200" ]]; then
    warn "ES not reachable ($code) — using existing IP cache if any"
    return 0
  fi
  # Unique IPv4s of in-scope hosts. terms agg, bounded size.
  local query resp tmp
  query='{"size":0,"query":{"bool":{"filter":[{"term":{"triage_in_scope":true}}]}},"aggs":{"ips":{"terms":{"field":"ip","size":20000}}}}'
  resp="$(es_curl -H 'Content-Type: application/json' -X POST "$ES_URL/$INDEX_NAME/_search" -d "$query" 2>/dev/null)" || resp=""
  [[ -z "$resp" ]] && { warn "ES query failed — keeping old IP cache"; return 0; }
  tmp="$(mktemp)"
  printf '%s' "$resp" | jq -r '.aggregations.ips.buckets[]?.key // empty' 2>/dev/null \
    | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' \
    | grep -vE '^(10\.|127\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|0\.|255\.)' \
    | sort -u > "$tmp"
  if [[ -s "$tmp" ]]; then
    mv "$tmp" "$IP_CACHE"
    date +%s > "$LAST_IP_REFRESH"
    log "refreshed in-scope IP seeds: $(wc -l < "$IP_CACHE" | tr -d ' ')"
  else
    rm -f "$tmp"
    warn "ES returned no in-scope IPs (pipeline may not have validated any yet)"
  fi
}

refresh_inscope_ips

[[ -s "$IP_CACHE" ]] || { log "no in-scope IP seeds yet — nothing to scan"; exit 0; }

# ---- 2. Rotate a bounded batch of seed IPs ---------------------------------
total="$(wc -l < "$IP_CACHE" | tr -d ' ')"
start="$(cat "$IDX_FILE" 2>/dev/null || echo 0)"
[[ "$start" =~ ^[0-9]+$ ]] || start=0
(( start >= total )) && start=0

targets="$(mktemp)"
trap 'rm -f "$targets" "$targets".certs "$targets".doms "$targets".scoped "$targets".fresh' EXIT

# Build this cycle's target list (exact seed IPs, or their /24s if expansion on).
# /24 expansion can repeat a subnet across adjacent seed IPs, so dedup after.
i=0; idx=$start
while (( i < CLOUDRECON_BATCH_IPS && i < total )); do
  ip="$(sed -n "$((idx+1))p" "$IP_CACHE")"
  if [[ -n "$ip" ]]; then
    if [[ "$CLOUDRECON_EXPAND_24" == "1" ]]; then
      printf '%s.0/24\n' "${ip%.*}" >> "$targets"
    else
      printf '%s\n' "$ip" >> "$targets"
    fi
  fi
  i=$((i+1)); idx=$(( (start + i) % total ))
done
sort -u "$targets" -o "$targets"
echo "$idx" > "$IDX_FILE"

ntargets="$(wc -l < "$targets" | tr -d ' ')"
[[ "$ntargets" -eq 0 ]] && { log "no targets this cycle"; exit 0; }
log "scanning $ntargets target(s) (seed idx $start→$idx/$total, expand_24=$CLOUDRECON_EXPAND_24)"

# ---- 3. Caduceus cert scan -------------------------------------------------
timeout --kill-after=30 "$CLOUDRECON_MAX_RUNTIME" \
  "$CADUCEUS_BIN" -i "$(paste -sd, "$targets")" -j \
  -p "$CLOUDRECON_PORTS" -c "$CLOUDRECON_CONCURRENCY" -t "$CLOUDRECON_TIMEOUT" \
  > "$targets".certs 2>/dev/null || warn "caduceus exited non-zero (partial results kept)"

[[ -s "$targets".certs ]] || { log "no certs returned this cycle"; exit 0; }

# ---- 4. Extract domains from cert CN+SANs ----------------------------------
jq -r '.domains[]? // empty' "$targets".certs 2>/dev/null \
  | tr 'A-Z' 'a-z' | sed -E 's/^\*\.//; s/[[:space:]]//g; s/\.$//' \
  | grep -E '^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$' \
  | awk 'NF && !seen[$0]++' > "$targets".doms

ndoms="$(wc -l < "$targets".doms | tr -d ' ')"
log "extracted $ndoms unique domain(s) from certs"
[[ "$ndoms" -eq 0 ]] && exit 0

# ---- 5. Keep only in-scope-paying (co-hosted other-tenant domains are noise) -
bash "$SCOPE_CHECK" --filter in-scope-paying < "$targets".doms \
  | awk 'NF && !seen[$0]++' > "$targets".scoped
nscoped="$(wc -l < "$targets".scoped | tr -d ' ')"
log "in-scope-paying: $nscoped"
[[ "$nscoped" -eq 0 ]] && exit 0

# ---- 6. Delta vs known hosts, then emit batches ----------------------------
flock "$KNOWN_HOSTS.lock" sort -u "$KNOWN_HOSTS" -o "$KNOWN_HOSTS"   # shared lock w/ discovery+validate
sort -u "$targets".scoped -o "$targets".scoped
comm -23 "$targets".scoped "$KNOWN_HOSTS" > "$targets".fresh 2>/dev/null || cp "$targets".scoped "$targets".fresh

nfresh="$(wc -l < "$targets".fresh | tr -d ' ')"
log "new (not already known): $nfresh"
[[ "$nfresh" -eq 0 ]] && exit 0

free_slots=$(( INBOX_FILE_CAP - $(inbox_count) ))
[[ "$free_slots" -le 0 ]] && { log "no inbox slots free"; exit 0; }

splitdir="$(mktemp -d)"
split -l "$BATCH_SIZE" "$targets".fresh "$splitdir/b_"
emitted=0; ts="$(date -u +%Y%m%dT%H%M%SZ)"
for f in "$splitdir"/b_*; do
  [[ "$emitted" -ge "$free_slots" ]] && break
  dest="$INBOX/11_cloudrecon_${ts}_$(printf '%03d' "$((emitted+1))").txt"
  mv "$f" "$dest" && { emitted=$((emitted+1)); log "queued $dest ($(wc -l < "$dest" | tr -d ' ') hosts)"; }
done
rm -rf "$splitdir"
log "done — $nfresh new in-scope hosts in $emitted batch(es)"

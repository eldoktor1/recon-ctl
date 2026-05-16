#!/usr/bin/env bash
# =============================================================================
# recon_true_fresh.sh — True-freshness engine (v2.5)
#
# DESIGN
#   - Certstream listener (background Python child, single-instance via pidfile)
#     streams real-time CT log entries, in-memory scope filters them, and
#     appends in-scope-paying matches to a holding file.
#   - crt.sh poller (every CRT_SH_INTERVAL seconds, when due) fetches recent
#     certs for each root domain in scope and adds entries with not_before ≤ 24h
#     to the same holding file.
#   - Flush phase: dedupes against a 24h cooldown file, writes to
#     ~/recon/state/true_fresh.jsonl (the durable feed), splits into
#     500-line batches named 00_truefresh_<iso_ts>_<batch>.txt under
#     ~/recon/queue/inbox/ for the fast validator lane.
#
# EGRESS
#   Runs as d0k (not reconrun) — passive CT log feeds, no target-facing traffic.
#   Certstream WSS and crt.sh GET requests egress via Mullvad like everything else.
#
# CLEANUP
#   - Holding file deleted on every flush.
#   - crt.sh JSON responses deleted immediately after extraction.
#   - seen_hosts cooldown file pruned to a rolling 24h window each flush.
# =============================================================================
set -uo pipefail
IFS=$'\n\t'

log()  { printf '[%s TRUE-FRESH] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s TRUE-FRESH WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCOPE_CHECK="${SCOPE_CHECK:-$SCRIPT_DIR/recon_scope_check.sh}"

BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
TF_DIR="$STATE_DIR/true_fresh"
QUEUE_INBOX="$BASE_DIR/queue/inbox"
SCOPE_DIR="${SCOPE_DIR:-$BASE_DIR/scope}"

HOLDING_FILE="$TF_DIR/holding.jsonl"
SEEN_FILE="$TF_DIR/seen_hosts.txt"
PERSIST_JSONL="$TF_DIR/../true_fresh.jsonl"   # i.e. ~/recon/state/true_fresh.jsonl
PIDFILE="$TF_DIR/certstream.pid"
LISTENER_LOG="$BASE_DIR/logs/true_fresh_listener.log"
LOCK_FILE="$STATE_DIR/true_fresh.lock"

BATCH_SIZE="${TRUE_FRESH_BATCH_SIZE:-500}"
COOLDOWN_HOURS="${TRUE_FRESH_COOLDOWN_HOURS:-24}"
# v2.5.4: dropped from 6h → 2h. certstream.calidog.io is unreliable in
# practice, so crt.sh is the load-bearing source of freshness.
CRT_SH_INTERVAL="${CRT_SH_INTERVAL:-7200}"
CRT_SH_TIMEOUT="${CRT_SH_TIMEOUT:-30}"
MAX_PER_FLUSH="${TRUE_FRESH_MAX_PER_FLUSH:-5000}"

mkdir -p "$TF_DIR" "$QUEUE_INBOX" "$BASE_DIR/logs"
touch "$HOLDING_FILE" "$SEEN_FILE" "$PERSIST_JSONL"

exec 9>"$LOCK_FILE"
flock -n 9 || { warn "true_fresh already running"; exit 0; }

# ---- Scope DB presence check (otherwise nothing matches) -------------------
INSCOPE_TSV="$SCOPE_DIR/inscope_patterns.tsv"
if [[ ! -s "$INSCOPE_TSV" ]]; then
  warn "scope DB not populated ($INSCOPE_TSV missing); skipping cycle"
  exit 0
fi

# ---- 1. Ensure certstream listener is running ------------------------------
certstream_alive() {
  [[ -s "$PIDFILE" ]] || return 1
  local pid; pid="$(cat "$PIDFILE" 2>/dev/null)"
  [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null
}

# Locate a python3 interpreter that can `import certstream`. Probes (in order):
#   1. $BASE_DIR/.venv         — repo-local venv we manage ourselves
#   2. ~/.local/share/pipx/venvs/certstream  — `pipx install certstream`
#   3. ~/.local/pipx/venvs/certstream        — alt pipx prefix
#   4. system python3 (rare; PEP-668 blocks pip on Kali/Debian)
# If none works, auto-bootstrap (1): create the repo venv and pip-install
# certstream into it. After first run, every restart is instant.
resolve_certstream_python() {
  command -v python3 >/dev/null 2>&1 || { warn "python3 missing"; return 1; }
  local candidates=(
    "$BASE_DIR/.venv/bin/python3"
    "$HOME/.local/share/pipx/venvs/certstream/bin/python3"
    "$HOME/.local/pipx/venvs/certstream/bin/python3"
    "$(command -v python3)"
  )
  for py in "${candidates[@]}"; do
    [[ -x "$py" ]] || continue
    if "$py" -c 'import certstream' >/dev/null 2>&1; then
      printf '%s\n' "$py"; return 0
    fi
  done

  # Nothing has it — bootstrap the repo venv.
  log "certstream not found anywhere; bootstrapping $BASE_DIR/.venv (one-time, ~30s)"
  if ! python3 -m venv "$BASE_DIR/.venv" >>"$LISTENER_LOG" 2>&1; then
    warn "venv creation failed; install certstream manually:"
    warn "  python3 -m venv $BASE_DIR/.venv && $BASE_DIR/.venv/bin/pip install certstream"
    return 1
  fi
  "$BASE_DIR/.venv/bin/pip" install --quiet --upgrade pip >>"$LISTENER_LOG" 2>&1 || true
  if ! "$BASE_DIR/.venv/bin/pip" install --quiet certstream >>"$LISTENER_LOG" 2>&1; then
    warn "pip install certstream failed; see $LISTENER_LOG"
    return 1
  fi
  if "$BASE_DIR/.venv/bin/python3" -c 'import certstream' >/dev/null 2>&1; then
    printf '%s\n' "$BASE_DIR/.venv/bin/python3"; return 0
  fi
  warn "post-bootstrap import still fails; see $LISTENER_LOG"
  return 1
}

start_certstream() {
  local PY
  PY="$(resolve_certstream_python)" || return 1
  log "Starting certstream listener via $PY"
  # CRITICAL: 9>&- closes the script lock fd in the child. Without this, the
  # long-lived listener inherits fd 9 and keeps the flock held forever — every
  # supervise_loop iteration after the first then bails with "true_fresh
  # already running", silently disabling crt.sh polling and the flush phase.
  nohup "$PY" - "$INSCOPE_TSV" "$HOLDING_FILE" 9>&- >>"$LISTENER_LOG" 2>&1 <<'PY' &
import sys, os, json, time, fcntl, re
import certstream

inscope_tsv = sys.argv[1]
holding_file = sys.argv[2]

# --- Load scope patterns into memory once -----------------------------------
# TSV columns (from recon_scope_check.sh): pattern, program, platform, pays, payout_tier
exact = set()
suffixes = []  # list of (suffix_with_dot, apex)
def load():
    try:
        with open(inscope_tsv, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.rstrip("\r\n")
                if not line:
                    continue
                fields = line.split("\t")
                pat = fields[0].strip().lower()
                pays = (fields[3].strip().lower() if len(fields) > 3 else "false") == "true"
                if not pays:
                    continue  # only paying scope
                if pat.startswith("*."):
                    suf = pat[1:]            # ".example.com"
                    apex = pat[2:]            # "example.com"
                    suffixes.append((suf, apex))
                else:
                    exact.add(pat)
    except Exception as e:
        sys.stderr.write("scope load error: %s\n" % e)
load()

def matches(host):
    h = host.lower().rstrip(".")
    if h in exact:
        return True
    for suf, apex in suffixes:
        if h == apex:
            return True
        if h.endswith(suf):
            return True
    return False

VALID_HOST = re.compile(r"^(?!-)[A-Za-z0-9*_-]+(\.(?!-)[A-Za-z0-9_-]+)+$")

def emit(host, src):
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    line = json.dumps({"host": host.lower().rstrip("."), "external_first_seen": ts, "src": src}, separators=(",", ":")) + "\n"
    try:
        with open(holding_file, "a", encoding="utf-8") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.write(line)
            fcntl.flock(f, fcntl.LOCK_UN)
    except Exception as e:
        # v2.5.5: surface emit failures instead of swallowing them silently
        _stats["emit_errors"] += 1
        if _stats["emit_errors"] <= 5:
            sys.stderr.write("emit failed: %s (host=%s)\n" % (e, host))
            sys.stderr.flush()

# v2.5.5: counters + periodic stats line so we can SEE what the listener is
# actually doing. Without these the script could appear "alive" while
# matching zero hosts forever (which we just observed for 17h).
_stats = {"certs": 0, "domains_seen": 0, "matches": 0, "emit_errors": 0}
_last_stats = time.time()
def _maybe_log_stats():
    global _last_stats
    now = time.time()
    if now - _last_stats >= 300:  # every 5 min
        sys.stderr.write(
            "stats: certs=%d domains_seen=%d matches=%d emit_errors=%d scope=%d+%d\n"
            % (_stats["certs"], _stats["domains_seen"], _stats["matches"],
               _stats["emit_errors"], len(exact), len(suffixes))
        )
        sys.stderr.flush()
        _last_stats = now

def callback(message, context):
    _stats["certs"] += 1
    _maybe_log_stats()
    if message.get("message_type") != "certificate_update":
        return
    leaf = message.get("data", {}).get("leaf_cert", {})
    all_domains = set()
    cn = leaf.get("subject", {}).get("CN") or ""
    if cn:
        all_domains.add(cn)
    for d in (leaf.get("all_domains") or []):
        if d:
            all_domains.add(d)
    for d in all_domains:
        _stats["domains_seen"] += 1
        # Strip leading wildcard *. but NOT a bare wildcard
        d = d.strip()
        if d.startswith("*."):
            d = d[2:]
        d = d.lower().rstrip(".")
        if not d:
            continue
        if matches(d):
            _stats["matches"] += 1
            emit(d, "certstream")

# Reload scope periodically without restart
import threading
def reload_loop():
    while True:
        time.sleep(900)
        exact.clear()
        suffixes.clear()
        load()
threading.Thread(target=reload_loop, daemon=True).start()

# v2.5.4: exponential backoff on reconnect. certstream.calidog.io drops
# connections frequently; constant 10s reconnects spam the log without
# helping. Start at 30s, double up to 300s.
backoff = 30
while True:
    try:
        certstream.listen_for_events(callback, url="wss://certstream.calidog.io/")
        backoff = 30  # reset on clean exit (rare)
    except Exception as e:
        sys.stderr.write("certstream reconnect in %ds: %s\n" % (backoff, e))
        time.sleep(backoff)
        backoff = min(backoff * 2, 300)
PY
  local cspid=$!
  echo "$cspid" > "$PIDFILE"
  log "certstream listener started (pid $cspid)"
}

if ! certstream_alive; then
  start_certstream || true
fi

# ---- 2. crt.sh poller (when due) -------------------------------------------
crt_sh_due() {
  local marker="$TF_DIR/.last_crt_sh"
  local last; last="$(cat "$marker" 2>/dev/null || echo 0)"
  local now; now="$(date +%s)"
  (( now - last >= CRT_SH_INTERVAL ))
}
mark_crt_sh_done() { date +%s > "$TF_DIR/.last_crt_sh"; }

poll_crt_sh() {
  command -v jq >/dev/null 2>&1 || { warn "jq missing"; return 0; }
  command -v curl >/dev/null 2>&1 || { warn "curl missing"; return 0; }

  # Distinct root domains from in-scope paying patterns (strip leading *., trim apex)
  local roots; roots="$(mktemp)"
  awk -F'\t' '
    $4=="true" {
      pat=$1
      sub(/^\*\./, "", pat)
      # Use apex: last two labels at minimum
      n=split(pat, parts, ".")
      if (n >= 2) {
        apex = parts[n-1] "." parts[n]
        print apex
      }
    }' "$INSCOPE_TSV" | sort -u > "$roots"

  local total; total="$(wc -l < "$roots" | tr -d ' ')"
  log "crt.sh polling $total root domains"
  local since; since="$(date -u -d '-24 hours' +%s)"
  local added=0

  while IFS= read -r root; do
    [[ -z "$root" ]] && continue
    local resp; resp="$(mktemp)"
    if curl -fsS -m "$CRT_SH_TIMEOUT" -A 'Mozilla/5.0 recon-pipeline true-fresh' \
         "https://crt.sh/?q=%25.${root}&output=json" -o "$resp" 2>/dev/null; then
      # crt.sh returns array of {name_value, not_before, ...}
      while IFS= read -r host; do
        [[ -z "$host" ]] && continue
        printf '{"host":"%s","external_first_seen":"%s","src":"crt.sh"}\n' \
          "$host" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" >> "$HOLDING_FILE"
        added=$((added + 1))
      done < <(jq -r --argjson since "$since" '
        if type=="array" then
          .[] | select((.not_before // "") != "") |
          (.not_before | sub(" "; "T") + "Z" | sub("ZZ$"; "Z") | fromdate) as $epoch |
          select($epoch >= $since) |
          (.name_value // "") | split("\n")[] |
          ascii_downcase |
          select(. != "") |
          sub("^\\*\\."; "")
        else empty end
      ' "$resp" 2>/dev/null | sort -u)
    fi
    rm -f "$resp"
    sleep 1   # be polite to crt.sh
  done < "$roots"
  rm -f "$roots"
  mark_crt_sh_done
  log "crt.sh batch added $added raw entries (pre-filter)"
}

if crt_sh_due; then
  poll_crt_sh || warn "crt.sh poll had errors (continuing)"
fi

# ---- 3. Flush phase --------------------------------------------------------
# Holding entries may include non-scope entries (e.g. crt.sh raw). Scope-filter
# them through recon_scope_check.sh in batch mode, drop duplicates against the
# 24h seen file, write to the durable jsonl + queue batches.

if [[ ! -s "$HOLDING_FILE" ]]; then
  log "Nothing to flush this cycle"
  exit 0
fi

WORK="$(mktemp)"
trap 'rm -f "$WORK" "$WORK.scoped" "$WORK.fresh" "$WORK.candidates"' EXIT

# Cap how many we process per flush
head -n "$MAX_PER_FLUSH" "$HOLDING_FILE" > "$WORK"
# Atomically rotate: anything appended after the cp is preserved
{ flock 9; : > "$HOLDING_FILE"; } 2>/dev/null || : > "$HOLDING_FILE"

# Extract candidate hosts (dedupe in-memory)
jq -r '.host // empty' "$WORK" 2>/dev/null | awk 'NF && !seen[$0]++' > "$WORK.candidates"

# Run in-scope-paying filter (single awk pass via recon_scope_check.sh)
if [[ ! -s "$WORK.candidates" ]]; then
  log "Holding had no parseable hosts"
  exit 0
fi

bash "$SCOPE_CHECK" --filter in-scope-paying < "$WORK.candidates" \
  | awk 'NF && !seen[$0]++' > "$WORK.scoped"

scoped_n="$(wc -l < "$WORK.scoped" | tr -d ' ')"
log "Scope-filtered: $scoped_n in-scope-paying candidates"

if [[ "$scoped_n" -eq 0 ]]; then
  exit 0
fi

# ---- 24h cooldown dedupe (seen_hosts.txt) ----------------------------------
# Format: <epoch>\t<host>. Prune anything older than COOLDOWN_HOURS before
# checking. This keeps the file bounded.
NOW="$(date +%s)"
CUTOFF=$(( NOW - COOLDOWN_HOURS * 3600 ))

PRUNED="$(mktemp)"
awk -v cutoff="$CUTOFF" -F'\t' '$1 >= cutoff' "$SEEN_FILE" > "$PRUNED" 2>/dev/null || true
mv "$PRUNED" "$SEEN_FILE"

awk -F'\t' '{print $2}' "$SEEN_FILE" | sort -u > "$WORK.seen"
grep -Fxv -f "$WORK.seen" "$WORK.scoped" > "$WORK.fresh" 2>/dev/null || cp "$WORK.scoped" "$WORK.fresh"
rm -f "$WORK.seen"

fresh_n="$(wc -l < "$WORK.fresh" | tr -d ' ')"
log "After 24h cooldown: $fresh_n truly new hosts"
if [[ "$fresh_n" -eq 0 ]]; then
  exit 0
fi

# ---- Write to durable jsonl + record in seen ------------------------------
ISO="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
while IFS= read -r host; do
  [[ -z "$host" ]] && continue
  printf '%s\t%s\n' "$NOW" "$host" >> "$SEEN_FILE"
  printf '{"host":"%s","external_first_seen":"%s"}\n' "$host" "$ISO" >> "$PERSIST_JSONL"
done < "$WORK.fresh"

# Keep PERSIST_JSONL bounded — entries older than 7d serve no purpose downstream
TMP_TF="$(mktemp)"
SEVEN_DAYS_AGO="$(date -u -d '-7 days' '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u '+%Y-%m-%dT%H:%M:%SZ')"
jq -c --arg cutoff "$SEVEN_DAYS_AGO" 'select((.external_first_seen // "") >= $cutoff)' \
   "$PERSIST_JSONL" 2>/dev/null > "$TMP_TF" && mv "$TMP_TF" "$PERSIST_JSONL"

# ---- Split into 500-line batches under queue/inbox with 00_ prefix --------
BATCH_TS="$(date -u +%Y%m%dT%H%M%SZ)"
SPLITDIR="$(mktemp -d)"
split -l "$BATCH_SIZE" "$WORK.fresh" "$SPLITDIR/b_"
i=0
for f in "$SPLITDIR"/b_*; do
  i=$((i + 1))
  dest="$QUEUE_INBOX/00_truefresh_${BATCH_TS}_$(printf '%03d' "$i").txt"
  mv "$f" "$dest" && log "queued $dest ($(wc -l < "$dest" | tr -d ' ') hosts)"
done
rmdir "$SPLITDIR" 2>/dev/null || true

log "Flush done — $fresh_n hosts queued in $i batch(es)"

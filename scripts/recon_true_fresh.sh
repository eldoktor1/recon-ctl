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
MAX_PER_FLUSH="${TRUE_FRESH_MAX_PER_FLUSH:-5000}"

# === CT-log freshness sources (v2.6) ========================================
# Reality check (2026-05): certstream.calidog.io's WSS stream is degraded and
# crt.sh is Cloudflare-rate-limited to the point of returning nothing. So the
# load-bearing source is now Cert Spotter's API, polled incrementally with a
# per-domain cursor (the `after` position param) so each poll returns only
# NEW issuances. certstream stays as a best-effort real-time firehose; crt.sh
# is a bounded last-resort fallback. All three feed the same holding file.
#
# Cert Spotter free tier works tokenless but is aggressively rate-limited, so
# we rotate through paying roots a bounded batch at a time and resume where a
# 429 stopped us. Drop a token at ~/.recon_certspotter_token to raise limits.
CERTSPOTTER_API="${CERTSPOTTER_API:-https://api.certspotter.com/v1/issuances}"
CERTSPOTTER_TOKEN="${CERTSPOTTER_TOKEN:-}"
[[ -z "$CERTSPOTTER_TOKEN" && -f "$HOME/.recon_certspotter_token" ]] && \
  CERTSPOTTER_TOKEN="$(tr -d '[:space:]' < "$HOME/.recon_certspotter_token" 2>/dev/null || true)"
CERTSPOTTER_INTERVAL="${CERTSPOTTER_INTERVAL:-600}"      # poll cadence (10 min)
CERTSPOTTER_TIMEOUT="${CERTSPOTTER_TIMEOUT:-25}"
# Cert Spotter paginates issuances OLDEST-first at 100/page (forward-only via
# the `after` id). To converge a domain's cursor toward the present we follow
# up to MAX_PAGES pages per root per cycle. The not_before window filter is
# applied on EVERY page, so a lagging cursor can never emit a stale subdomain —
# correctness is independent of cursor position; paging only affects how fast
# we reach the tip.
CERTSPOTTER_MAX_PAGES="${CERTSPOTTER_MAX_PAGES:-3}"
if [[ -n "$CERTSPOTTER_TOKEN" ]]; then
  # Measured free-token rate limit: ~3-5 successful requests per 330s window.
  # With INTERVAL=600s the window resets between cycles. BATCH=8 = 48 roots/hr.
  # Domains sorted elite-first so the limited quota hits the best programs.
  # Sleep 3s between requests to stay under burst thresholds.
  # To unlock higher throughput, upgrade SSLMate CT Search subscription.
  CERTSPOTTER_BATCH="${CERTSPOTTER_BATCH:-8}"            # roots per cycle (token)
  CERTSPOTTER_SLEEP="${CERTSPOTTER_SLEEP:-3}"
else
  CERTSPOTTER_BATCH="${CERTSPOTTER_BATCH:-5}"            # roots per cycle (free, no token)
  CERTSPOTTER_SLEEP="${CERTSPOTTER_SLEEP:-5}"
fi
CURSOR_FILE="$TF_DIR/certspotter_cursors.tsv"            # root<TAB>last_issuance_id
ROOT_IDX_FILE="$TF_DIR/.certspotter_root_idx"            # rotating offset into root list
CS_RATELIMIT_FILE="$TF_DIR/.certspotter_ratelimit_until" # epoch when global cooldown expires
PAYING_ROOTS_CACHE="$TF_DIR/.paying_roots_cache"         # built once per invocation, shared by all pollers

# crt.sh HTTP — bounded fallback only. Old code iterated ALL ~900 roots at 30s each,
# which could hang the whole loop for hours when crt.sh was unreachable. Now it
# polls a small rotating batch with a short timeout.
CRT_SH_INTERVAL="${CRT_SH_INTERVAL:-3600}"
CRT_SH_TIMEOUT="${CRT_SH_TIMEOUT:-15}"
CRT_SH_BATCH="${CRT_SH_BATCH:-40}"
CRT_SH_IDX_FILE="$TF_DIR/.crtsh_root_idx"

# crt.sh Postgres — bypasses Cloudflare entirely. Same data, no HTTP rate-limit.
# Requires: sudo apt install postgresql-client   (no API key, public read-only replica)
# host=crt.sh port=5432 user=guest db=certwatch  (no password needed)
CRT_SH_PG_INTERVAL="${CRT_SH_PG_INTERVAL:-1800}"        # 30-min cadence
CRT_SH_PG_TIMEOUT="${CRT_SH_PG_TIMEOUT:-10}"            # connect + statement timeout (s)
CRT_SH_PG_BATCH="${CRT_SH_PG_BATCH:-30}"                # roots per cycle
CRT_SH_PG_IDX_FILE="$TF_DIR/.crtsh_pg_root_idx"

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

# Reload scope periodically without restart.
# Builds into temp sets/lists first, then atomically swaps — avoids the brief
# window where exact and suffixes are both empty and incoming certs are silently
# dropped (no match possible during an in-progress clear+reload).
import threading
def reload_loop():
    while True:
        time.sleep(900)
        new_exact = set()
        new_suffixes = []
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
                        continue
                    if pat.startswith("*."):
                        suf = pat[1:]
                        apex = pat[2:]
                        new_suffixes.append((suf, apex))
                    else:
                        new_exact.add(pat)
        except Exception as e:
            sys.stderr.write("scope reload error: %s\n" % e)
            continue  # keep old lists on error
        exact.clear(); exact.update(new_exact)
        suffixes[:] = new_suffixes
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

# ---- 2. API pollers (Cert Spotter primary, crt.sh fallback) ----------------

# Paying roots (apex), de-duplicated, ordered by payout tier (elite first) so a
# bounded per-cycle batch always covers the highest-value programs soonest.
build_paying_roots() {
  awk -F'\t' '
    $4=="true" {
      pat=$1; sub(/^\*\./, "", pat)
      n=split(pat, p, "."); if (n < 2) next
      apex = p[n-1] "." p[n]
      rank = ($5=="elite"?0:$5=="high"?1:$5=="mid"?2:$5=="low"?3:4)
      if (!(apex in best) || rank < best[apex]) best[apex] = rank
    }
    END { for (a in best) printf "%d\t%s\n", best[a], a }
  ' "$INSCOPE_TSV" | sort -t"$(printf '\t')" -k1,1n -k2,2 | cut -f2 \
    | grep -E '^[a-z0-9][a-z0-9-]*(\.[a-z0-9][a-z0-9-]*)*\.[a-z]{2,}$'
  # ↑ Rejects junk from scope DB: prose descriptions, IP fragments (100.0, 127.0),
  # regex alternations (doctolib.(fr|de|it)), trailing tabs, and notes in parens.
}

cursor_lookup()  { awk -F'\t' -v r="$1" '$1==r{print $2; exit}' "$CURSOR_FILE" 2>/dev/null; }
cursor_update() {
  local root="$1" newid="$2" tmp
  [[ -z "$newid" ]] && return 0
  tmp="$(mktemp)"
  awk -F'\t' -v r="$root" -v id="$newid" '
    $1==r { print r"\t"id; found=1; next } { print }
    END { if (!found) print r"\t"id }
  ' "$CURSOR_FILE" > "$tmp" 2>/dev/null && mv "$tmp" "$CURSOR_FILE" || rm -f "$tmp"
}

# Batch cursor write — merges a temp file of "root<TAB>maxid" lines into CURSOR_FILE
# in a single awk pass instead of N per-root rewrites. At 2300+ paying roots the
# savings are meaningful (each cursor_update was an awk+mv over a growing TSV).
batch_cursor_update() {
  local updates_file="$1"
  [[ -s "$updates_file" ]] || return 0
  local tmp; tmp="$(mktemp)"
  awk -F'\t' '
    NR==FNR { new[$1]=$2; next }
    $1 in new { print $1"\t"new[$1]; delete new[$1]; next }
    { print }
    END { for (r in new) print r"\t"new[r] }
  ' "$updates_file" "$CURSOR_FILE" > "$tmp" 2>/dev/null && mv "$tmp" "$CURSOR_FILE" || rm -f "$tmp"
}

certspotter_due() {
  local last; last="$(cat "$TF_DIR/.last_certspotter" 2>/dev/null || echo 0)"
  (( $(date +%s) - last >= CERTSPOTTER_INTERVAL ))
}

# Fetch+emit a single Cert Spotter page for one root. Appends window-fresh
# hosts to HOLDING and echoes one TAB-separated line: "<maxid>\t<count>\t<added>"
# (maxid = max issuance id on the page, count = issuances returned, added =
# fresh hosts emitted). Runs in a $() subshell, so it returns state via stdout,
# not globals. Exit code: 0 ok, 2 rate-limited (429), 1 other error.
_certspotter_page() {
  local root="$1" after="$2" window_iso="$3"
  local url="${CERTSPOTTER_API}?domain=${root}&include_subdomains=true&expand=dns_names&expand=not_before"
  [[ -n "$after" ]] && url="${url}&after=${after}"
  local resp hdrs code
  resp="$(mktemp)"; hdrs="$(mktemp)"
  code="$(curl -sS -m "$CERTSPOTTER_TIMEOUT" -D "$hdrs" -o "$resp" -w '%{http_code}' \
          "${CS_AUTH[@]}" -A 'recon-pipeline true-fresh' "$url" 2>/dev/null || echo 000)"
  if [[ "$code" == "429" ]]; then
    # Honour Retry-After: record the epoch when the global cooldown expires so
    # poll_certspotter can skip entire cycles instead of hammering through the ban.
    local retry_after
    retry_after="$(grep -i '^Retry-After:' "$hdrs" 2>/dev/null | tr -d '\r' | awk '{print $2}')"
    if [[ "$retry_after" =~ ^[0-9]+$ ]]; then
      echo $(( $(date +%s) + retry_after + 30 )) > "$CS_RATELIMIT_FILE"  # +30s safety margin
    fi
    rm -f "$resp" "$hdrs"; return 2
  fi
  rm -f "$hdrs"
  if [[ "$code" != "200" ]] || ! jq -e 'type=="array"' "$resp" >/dev/null 2>&1; then
    rm -f "$resp"; return 1
  fi
  # Always window-filter: a lagging cursor must never emit a stale subdomain.
  # Root-domain filter (CRITICAL): certs are found because $root appears in their
  # SANs, but the SAN list also includes every OTHER domain on that cert. CDN and
  # multi-tenant certs routinely list 50-100+ unrelated companies. Without this
  # select, querying aiven.io returns certs shared with fastly.net, cloudfront.net,
  # etc. — all get emitted to holding.jsonl and fail scope filtering (observed:
  # 783 hosts emitted → 0 in-scope, true_fresh.jsonl stays empty).
  local hosts_tmp added=0
  hosts_tmp="$(mktemp)"
  jq -rc --arg now "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" --arg w "$window_iso" --arg root "$root" '
    .[] | select((.not_before // "") >= $w) | (.not_before // $now) as $nb |
    .dns_names[]? | ascii_downcase | sub("^\\*\\.";"") |
    select(length>0) |
    select(. == $root or endswith("." + $root)) |
    {host:., external_first_seen:$nb, src:"certspotter"}
  ' "$resp" 2>/dev/null > "$hosts_tmp"
  added="$(wc -l < "$hosts_tmp" | tr -d ' ')"
  [[ "$added" -gt 0 ]] && cat "$hosts_tmp" >> "$HOLDING_FILE"
  rm -f "$hosts_tmp"
  local count maxid
  count="$(jq 'length' "$resp" 2>/dev/null || echo 0)"
  maxid="$(jq -r '[.[].id // empty] | map(tonumber? // .) | max // empty' "$resp" 2>/dev/null)"
  rm -f "$resp"
  printf '%s\t%s\t%s\n' "$maxid" "$count" "$added"
  return 0
}

# Cert Spotter poller. Rotates a bounded batch of paying roots per cycle; per
# root, pages forward from the stored cursor up to MAX_PAGES (Cert Spotter is
# oldest-first, so paging converges the cursor toward the present). The
# not_before window filter is applied on every page, so emission is always
# correct regardless of cursor position. Stops cleanly on 429 and resumes at
# the same root next cycle so we never lose ground or hammer the API.
poll_certspotter() {
  command -v curl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1 || return 0

  # Global rate-limit cooldown: if the last 429 included a Retry-After header,
  # skip this entire cycle and wait for the server-specified window to expire.
  if [[ -f "$CS_RATELIMIT_FILE" ]]; then
    local limit_until now_epoch
    limit_until="$(cat "$CS_RATELIMIT_FILE" 2>/dev/null || echo 0)"
    now_epoch="$(date +%s)"
    if (( now_epoch < limit_until )); then
      log "certspotter rate-limit cooldown active — $(( limit_until - now_epoch ))s remaining, skipping cycle"
      return 0
    fi
    rm -f "$CS_RATELIMIT_FILE"  # cooldown expired, clear it
  fi

  touch "$CURSOR_FILE"
  local roots="$PAYING_ROOTS_CACHE"
  local total; total="$(wc -l < "$roots" | tr -d ' ')"
  [[ "$total" -eq 0 ]] && return 0

  local start; start="$(cat "$ROOT_IDX_FILE" 2>/dev/null || echo 0)"
  [[ "$start" =~ ^[0-9]+$ ]] || start=0
  (( start >= total )) && start=0

  local window_iso; window_iso="$(date -u -d "-${COOLDOWN_HOURS} hours" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo "1970-01-01T00:00:00Z")"
  CS_AUTH=(); [[ -n "$CERTSPOTTER_TOKEN" ]] && CS_AUTH=(-H "Authorization: Bearer $CERTSPOTTER_TOKEN")

  local added=0 polled=0 i idx root cursor page after rc ratelimited=0 next_idx
  local result maxid pcount padded _cursor_updates
  _cursor_updates="$(mktemp)"

  # Bootstrap cursor: the highest issuance ID we've already seen across all
  # domains. New domains (no stored cursor) start from here instead of the
  # beginning of cert history — avoids paging through millions of historical
  # certs for large domains like digitalocean.com, canva.com, blockchain.com
  # which triggers immediate 429s. We may miss certs issued before this point
  # for brand-new entries, but that's acceptable: we'll catch new issuances
  # going forward from the next poll.
  local bootstrap_cursor
  bootstrap_cursor="$(awk -F'\t' 'BEGIN{max=0} $2+0>max{max=$2+0} END{if(max>0)print max}' \
    "$CURSOR_FILE" 2>/dev/null || echo "")"

  for (( i=0; i<CERTSPOTTER_BATCH && i<total; i++ )); do
    idx=$(( (start + i) % total ))
    root="$(sed -n "$((idx+1))p" "$roots")"
    [[ -z "$root" ]] && continue
    cursor="$(cursor_lookup "$root")"
    # New domain: seed cursor near the current tip so we only fetch recent certs
    [[ -z "$cursor" && -n "$bootstrap_cursor" ]] && cursor="$bootstrap_cursor"
    after="$cursor"
    polled=$((polled + 1))
    for (( page=0; page<CERTSPOTTER_MAX_PAGES; page++ )); do
      result="$(_certspotter_page "$root" "$after" "$window_iso")"; rc=$?
      if [[ "$rc" == "2" ]]; then
        ratelimited=1
        warn "certspotter 429 at root '$root' (idx $idx) — skipping root, continuing batch"
        break   # break page loop only; outer root loop continues to next domain
      fi
      [[ "$rc" != "0" ]] && break
      maxid="$(printf '%s' "$result" | cut -f1)"
      pcount="$(printf '%s' "$result" | cut -f2)"
      padded="$(printf '%s' "$result" | cut -f3)"
      added=$(( added + ${padded:-0} ))
      if [[ -n "$maxid" ]]; then
        printf '%s\t%s\n' "$root" "$maxid" >> "$_cursor_updates"
        after="$maxid"
      fi
      # short page (<100) = reached the tip for this root
      [[ "${pcount:-0}" -lt 100 ]] && break
      sleep "$CERTSPOTTER_SLEEP"
    done
    sleep "$CERTSPOTTER_SLEEP"
  done

  # Single awk merge instead of N per-root TSV rewrites
  batch_cursor_update "$_cursor_updates"
  rm -f "$_cursor_updates"

  # Always advance past the full batch. Rate-limited roots are skipped (not retried
  # immediately) so a single 429 domain can't stall the entire rotation forever.
  next_idx=$(( (start + CERTSPOTTER_BATCH) % total ))
  echo "$next_idx" > "$ROOT_IDX_FILE"
  date +%s > "$TF_DIR/.last_certspotter"
  log "certspotter: polled $polled roots (idx $start→$next_idx/$total), +$added fresh host entries"
}

crt_sh_due() {
  local last; last="$(cat "$TF_DIR/.last_crt_sh" 2>/dev/null || echo 0)"
  (( $(date +%s) - last >= CRT_SH_INTERVAL ))
}

# crt.sh — bounded rotating fallback. Short timeout + small batch so an
# unreachable crt.sh can never hang the loop for more than a few seconds/root.
poll_crt_sh() {
  command -v jq >/dev/null 2>&1 && command -v curl >/dev/null 2>&1 || return 0
  local roots="$PAYING_ROOTS_CACHE"
  local total; total="$(wc -l < "$roots" | tr -d ' ')"
  [[ "$total" -eq 0 ]] && return 0

  local start; start="$(cat "$CRT_SH_IDX_FILE" 2>/dev/null || echo 0)"
  [[ "$start" =~ ^[0-9]+$ ]] || start=0
  (( start >= total )) && start=0

  local since; since="$(date -u -d "-${COOLDOWN_HOURS} hours" +%s 2>/dev/null || echo 0)"
  # Circuit breaker: crt.sh is frequently fully unreachable (Cloudflare). Rather
  # than burn CRT_SH_BATCH × timeout seconds confirming it's down, bail after a
  # run of consecutive failures and let certspotter carry freshness this cycle.
  local fail_streak=0 max_fails="${CRT_SH_MAX_FAILS:-4}"
  local added=0 i idx root resp polled=0 crt_tmp
  for (( i=0; i<CRT_SH_BATCH && i<total; i++ )); do
    idx=$(( (start + i) % total ))
    root="$(sed -n "$((idx+1))p" "$roots")"
    [[ -z "$root" ]] && continue
    resp="$(mktemp)"
    polled=$((polled + 1))
    if curl -fsS -m "$CRT_SH_TIMEOUT" --connect-timeout 8 -A 'Mozilla/5.0 recon-pipeline true-fresh' \
         "https://crt.sh/?q=%25.${root}&output=json" -o "$resp" 2>/dev/null; then
      fail_streak=0
      crt_tmp="$(mktemp)"
      # Emit JSON directly from jq with actual cert not_before as external_first_seen.
      # Previous code used $(date) (current time) — wrong: crt.sh entries should carry
      # the real issuance timestamp so triage freshness windows are accurate.
      jq -rc --argjson since "$since" '
        if type=="array" then
          .[] | select((.not_before // "") != "") |
          (.not_before | sub(" "; "T") + "Z" | sub("ZZ$"; "Z")) as $nb |
          ($nb | try fromdate catch 0) as $epoch |
          select($epoch >= $since) |
          (.name_value // "") | split("\n")[] | ascii_downcase |
          select(. != "") | sub("^\\*\\."; "") |
          {host:., external_first_seen:$nb, src:"crt.sh"}
        else empty end
      ' "$resp" 2>/dev/null | awk '!seen[$0]++' > "$crt_tmp"
      if [[ -s "$crt_tmp" ]]; then
        cat "$crt_tmp" >> "$HOLDING_FILE"
        added=$(( added + $(wc -l < "$crt_tmp" | tr -d ' ') ))
      fi
      rm -f "$crt_tmp"
    else
      fail_streak=$((fail_streak + 1))
      if (( fail_streak >= max_fails )); then
        rm -f "$resp"
        warn "crt.sh unreachable ($fail_streak consecutive fails) — circuit-break, certspotter carries this cycle"
        break
      fi
    fi
    rm -f "$resp"
  done
  # Advance only past the roots we actually polled (so a circuit-break doesn't
  # skip the unpolled tail of this batch).
  echo "$(( (start + polled) % total ))" > "$CRT_SH_IDX_FILE"
  date +%s > "$TF_DIR/.last_crt_sh"
  log "crt.sh: polled $polled/$CRT_SH_BATCH roots (idx $start/$total), +$added raw entries"
}

crt_sh_pg_due() {
  local last; last="$(cat "$TF_DIR/.last_crt_sh_pg" 2>/dev/null || echo 0)"
  (( $(date +%s) - last >= CRT_SH_PG_INTERVAL ))
}

# crt.sh Postgres poller — rotating batch, same pattern as the HTTP poller but
# using psql against crt.sh's public read-only replica. Bypasses Cloudflare and
# gives SQL-level timestamp filtering. Requires: sudo apt install postgresql-client
poll_crt_sh_pg() {
  command -v psql >/dev/null 2>&1 || return 0
  local roots="$PAYING_ROOTS_CACHE"
  local total; total="$(wc -l < "$roots" | tr -d ' ')"
  [[ "$total" -eq 0 ]] && return 0

  local start; start="$(cat "$CRT_SH_PG_IDX_FILE" 2>/dev/null || echo 0)"
  [[ "$start" =~ ^[0-9]+$ ]] || start=0
  (( start >= total )) && start=0

  local since_iso; since_iso="$(date -u -d "-${COOLDOWN_HOURS} hours" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo '1970-01-01T00:00:00Z')"
  local stmt_timeout=$(( CRT_SH_PG_TIMEOUT * 1000 ))
  local fail_streak=0 max_fails=3 added=0 polled=0 i idx root pg_tmp

  for (( i=0; i<CRT_SH_PG_BATCH && i<total; i++ )); do
    idx=$(( (start + i) % total ))
    root="$(sed -n "$((idx+1))p" "$roots")"
    [[ -z "$root" ]] && continue
    # Validate: build_paying_roots already enforces apex format, but be explicit
    [[ "$root" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] || continue
    polled=$((polled + 1))
    pg_tmp="$(mktemp)"
    # psql -w: never prompt for password. PGPASSWORD="" suppresses .pgpass lookup.
    # statement_timeout prevents slow plans from hanging the loop.
    # certificate_and_identities view: name_value + certificate (bytea).
    # not_before is computed via x509_notbefore(certificate); no separate column.
    if printf "SET statement_timeout = %d;\nSELECT DISTINCT LOWER(name_value),\n  to_char(x509_notbefore(certificate),'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')\nFROM certificate_and_identities\nWHERE (name_value ILIKE '%%.%s' OR LOWER(name_value) = '%s')\n  AND x509_notbefore(certificate) IS NOT NULL\n  AND x509_notbefore(certificate) > '%s'\n  AND name_value NOT ILIKE '%%*%%'\nLIMIT 500;\n" \
         "$stmt_timeout" "$root" "$root" "$since_iso" \
      | PGPASSWORD="" PGCONNECT_TIMEOUT="$CRT_SH_PG_TIMEOUT" \
        psql -h crt.sh -p 5432 -U guest -d certwatch -w -t -A -F'|' \
        > "$pg_tmp" 2>/dev/null && [[ -s "$pg_tmp" ]]; then
      fail_streak=0
      local new_count=0
      while IFS='|' read -r host nb; do
        host="${host// /}"
        [[ -z "$host" || ! "$host" =~ \. ]] && continue
        printf '{"host":"%s","external_first_seen":"%s","src":"crt.sh-pg"}\n' \
          "$host" "${nb:-$since_iso}" >> "$HOLDING_FILE"
        new_count=$((new_count + 1))
      done < "$pg_tmp"
      added=$((added + new_count))
    else
      fail_streak=$((fail_streak + 1))
      if (( fail_streak >= max_fails )); then
        rm -f "$pg_tmp"
        warn "crt.sh Postgres unreachable ($fail_streak consecutive fails) — circuit-break"
        break
      fi
    fi
    rm -f "$pg_tmp"
  done

  echo "$(( (start + polled) % total ))" > "$CRT_SH_PG_IDX_FILE"
  date +%s > "$TF_DIR/.last_crt_sh_pg"
  log "crt.sh-pg: polled $polled/$CRT_SH_PG_BATCH roots (idx $start/$total), +$added raw entries"
}

# Build paying roots once — shared by certspotter, crt.sh HTTP, and crt.sh Postgres
build_paying_roots > "$PAYING_ROOTS_CACHE"

if certspotter_due; then
  poll_certspotter || warn "certspotter poll had errors (continuing)"
fi
if crt_sh_due; then
  poll_crt_sh || warn "crt.sh poll had errors (continuing)"
fi
if crt_sh_pg_due; then
  poll_crt_sh_pg || warn "crt.sh-pg poll had errors (continuing)"
fi

rm -f "$PAYING_ROOTS_CACHE"

# ---- 3. Flush phase --------------------------------------------------------
# Holding entries may include non-scope entries (e.g. crt.sh raw). Scope-filter
# them through recon_scope_check.sh in batch mode, drop duplicates against the
# 24h seen file, write to the durable jsonl + queue batches.

if [[ ! -s "$HOLDING_FILE" ]]; then
  log "Nothing to flush this cycle"
  exit 0
fi

WORK="$(mktemp)"
trap 'rm -f "$WORK" "$WORK.scoped" "$WORK.scoped_s" "$WORK.fresh" "$WORK.candidates" "$WORK.seen"' EXIT

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
# sort+comm is O(n log n) vs grep -Fxv O(n*m) — matters at large scope/seen sizes
sort "$WORK.scoped" > "$WORK.scoped_s"
comm -23 "$WORK.scoped_s" "$WORK.seen" > "$WORK.fresh" 2>/dev/null || cp "$WORK.scoped" "$WORK.fresh"
rm -f "$WORK.seen" "$WORK.scoped_s"

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

# Health signal: daemon/monitors can check this to detect a starved feed
[[ "$i" -gt 0 ]] && date +%s > "$TF_DIR/.last_emission_epoch"
log "Flush done — $fresh_n hosts queued in $i batch(es)"

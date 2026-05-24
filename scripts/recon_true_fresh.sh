#!/usr/bin/env bash
# =============================================================================
# recon_true_fresh.sh — True-freshness engine (v2.8 — gungnir)
#
# DESIGN
#   - gungnir listener (background Go binary, single-instance via pidfile)
#     connects DIRECTLY to ~30+ certificate-transparency logs (Google, Cloudflare,
#     Sectigo, Let's Encrypt, DigiCert + static/tiled logs) and streams newly
#     issued certs in real time. We run it with `-r <paying-roots> -f` so it only
#     emits hosts under our paying scope and auto-reloads when scope changes.
#     Its stdout is piped into a tiny flock-append reader (zero network I/O, so it
#     can never enter WSL2 D-state) that wraps each host as a holding-file record.
#   - certspotter poller (BACKFILL only, low-frequency): gungnir is forward-only
#     (it catches certs issued AFTER it starts watching a root), so certspotter
#     fills two gaps — historical certs for newly-added roots, and any issuances
#     missed during a gungnir outage. Bounded batch, cursor-based, multi-key.
#   - Flush phase: dedupes against a 24h cooldown file, writes to
#     ~/recon/state/true_fresh.jsonl (the durable feed), splits into
#     500-line batches named 00_truefresh_<iso_ts>_<batch>.txt under
#     ~/recon/queue/inbox/ for the fast validator lane.
#
# WHY gungnir REPLACED certstream + crt.sh (v2.8)
#   certstream.calidog.io was chronically degraded (its Python client wedged in
#   D-state for 24h); crt.sh is Cloudflare-rate-limited to uselessness. Both hit
#   single aggregator chokepoints over curl/python sockets that block
#   uninterruptibly on half-open Mullvad WireGuard connections. gungnir talks to
#   the CT logs directly with Go's epoll-based netpoller + ctx-aware backoff, so a
#   stalled log never blocks the others and the process always stays killable.
#
# EGRESS
#   Runs as d0k (not reconrun) — passive CT log feeds, no target-facing traffic.
#   gungnir CT-log fetches and certspotter GETs egress via Mullvad like everything else.
#
# CLEANUP
#   - Holding file truncated on every flush.
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
GUNGNIR_PIDFILE="$TF_DIR/gungnir.pid"
LISTENER_LOG="$BASE_DIR/logs/true_fresh_listener.log"
LOCK_FILE="$STATE_DIR/true_fresh.lock"

BATCH_SIZE="${TRUE_FRESH_BATCH_SIZE:-500}"
COOLDOWN_HOURS="${TRUE_FRESH_COOLDOWN_HOURS:-24}"
MAX_PER_FLUSH="${TRUE_FRESH_MAX_PER_FLUSH:-5000}"

# === gungnir CT-log streamer (primary, v2.8) ================================
# gungnir watches PAYING_ROOTS with -f and live-reloads on change; certspotter
# reads the same file. It is refreshed (cmp-guarded) every invocation so adding a
# paying program propagates to the live stream without a restart.
GUNGNIR_BIN="${GUNGNIR_BIN:-$HOME/go/bin/gungnir}"
PAYING_ROOTS="$TF_DIR/paying_roots.txt"   # stable paying-apex list (gungnir -r + certspotter)

# === certspotter backfill (secondary, low-frequency) =======================
# gungnir is forward-only (it sees certs issued AFTER it starts watching a root),
# so certspotter backfills two gaps: historical certs for newly-added roots, and
# issuances missed during a gungnir outage. Bounded + cursor-based so it never
# hammers the API. Set CERTSPOTTER_BACKFILL=0 to disable entirely.
CERTSPOTTER_BACKFILL="${CERTSPOTTER_BACKFILL:-1}"
CERTSPOTTER_API="${CERTSPOTTER_API:-https://api.certspotter.com/v1/issuances}"
# Tokens from ~/.recon_certspotter_token (one per line). Multiple rotate round-robin.
CERTSPOTTER_TOKENS=()
if [[ -f "$HOME/.recon_certspotter_token" ]]; then
  while IFS= read -r _tok; do
    _tok="${_tok//[[:space:]]/}"
    [[ -n "$_tok" ]] && CERTSPOTTER_TOKENS+=("$_tok")
  done < "$HOME/.recon_certspotter_token"
fi
CERTSPOTTER_NUM_TOKENS="${#CERTSPOTTER_TOKENS[@]}"
# Backfill cadence: hourly by default. gungnir carries real-time freshness, so
# this is only a safety net — no need to poll aggressively.
CERTSPOTTER_INTERVAL="${CERTSPOTTER_INTERVAL:-3600}"
CERTSPOTTER_TIMEOUT="${CERTSPOTTER_TIMEOUT:-25}"
# Oldest-first pagination at 100/page; follow up to MAX_PAGES/root/cycle. The
# not_before window filter is applied on EVERY page, so a lagging cursor can never
# emit a stale subdomain — correctness is independent of cursor position.
CERTSPOTTER_MAX_PAGES="${CERTSPOTTER_MAX_PAGES:-3}"
if [[ "$CERTSPOTTER_NUM_TOKENS" -gt 0 ]]; then
  CERTSPOTTER_BATCH="${CERTSPOTTER_BATCH:-$(( 8 * CERTSPOTTER_NUM_TOKENS ))}"
  CERTSPOTTER_SLEEP="${CERTSPOTTER_SLEEP:-3}"
else
  CERTSPOTTER_BATCH="${CERTSPOTTER_BATCH:-5}"            # no-token fallback
  CERTSPOTTER_SLEEP="${CERTSPOTTER_SLEEP:-5}"
fi
CURSOR_FILE="$TF_DIR/certspotter_cursors.tsv"            # root<TAB>last_issuance_id
ROOT_IDX_FILE="$TF_DIR/.certspotter_root_idx"            # rotating offset into root list
CS_KEY_IDX_FILE="$TF_DIR/.certspotter_key_idx"           # which token to use next (multi-key)
# Per-key ratelimit: $TF_DIR/.certspotter_ratelimit_<idx> or _global for no-token path
CS_RATELIMIT_FILE="$TF_DIR/.certspotter_ratelimit_global"

mkdir -p "$TF_DIR" "$QUEUE_INBOX" "$BASE_DIR/logs"
touch "$HOLDING_FILE" "$SEEN_FILE" "$PERSIST_JSONL"

# The true_fresh feed is consumed by triage.sh, which runs as the SCANNER user
# (reconrun) via sudo. mktemp creates 0600 files and `mv` does NOT inherit the
# state dir's default ACL — so the 7d-prune rewrite below silently strips
# reconrun's read access. When that happens triage's `jq ... || echo '{}'` map
# build reads nothing, the true_fresh map is empty, and EVERY host is scored
# triage_true_fresh=false — which kills DAST fresh-first prioritisation AND the
# Discord true-fresh alert gate. Re-grant reconrun read after every feed write.
TF_SCANNER_USER="${SCANNER_USER:-reconrun}"
grant_feed_read() {
  setfacl -m "u:${TF_SCANNER_USER}:r" "$PERSIST_JSONL" 2>/dev/null \
    || chmod 0644 "$PERSIST_JSONL" 2>/dev/null || true
}
grant_feed_read

exec 9>"$LOCK_FILE"
flock -n 9 || { warn "true_fresh already running"; exit 0; }
# FD_CLOEXEC on the lock fd: any exec'd child (python3, jq, curl, awk) will
# NOT inherit fd 9. This prevents D-state network processes from holding the
# flock and blocking the daemon's true-fresh loop indefinitely.
python3 -c "import fcntl; fcntl.fcntl(9, fcntl.F_SETFD, fcntl.FD_CLOEXEC)" 2>/dev/null || true

# ---- Scope DB presence check (otherwise nothing matches) -------------------
INSCOPE_TSV="$SCOPE_DIR/inscope_patterns.tsv"
if [[ ! -s "$INSCOPE_TSV" ]]; then
  warn "scope DB not populated ($INSCOPE_TSV missing); skipping cycle"
  exit 0
fi

# ---- 1. gungnir CT-log listener (function definitions; invoked in footer) --
# A single long-lived gungnir process per host, tracked by pidfile. Launched in
# its own session (setsid) so the daemon can terminate the whole pipeline
# (gungnir + reader) with one process-group kill on shutdown.
gungnir_alive() {
  [[ -s "$GUNGNIR_PIDFILE" ]] || return 1
  local pid; pid="$(cat "$GUNGNIR_PIDFILE" 2>/dev/null)"
  [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null
}

# Rebuild the paying-roots file only when its content actually changes, so
# gungnir's -f watcher doesn't needlessly restart its scan (which re-fetches each
# log's STH and loses ~20 entries of position) on every cycle.
refresh_paying_roots() {
  local tmp; tmp="$(mktemp)"
  build_paying_roots > "$tmp" 2>/dev/null
  if [[ ! -s "$tmp" ]]; then
    rm -f "$tmp"; return 1
  fi
  if [[ ! -f "$PAYING_ROOTS" ]] || ! cmp -s "$tmp" "$PAYING_ROOTS"; then
    mv "$tmp" "$PAYING_ROOTS"
    log "paying roots refreshed ($(wc -l < "$PAYING_ROOTS" | tr -d ' ') apexes)"
  else
    rm -f "$tmp"
  fi
  return 0
}

# Reader: wraps each hostname gungnir prints into a holding-file record. It does
# NO network I/O (only reads a pipe and appends a local file under flock), so
# unlike curl/python-requests it can never enter WSL2 D-state.
GUNGNIR_READER='
import sys, json, time, fcntl
hf = sys.argv[1]
for line in iter(sys.stdin.readline, ""):
    h = line.strip().lower().rstrip(".")
    if not h:
        continue
    if h.startswith("*."):
        h = h[2:]
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    rec = json.dumps({"host": h, "external_first_seen": ts, "src": "gungnir"}, separators=(",", ":")) + "\n"
    try:
        with open(hf, "a", encoding="utf-8") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.write(rec)
            fcntl.flock(f, fcntl.LOCK_UN)
    except Exception as e:
        sys.stderr.write("reader emit failed: %s\n" % e); sys.stderr.flush()
'

start_gungnir() {
  if [[ ! -x "$GUNGNIR_BIN" ]]; then
    warn "gungnir not found/executable at $GUNGNIR_BIN — install with:"
    warn "  go install github.com/g0ldencybersec/gungnir/cmd/gungnir@latest"
    return 1
  fi
  if [[ ! -s "$PAYING_ROOTS" ]]; then
    warn "paying roots file empty — not starting gungnir this cycle"
    return 1
  fi
  log "Starting gungnir listener ($GUNGNIR_BIN -r $PAYING_ROOTS -f)"
  # setsid: own session/process group so the daemon can kill gungnir + reader
  # together with one group kill. 9>&-: close the script lock fd in the child so
  # the long-lived listener never inherits/holds the flock (the bug that silently
  # disabled the loop for 18h with the old certstream child).
  setsid bash -c "exec '$GUNGNIR_BIN' -r '$PAYING_ROOTS' -f 2>>'$LISTENER_LOG' | exec python3 -u -c '$GUNGNIR_READER' '$HOLDING_FILE'" 9>&- >>"$LISTENER_LOG" 2>&1 &
  local gpid=$!
  echo "$gpid" > "$GUNGNIR_PIDFILE"
  log "gungnir listener started (pgid $gpid)"
}

# ---- 2. API pollers (Cert Spotter primary, crt.sh fallback) ----------------

# Paying roots (apex), de-duplicated, ordered by payout tier (elite first) so a
# bounded per-cycle batch always covers the highest-value programs soonest.
build_paying_roots() {
  # Stage 1 (awk): emit rank<TAB>cleaned-host for every paying pattern. The host
  # is the pattern with its leading *. stripped, lightly sanity-checked.
  # Stage 2 (python/publicsuffixlist): collapse each host to its REGISTRABLE
  # domain (eTLD+1) using the Public Suffix List. This is critical: naive
  # last-two-labels turns *.foo.com.br into "com.br" (a public suffix), which
  # makes gungnir match the ENTIRE suffix and floods holding with out-of-scope
  # hosts. privatesuffix() returns None for bare public suffixes, dropping them.
  # No network — publicsuffixlist ships an offline PSL snapshot, so this can
  # never hang. Dedups by apex keeping the best (lowest) payout rank.
  # NOTE: python3 -c (not `python3 - <<HEREDOC`) so the awk output stays on
  # Python's stdin — a heredoc would replace stdin with the program text.
  awk -F'\t' '
    $4=="true" {
      pat=$1; sub(/^\*\./, "", pat)
      if (pat !~ /^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$/) next
      rank = ($5=="elite"?0:$5=="high"?1:$5=="mid"?2:$5=="low"?3:4)
      print rank "\t" pat
    }
  ' "$INSCOPE_TSV" | python3 -c '
import sys
# Shared cloud/CDN/PaaS infra apexes. CT-watching these yields only other
# tenants every AWS/Azure/CDN customer issues certs under them, so they flood
# holding with thousands of out-of-scope hosts (vpce.amazonaws.com etc.) and
# can push genuinely-fresh in-scope hosts past the flush MAX_PER_FLUSH cap. A
# program that scopes its OWN cloud assets is reached via its own apex, not these.
DENY = {
    "amazonaws.com","amazonaws.com.cn","awsapps.com","awsglobalaccelerator.com",
    "elasticbeanstalk.com","cloudfront.net","azurewebsites.net","azure-api.net",
    "azureedge.net","azurefd.net","azurecontainer.io","cloudapp.net","cloudapp.azure.com",
    "trafficmanager.net","windows.net","appspot.com","run.app","web.app",
    "firebaseapp.com","firebaseio.com","cloudfunctions.net","googleusercontent.com",
    "herokuapp.com","herokudns.com","herokussl.com","netlify.app","vercel.app",
    "now.sh","workers.dev","pages.dev","cloudflare.net","cloudflareworkers.com",
    "fastly.net","fastlylb.net","akamai.net","akamaiedge.net","akamaihd.net",
    "edgekey.net","edgesuite.net","llnwd.net","digitaloceanspaces.com",
    "nflxvideo.net","nflxext.com","nflximg.net","github.io","githubusercontent.com",
    # Multi-tenant SaaS NOT in the PSL private section, so they collapse to the
    # shared apex and flood with other customers tenant portals (e.g. 160
    # <customer>.zendesk.com in 500). A program scoping its OWN tenant is still
    # reached via that program apex elsewhere in scope; the bare SaaS apex is noise.
    "zendesk.com","auth0app.com","myshopify.com","freshdesk.com","desk.com",
    "statuspage.io","pantheonsite.io","wpengine.com","wixsite.com","zohohost.com",
}
try:
    from publicsuffixlist import PublicSuffixList
    psl = PublicSuffixList()
    def apex(h): return psl.privatesuffix(h)
except Exception:
    def apex(h):
        labs = h.split(".")
        return ".".join(labs[-2:]) if len(labs) >= 2 else None
best = {}
for line in sys.stdin:
    parts = line.rstrip("\n").split("\t")
    if len(parts) < 2:
        continue
    try:
        rank = int(parts[0])
    except ValueError:
        rank = 4
    a = apex(parts[1].lower().strip("."))
    if not a or a in DENY or any(a.endswith("." + d) for d in DENY):
        continue
    if a not in best or rank < best[a]:
        best[a] = rank
for a, r in best.items():
    print("%d\t%s" % (r, a))
' | sort -t"$(printf '\t')" -k1,1n -k2,2 | cut -f2 \
    | grep -E '^[a-z0-9][a-z0-9-]*(\.[a-z0-9][a-z0-9-]*)*\.[a-z]{2,}$'
  # Final grep also rejects residual junk: prose, IP fragments, regex alternations.
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
  local root="$1" after="$2" window_iso="$3" token="${4:-}" key_idx="${5:-global}"
  local url="${CERTSPOTTER_API}?domain=${root}&include_subdomains=true&expand=dns_names&expand=not_before"
  [[ -n "$after" ]] && url="${url}&after=${after}"
  local resp code rl_file="$TF_DIR/.certspotter_ratelimit_${key_idx}"
  resp="$(mktemp)"
  # Use Python requests instead of curl: requests uses select()-based non-blocking
  # I/O which remains interruptible even in WSL2, unlike curl which can enter
  # kernel D-state (uninterruptible sleep) on half-open Mullvad WireGuard connections
  # — making curl immune to SIGKILL and permanently blocking the pipeline.
  code="$(python3 - "$url" "$token" "$resp" "$CERTSPOTTER_TIMEOUT" <<'PYEOF' 2>/dev/null
import sys, json
try:
    import requests as req
except ImportError:
    print("000"); sys.exit(0)
url, token, outfile, tmo = sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4])
hdrs = {"User-Agent": "recon-pipeline true-fresh"}
if token: hdrs["Authorization"] = "Bearer " + token
try:
    r = req.get(url, headers=hdrs, timeout=(10, tmo))
    with open(outfile, "wb") as f: f.write(r.content)
    print(r.status_code)
    ra = r.headers.get("Retry-After", "")
    if ra: print("retry-after:" + str(ra))
except Exception: print("000")
PYEOF
  )"
  local http_code retry_after
  http_code="$(printf '%s' "$code" | head -1)"
  retry_after="$(printf '%s' "$code" | grep '^retry-after:' | cut -d: -f2 | tr -d ' ')"
  if [[ "$http_code" == "429" ]]; then
    # Honour Retry-After: write per-key cooldown file so poll_certspotter skips
    # this key and tries the next one instead of stalling the whole batch.
    echo $(( $(date +%s) + ${retry_after:-330} + 30 )) > "$rl_file"
    rm -f "$resp"; return 2
  fi
  if [[ "$http_code" != "200" ]] || ! jq -e 'type=="array"' "$resp" >/dev/null 2>&1; then
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
  command -v jq >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1 || return 0

  # No-token path: check global cooldown file before doing any work.
  if [[ "$CERTSPOTTER_NUM_TOKENS" -eq 0 && -f "$CS_RATELIMIT_FILE" ]]; then
    local limit_until now_epoch
    limit_until="$(cat "$CS_RATELIMIT_FILE" 2>/dev/null || echo 0)"
    now_epoch="$(date +%s)"
    if (( now_epoch < limit_until )); then
      log "certspotter rate-limit cooldown active — $(( limit_until - now_epoch ))s remaining, skipping cycle"
      return 0
    fi
    rm -f "$CS_RATELIMIT_FILE"
  fi

  touch "$CURSOR_FILE"
  local roots="$PAYING_ROOTS"
  local total; total="$(wc -l < "$roots" | tr -d ' ')"
  [[ "$total" -eq 0 ]] && return 0

  local start; start="$(cat "$ROOT_IDX_FILE" 2>/dev/null || echo 0)"
  [[ "$start" =~ ^[0-9]+$ ]] || start=0
  (( start >= total )) && start=0

  local window_iso; window_iso="$(date -u -d "-${COOLDOWN_HOURS} hours" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo "1970-01-01T00:00:00Z")"

  # Multi-key: load rotation state. cur_key rotates round-robin; on 429, the key's
  # ratelimit file is written by _certspotter_page and _pick_key skips it next time.
  local cur_key=0
  if [[ "$CERTSPOTTER_NUM_TOKENS" -gt 1 ]]; then
    cur_key="$(cat "$CS_KEY_IDX_FILE" 2>/dev/null || echo 0)"
    [[ "$cur_key" =~ ^[0-9]+$ ]] || cur_key=0
    (( cur_key >= CERTSPOTTER_NUM_TOKENS )) && cur_key=0
  fi

  # Sets cur_key to the next non-rate-limited key index. Returns 1 if all keys
  # are currently rate-limited (caller should bail early).
  _pick_key() {
    [[ "$CERTSPOTTER_NUM_TOKENS" -eq 0 ]] && return 0   # no-token: always ok
    local now; now=$(date +%s)
    local k ki rl until
    for (( k=0; k<CERTSPOTTER_NUM_TOKENS; k++ )); do
      ki=$(( (cur_key + k) % CERTSPOTTER_NUM_TOKENS ))
      rl="$TF_DIR/.certspotter_ratelimit_${ki}"
      if [[ -f "$rl" ]]; then
        until="$(cat "$rl" 2>/dev/null || echo 0)"
        (( now < until )) && continue
        rm -f "$rl"
      fi
      cur_key=$ki
      return 0
    done
    return 1  # all keys rate-limited
  }

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

    # Pick the next available (non-rate-limited) key before polling this root.
    # If all keys are exhausted, end the batch early rather than requesting unauthenticated.
    local sel_key="global" tok=""
    if [[ "$CERTSPOTTER_NUM_TOKENS" -gt 0 ]]; then
      if ! _pick_key; then
        warn "certspotter: all $CERTSPOTTER_NUM_TOKENS keys rate-limited — ending batch early"
        ratelimited=1; break
      fi
      sel_key="$cur_key"
      tok="${CERTSPOTTER_TOKENS[$cur_key]}"
      cur_key=$(( (cur_key + 1) % CERTSPOTTER_NUM_TOKENS ))  # advance for next root
    fi

    cursor="$(cursor_lookup "$root")"
    # New domain: seed cursor near the current tip so we only fetch recent certs
    [[ -z "$cursor" && -n "$bootstrap_cursor" ]] && cursor="$bootstrap_cursor"
    after="$cursor"
    polled=$((polled + 1))
    for (( page=0; page<CERTSPOTTER_MAX_PAGES; page++ )); do
      result="$(_certspotter_page "$root" "$after" "$window_iso" "$tok" "$sel_key")"; rc=$?
      if [[ "$rc" == "2" ]]; then
        ratelimited=1
        warn "certspotter 429 at root '$root' (idx $idx, key $sel_key) — skipping root, continuing batch"
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
  # Persist key rotation position so the next cycle continues round-robin.
  [[ "$CERTSPOTTER_NUM_TOKENS" -gt 1 ]] && echo "$cur_key" > "$CS_KEY_IDX_FILE"
  date +%s > "$TF_DIR/.last_certspotter"
  local key_msg=""
  [[ "$CERTSPOTTER_NUM_TOKENS" -gt 1 ]] && key_msg=" (${CERTSPOTTER_NUM_TOKENS} keys rotating)"
  log "certspotter: polled $polled roots (idx $start→$next_idx/$total), +$added fresh host entries${key_msg}"
}

# ---- Orchestration: refresh roots, ensure gungnir, run certspotter backfill --
# Refresh the paying-roots file (cmp-guarded). gungnir watches it via -f and
# certspotter reads it, so both stay in sync with the live scope DB.
refresh_paying_roots || warn "paying roots refresh failed (using previous list)"

# Ensure the gungnir real-time listener is running (primary freshness source).
if ! gungnir_alive; then
  start_gungnir || true
fi

# certspotter backfill (secondary). Forward-only gungnir misses historical certs
# for newly-added roots and any outage gap; this fills them in, bounded + hourly.
if [[ "$CERTSPOTTER_BACKFILL" == "1" ]] && certspotter_due; then
  poll_certspotter || warn "certspotter backfill had errors (continuing)"
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
grant_feed_read   # mktemp+mv just stripped reconrun's read access — restore it

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

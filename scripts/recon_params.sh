#!/usr/bin/env bash
# =============================================================================
# recon_params.sh — sus_params targeting catalog (g0ldencybersec gf-patterns)
#
# A queryable inventory of IN-SCOPE-PAYING URLs-with-parameters, classified by
# vuln class, so you can pull "all in-scope SQLi targets" / "all XSS targets" on
# demand — for manual hunting or feeding sqlmap/dalfox/nuclei.
#
#   enqueue        PRODUCER (ES-only, no target traffic): score+cooldown-aware
#                  candidate selection → small JOB FILES in the shared directory
#                  queue (queue/params/inbox). Backpressure at PARAMS_INBOX_CAP.
#   crawl          CONSUMER (target-facing → reconrun/Mullvad, egress-gated):
#                  atomically claim ONE job, crawl its hosts (katana+gau),
#                  gf-classify, index THIS job to recon_params immediately,
#                  7d per-host cooldown, move job→done. One job/cycle = bounded,
#                  honest egress + incremental feed. Crashed jobs auto-requeue.
#   list <class> [N]   print in-scope param-URLs for a class, fresh-first,
#                  tagged with program / tier / (FRESH). Read-only.
#   verify <xss|sqli> [N]   actively probe top N catalog URLs for the class:
#                  xss  → inject d0k_recon canary, check if it reflects in body
#                  sqli → inject ' payload, check response for DB error strings
#                  Confirmed hits printed live + appended to params/verify_<class>.jsonl
#
# Classes: sqli xss ssrf lfi ssti cmdi debug rce redirect idor img-traversal
# =============================================================================
set -uo pipefail
IFS=$'\n\t'

log()  { printf '[%s PARAMS] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s PARAMS WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCOPE_CHECK="${SCOPE_CHECK:-$SCRIPT_DIR/recon_scope_check.sh}"
BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
PARAMS_DIR="$BASE_DIR/params"
LOCK_FILE="$STATE_DIR/params.lock"

# Shared directory queue (same inbox→processing→done pattern as recon_validate.sh,
# in its OWN namespace so it never collides with the httpx-consumer queue). The
# PRODUCER (enqueue) drops job files into inbox; the CONSUMER (crawl) atomically
# claims one via mv→processing, then archives it to done.
PARAMS_QUEUE_DIR="${PARAMS_QUEUE_DIR:-$BASE_DIR/queue/params}"
PARAMS_INBOX="$PARAMS_QUEUE_DIR/inbox"
PARAMS_PROCESSING="$PARAMS_QUEUE_DIR/processing"
PARAMS_DONE="$PARAMS_QUEUE_DIR/done"

ES_URL="${ES_URL:-http://127.0.0.1:9200}"
source "$SCRIPT_DIR/recon_net.sh"
setup_es_netrc
INDEX_NAME="${INDEX_NAME:-recon_alive}"
PARAMS_INDEX="${PARAMS_INDEX:-recon_params}"

GOBIN="$HOME/go/bin"
KATANA="${KATANA:-$GOBIN/katana}"; GAU="${GAU:-$GOBIN/gau}"
WAYMORE="${WAYMORE:-$HOME/.local/bin/waymore}"   # richer multi-archive source beside gau (otx/urlscan/ghostarchive + vt/intelx if keyed)
WAYMORE_TIMEOUT="${WAYMORE_TIMEOUT:-60}"
GF="${GF:-$(command -v gf 2>/dev/null || echo "$GOBIN/gf")}"; QSREPLACE="${QSREPLACE:-$GOBIN/qsreplace}"
# arjun — ACTIVE hidden-param discovery (sends LIVE traffic → ON-DEMAND ONLY, never the daemon
# crawl; gated by PARAMS_ARJUN=1, set by `crawl-host --arjun` / `arjun`). Polite by default.
ARJUN="${ARJUN:-$(command -v arjun 2>/dev/null)}"
ARJUN_WORDLIST="${ARJUN_WORDLIST:-/usr/lib/python3/dist-packages/arjun/db/medium.txt}"
ARJUN_DELAY="${ARJUN_DELAY:-2}"        # seconds between requests (forces single-thread)
ARJUN_RATELIMIT="${ARJUN_RATELIMIT:-3}" # hard ceiling req/s (anti-burn backstop)
ARJUN_TIMEOUT="${ARJUN_TIMEOUT:-20}"

# Classify against EVERY gf pattern installed in ~/.gf — not a fixed list — so
# adding a new pattern automatically extends the catalog. Override with PARAMS_CLASSES.
# Exact sus_params class set (g0ldencybersec/sus_params).
# Hardcoded — not auto-detected from ~/.gf — so collect always uses the same
# classes regardless of which user runs it and what extra patterns d0k may have.
# These are the only patterns installed in reconrun's home (/home/reconrun/.gf).
if [[ -z "${PARAMS_CLASSES:-}" ]]; then
  # sus_params core 9 (g0ldencybersec): sqli xss ssrf lfi ssti cmdi debug redirect idor
  # + rce and img-traversal from community Gf-Patterns (installed in reconrun home)
  PARAMS_CLASSES=$'sqli\nxss\nssrf\nlfi\nssti\ncmdi\ndebug\nrce\nredirect\nidor\nimg-traversal'
fi
# JOBS-AND-QUEUES throughput model (matches recon_validate.sh): the PRODUCER enqueues
# small fixed-size jobs; the CONSUMER processes ONE job per cycle under the daemon's
# global egress governor. This keeps the egress footprint BOUNDED + HONEST (the old
# model held one egress slot but fanned out PARAM_PARALLEL-wide for a whole multi-hour
# run, so the 6-slot governor under-counted it ~5x — the exact self-inflicted-ban risk)
# and feeds downstream INCREMENTALLY (index per job, not once at end-of-run).
PARAMS_JOB_SIZE="${PARAMS_JOB_SIZE:-50}"          # hosts per queued job file
PARAMS_INBOX_CAP="${PARAMS_INBOX_CAP:-40}"        # producer backpressure: stop enqueuing at this many pending jobs (~2000 hosts buffered)
PARAMS_JOB_TTL="${PARAMS_JOB_TTL:-1800}"          # a claimed job idle > this (crashed consumer) → requeued to inbox
PARAMS_JOB_MAX_RETRY="${PARAMS_JOB_MAX_RETRY:-3}" # drop a job after this many requeues
PARAMS_DONE_KEEP="${PARAMS_DONE_KEEP:-200}"       # done-archive cap (most-recent kept)
PARAM_PARALLEL="${PARAM_PARALLEL:-5}"           # balanced safe-max: concurrent per-host crawls WITHIN a job (each per-host rate-limited) — politeness throttle, keep it
# SLIDING-WINDOW cooldown (24/7, never idle, never re-hammer): the producer query
# EXCLUDES hosts crawled within PARAMS_COOLDOWN_DAYS *server-side* (recon_alive
# params_scanned_at), so it always returns the highest-value NOT-recently-crawled
# hosts and reaches deeper into the ~600k pool automatically — the catalog can
# never go "no candidates" idle while uncrawled hosts remain. Cooldown is a
# ROTATION interval (re-check each host at most this often), NOT an idle cause;
# at safe crawl rates a full pass takes far longer than the window anyway.
PARAMS_COOLDOWN_DAYS="${PARAMS_COOLDOWN_DAYS:-7}"
# Product-class fan-out suppression: a root_domain we've already crawled >= MIN_SAMPLE
# hosts from but that yielded < MAX_YIELD params/host is a PROVEN zero-yield per-user/
# per-tenant fan-out (quora "spaces", artstation portfolios, statuspage tenants,
# elastic.dev CI — 938 hosts crawled, 0 params). Its remaining tens-of-thousands of hosts
# would grind 3/cycle forever, displacing real targets. Data-driven + self-maintaining:
# only suppresses AFTER a real sample proves the class dead (operator doctrine 2026-06-14:
# "check one, the rest of the class applies"); a root with any yield (tumblr/shopify/etsy/
# amazon) is never touched, and a fresh root must accrue MIN_SAMPLE crawls before judgement.
PARAMS_DEADROOT_MIN_SAMPLE="${PARAMS_DEADROOT_MIN_SAMPLE:-20}"
PARAMS_DEADROOT_MAX_YIELD="${PARAMS_DEADROOT_MAX_YIELD:-0.05}"   # params per crawled host
# CRITICAL GATE: only suppress MASS per-user/per-tenant fan-outs (quora 31k spaces,
# artstation 27k portfolios, elastic.dev 15k CI). Low ARCHIVE-param yield != no attack
# surface — a real program (paypal/tesla/hilton) can have hundreds of subdomains with no
# historical wayback param-URLs yet still be worth the param lane. Fan-out size is the
# discriminator: a root needs >= MIN_FANOUT eligible hosts before zero-yield => "dead". This
# spares corporate programs and limits blast radius if the yield data was skewed (e.g. by a
# transient archive outage). The param catalog is THIS lane only — suppression here never
# removes a host from jsintel/IDOR/takeover/nuclei, which query recon_alive independently.
PARAMS_DEADROOT_MIN_FANOUT="${PARAMS_DEADROOT_MIN_FANOUT:-8000}"
PARAMS_CANDIDATE_POOL="${PARAMS_CANDIDATE_POOL:-30000}"  # candidate reach (search_after-paged). MUST be deep: ephemeral/CI junk scores HIGH so it clusters in the top ~10k (measured ~77% junk there), while real param-bearing web apps sit DEEPER (a 40k sample was ~77% real post-filter). A shallow pool only ever sees the junk tier → ~0-yield crawls. Only queried when the queue has room (backpressure-gated), so the deeper pull is cheap. Server-side cooldown range still slides the window through the ~600k pool.
PARAMS_INTER_HOST_SLEEP="${PARAMS_INTER_HOST_SLEEP:-5}"   # max pre-gau jitter (provider stealth)
KATANA_DEPTH="${KATANA_DEPTH:-2}"
KATANA_CRAWL_TIMEOUT="${KATANA_CRAWL_TIMEOUT:-90}"
KATANA_RL="${KATANA_RL:-15}"
GAU_TIMEOUT="${GAU_TIMEOUT:-30}"    # otx+urlscan are fast; 30s is ample; 60 wasted when providers blocked
MAX_URLS_PER_HOST="${PARAMS_MAX_URLS_PER_HOST:-2000}"
# Portal product-class noise guard (crawl_host). Some CMS/portals (Liferay DXP, etc.) emit
# thousands of param URLs that gf mistags but that are NOT injectable: the Liferay /combo
# JS/CSS bundler (param names = asset file paths → bogus [xss]) and the document-library
# /documents/<groupId>/0/<name>/<uuid> download URLs (file referenced by the UUID path, not
# the param → bogus [lfi]/[cmdi]/[rce] triple-FP). These are shipped-product endpoints (same
# templated path on every host of that stack) = duplicates, not findings. We drop the known
# portal paths outright, then apply a CONSERVATIVE template-domination backstop: if a host
# yields a LOT of param URLs and one normalized path-template dominates, treat that template
# as product-class and drop it (a real app spreads params across many distinct routes).
PARAMS_PRODUCTCLASS_MIN="${PARAMS_PRODUCTCLASS_MIN:-150}"    # only engage the backstop above this raw param-URL count
PARAMS_PRODUCTCLASS_FRAC="${PARAMS_PRODUCTCLASS_FRAC:-60}"   # drop the top template iff it is >= this % of the set (integer %)
PARAMS_SCANNED_FIELD="${PARAMS_SCANNED_FIELD:-params_scanned_at}"   # recon_alive date field = per-host cooldown ledger (ES source of truth)
# Archive proxy (Cloudflare worker) — restores Wayback CDX param-URL discovery that the
# Internet Archive blocks from our Mullvad datacenter egress (it blackholes wayback for
# VPN/DC ranges). URL + secret live in FILES, never git: ~/.recon_cdx_url, ~/.recon_cdx_key.
# Empty ⇒ archive_fetch is a no-op (katana-only). Only the public-archive lookup egresses
# via Cloudflare; the bug-bounty host is NEVER contacted by it. Be gentle — don't burn the CF
# path: the per-host 7d cooldown means each host hits wayback ~once/7d, and the worker caches.
PARAMS_ARCHIVE_URL="${PARAMS_ARCHIVE_URL:-$(tr -d '\r\n' < "$HOME/.recon_cdx_url" 2>/dev/null)}"
PARAMS_ARCHIVE_KEY="${PARAMS_ARCHIVE_KEY:-$(tr -d '\r\n' < "$HOME/.recon_cdx_key" 2>/dev/null)}"
PARAMS_ARCHIVE_TIMEOUT="${PARAMS_ARCHIVE_TIMEOUT:-60}"  # big domains (superdrug/example-scale CDX histories) don't return inside 30s — they time out and we lose the param-RICH archive surface. Small/medium domains return in ~4s, so 60s only ever costs extra wall-clock on the slow tail (still well under the 1800s job TTL). 2026-06-14.
# Liveness verification (verify-live): archive URLs (wayback/gau) are HISTORICAL, so many
# are dead 404s. A paced, Mullvad-gated stage probes catalog URLs (deduped by path), keeps
# the live ones, and DELETES the dead — so only worth-keeping params remain and confirmers
# never burn budget on 404s. Bounded per cycle (anti-burn) + loud errors (never silent-freeze).
PARAMS_LIVE_BATCH="${PARAMS_LIVE_BATCH:-120}"        # catalog URLs checked per cycle
PARAMS_LIVE_TIMEOUT="${PARAMS_LIVE_TIMEOUT:-10}"     # per-probe timeout (s)
PARAMS_LIVE_TTL_DAYS="${PARAMS_LIVE_TTL_DAYS:-30}"   # re-verify a URL's liveness this often

mkdir -p "$PARAMS_DIR" "$STATE_DIR" "$PARAMS_INBOX" "$PARAMS_PROCESSING" "$PARAMS_DONE"
command -v jq >/dev/null 2>&1 || { warn "jq missing"; exit 1; }

es()  { curl -sS -m30 --netrc-file "$HOME/.recon_es_netrc" "$@"; }
es_up() { local c; c="$(curl -sS -o /dev/null -m5 --netrc-file "$HOME/.recon_es_netrc" -w '%{http_code}' "$ES_URL" 2>/dev/null || echo 000)"; [[ "$c" == "200" ]]; }

ensure_index() {
  es -fsS "$ES_URL/$PARAMS_INDEX" >/dev/null 2>&1 && return 0
  es -fsS -X PUT "$ES_URL/$PARAMS_INDEX" -H 'Content-Type: application/json' -d '{
    "mappings":{"properties":{
      "url":{"type":"keyword","ignore_above":4096},
      "host":{"type":"keyword"},
      "root_domain":{"type":"keyword"},
      "vuln_classes":{"type":"keyword"},
      "program":{"type":"keyword","ignore_above":512},
      "payout_tier":{"type":"keyword"},
      "true_fresh":{"type":"boolean"},
      "first_seen":{"type":"date"},
      "cataloged_at":{"type":"date"}
    }}}' >/dev/null 2>&1 || warn "could not create $PARAMS_INDEX index"
}

# ensure recon_alive carries the per-host cooldown date field used by the producer's
# sliding-window query. Idempotent and purely additive (safe on the central index).
ensure_alive_field() {
  es -fsS -X PUT "$ES_URL/$INDEX_NAME/_mapping" -H 'Content-Type: application/json' \
    -d "{\"properties\":{\"$PARAMS_SCANNED_FIELD\":{\"type\":\"date\"}}}" >/dev/null 2>&1 \
    || warn "could not ensure $INDEX_NAME.$PARAMS_SCANNED_FIELD mapping"
}

# archive_fetch HOST — fetch the host's archived URLs (Wayback CDX) via the Cloudflare
# worker proxy. IA blocks wayback from our Mullvad datacenter egress; Cloudflare's egress
# isn't blocked, so we proxy ONLY this public-archive lookup through the worker — the
# bug-bounty host itself is NEVER contacted here. No-op unless the URL+key files exist.
archive_fetch() {
  [[ -n "$PARAMS_ARCHIVE_URL" && -n "$PARAMS_ARCHIVE_KEY" ]] || return 0
  curl -sS -m"$PARAMS_ARCHIVE_TIMEOUT" -H "x-auth: $PARAMS_ARCHIVE_KEY" \
    "$PARAMS_ARCHIVE_URL/?domain=$1&limit=$MAX_URLS_PER_HOST" 2>/dev/null
}

# crawl_host — all per-host work, writing ONLY into its own dir under $wd so N copies
# run concurrently without clobbering shared files. Emits: bulk.part (ndjson), scanned
# (just the hostname — the consumer stamps recon_alive.params_scanned_at = the cooldown
# ledger), cls.<class> (per-class URLs), urlcount. Sources: katana (LIVE crawl, Mullvad)
# + gau (otx/urlscan) + archive_fetch (Wayback CDX via the Cloudflare worker). katana/gau
# are target-facing + per-host rate-limited; archive_fetch never touches the host.
crawl_host() {
  local host="$1" url="$2" root="$3" program="$4" tier="$5" fresh="$6" fseen="$7" wd="$8"
  local hd="$wd/$(printf '%s' "$host" | tr '/:.' '___')"; mkdir -p "$hd"
  sleep $(( (RANDOM % PARAMS_INTER_HOST_SLEEP) + 1 ))   # jitter so N parallel gau hits don't burst a provider
  # AUTHED crawl: cmd_crawl_host may export KATANA_AUTH_HEADER (operator's OWN session) so katana
  # walks the authenticated surface. The daemon never sets it → daemon crawls stay unauth (hard
  # line: no autonomous authed requests). gau/archive are passive, so auth only affects katana.
  local kauth=(); [[ -n "${KATANA_AUTH_HEADER:-}" ]] && kauth+=(-H "$KATANA_AUTH_HEADER")
  { timeout "$KATANA_CRAWL_TIMEOUT" "$KATANA" -u "$url" -d "$KATANA_DEPTH" -jc -fs rdn -silent -nc -rl "$KATANA_RL" "${kauth[@]}" 2>/dev/null
    # gau: otx+urlscan only — wayback (web.archive.org) + commoncrawl block our Mullvad
    # egress, so asking gau for them just burns the timeout. Wayback comes via the worker.
    [[ -x "$GAU" ]] && printf '%s\n' "$host" | timeout "$GAU_TIMEOUT" "$GAU" --providers otx,urlscan --threads 5 --subs 2>/dev/null
    # waymore — richer multi-archive aggregator, ZERO-OVERLAP partition (anti-burn): gau already does
    # otx+urlscan and the CF-worker CDX proxy (archive_fetch, below) does wayback — so waymore handles ONLY the
    # sources gau LACKS: ghostarchive (keyless) + virustotal/intelx (skip gracefully until keyed). This avoids
    # double-hitting the rate-limited otx/urlscan from the shared Mullvad IP (they 429 fast). PASSIVE — hits
    # archive APIs, NEVER the target (no extra target traffic). -n = this host only. Output → file → dedup pipe.
    # (Free win: add a urlscan/VT key to ~/.config/waymore/config.yml to unlock far more archive URLs.)
    if [[ -x "$WAYMORE" ]]; then
      timeout "$WAYMORE_TIMEOUT" "$WAYMORE" -i "$host" -n -mode U -oU "$hd/waymore.txt" \
        --providers ghostarchive,virustotal,intelx >/dev/null 2>&1 || true
      [[ -s "$hd/waymore.txt" ]] && cat "$hd/waymore.txt"
    fi
    # Wayback CDX archive URLs, proxied through Cloudflare (escapes IA's Mullvad block).
    archive_fetch "$host"
  } | grep -E '^https?://' | grep -F '?' | sort -u | head -n "$MAX_URLS_PER_HOST" > "$hd/raw" || true
  # Drop tracking-ONLY URLs: if EVERY param is analytics junk (utm_*, fbclid, gclid, …) the
  # page is not server-side testable — pure noise for the confirmers. Keep any URL with at
  # least one non-tracking param. (Liveness of the survivors is checked later by verify-live.)
  if [[ -s "$hd/raw" ]]; then
    awk '{ q=$0; sub(/^[^?]*\?/,"",q); real=0; n=split(q,P,/&/);
           for(i=1;i<=n;i++){ nm=P[i]; sub(/=.*/,"",nm);
             if (nm !~ /^(utm_[a-z_]+|fbclid|gclid|gclsrc|dclid|wbraid|gbraid|msclkid|mc_cid|mc_eid|_ga|_gl|yclid|igshid|twclid|spm|scm|fb_action_ids|fb_action_types|fb_source|ref|referrer)$/) { real=1; break } }
           if (real) print }' "$hd/raw" > "$hd/raw.f" 2>/dev/null && mv "$hd/raw.f" "$hd/raw"
  fi
  # Portal product-class noise: drop KNOWN gf-mistagged shipped-product paths before gf sees
  # them. All three are Liferay's static-asset plumbing, never an injectable sink:
  #   /combo bundler (?...js=/css= → bogus xss on asset file-paths),
  #   /documents/<groupId>/0/<name>/<uuid> document-library downloads (bogus lfi/cmdi/rce —
  #     the file is referenced by the UUID path, not the param),
  #   /o/<module>/.../<file>.css|.js OSGi-module CSS/JS bundler (same as /combo: bogus xss on
  #     a static asset whose only params are cache-busters minifierType/browserId/themeId/t).
  # Anchored to the path component so genuine app routes survive (e.g. /combobox?,
  # /documentsearch?, /api/x.json?id= do NOT match — only .css/.js under /o/). See PARAMS_PRODUCTCLASS_* above.
  if [[ -s "$hd/raw" ]]; then
    grep -avE '://[^/]+(/[^?]*)?/combo[/?]|://[^/]+(/[^?]*)?/documents/[0-9]+/|://[^/]+(/[^?]*)?/o/[^?]*\.(css|js)([?]|$)' "$hd/raw" > "$hd/raw.f" 2>/dev/null \
      && mv "$hd/raw.f" "$hd/raw"
  fi
  # Conservative template-domination backstop: if this host yields a LOT of param URLs and a
  # single normalized path-template (path with numeric/uuid/hex segments collapsed + the
  # param-name set) accounts for the bulk of them, that template is a shipped-product endpoint
  # repeated across the site, not real per-app surface — drop just that one dominant template.
  if [[ -s "$hd/raw" ]]; then
    awk -v MIN="$PARAMS_PRODUCTCLASS_MIN" -v FRAC="$PARAMS_PRODUCTCLASS_FRAC" '
      function tmpl(line,   u,p,q,nseg,seg,i,nm,nq,P,names) {
        u=line; sub(/^https?:\/\/[^\/]+/,"",u)        # strip scheme+host → path?query
        p=u; q=u; sub(/\?.*$/,"",p); sub(/^[^?]*\??/,"",q)
        nseg=split(p,seg,"/")                          # collapse volatile path segments
        for(i=1;i<=nseg;i++){
          if(seg[i] ~ /^[0-9]+$/) seg[i]="#"
          else if(seg[i] ~ /^[0-9a-fA-F]{8}-[0-9a-fA-F-]{20,}$/) seg[i]="#"
          else if(seg[i] ~ /^[0-9a-fA-F]{16,}$/) seg[i]="#"
        }
        p=seg[1]; for(i=2;i<=nseg;i++) p=p"/"seg[i]
        nq=split(q,P,/&/); names=""                    # param-name list (keeps templates with same path but different params distinct)
        for(i=1;i<=nq;i++){ nm=P[i]; sub(/=.*/,"",nm); names=names" "nm }
        return p"|"names
      }
      { lines[NR]=$0; key[NR]=tmpl($0); cnt[key[NR]]++; total++ }
      END {
        if (total < MIN) { for(i=1;i<=NR;i++) print lines[i]; exit }
        top=""; topn=0
        for(k in cnt) if(cnt[k]>topn){ topn=cnt[k]; top=k }
        if (topn*100 >= total*FRAC && topn>1) {        # dominant template → product-class, drop it
          for(i=1;i<=NR;i++) if(key[i]!=top) print lines[i]
        } else { for(i=1;i<=NR;i++) print lines[i] }
      }' "$hd/raw" > "$hd/raw.f" 2>/dev/null && mv "$hd/raw.f" "$hd/raw"
  fi
  # Active hidden-param discovery (arjun) — ON-DEMAND ONLY (PARAMS_ARJUN=1; never the autonomous
  # daemon crawl — arjun sends LIVE traffic, mass use = anti-burn risk). Finds params that appear
  # in NO crawled URL/JS (the inputs that drive SSRF/cache-poison/reflected bugs the crowd misses).
  # Discovered params are synthesized as url?p=FUZZ into raw so they ride the SAME gf→catalog pipeline.
  if [[ "${PARAMS_ARJUN:-0}" == "1" && -n "$ARJUN" && -x "$ARJUN" ]]; then
    local aout="$hd/arjun.json" awl=()
    [[ -s "$ARJUN_WORDLIST" ]] && awl=(-w "$ARJUN_WORDLIST")
    local ahdr=(); [[ -n "${KATANA_AUTH_HEADER:-}" ]] && ahdr=(--headers "$KATANA_AUTH_HEADER")
    log "  $host — arjun active param discovery (polite: -t1 -d$ARJUN_DELAY --rate-limit $ARJUN_RATELIMIT)"
    timeout 300 "$ARJUN" -u "$url" -m GET -t 1 -d "$ARJUN_DELAY" --rate-limit "$ARJUN_RATELIMIT" \
      --disable-redirects -T "$ARJUN_TIMEOUT" -q "${awl[@]}" "${ahdr[@]}" -oJ "$aout" >/dev/null 2>&1 || true
    if [[ -s "$aout" ]]; then
      python3 - "$aout" >> "$hd/raw" 2>/dev/null <<'PY' || true
import sys, json
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    d = {}
for u, info in (d.items() if isinstance(d, dict) else []):
    ps = (info or {}).get("params") or []
    if not ps:
        continue
    q = "&".join("%s=FUZZ" % p for p in ps)
    print(u + ("&" if "?" in u else "?") + q)
PY
      sort -u "$hd/raw" -o "$hd/raw" 2>/dev/null || true
    fi
  fi
  local raw_n; raw_n="$(wc -l < "$hd/raw" 2>/dev/null | tr -d ' ')"
  log "  $host — ${raw_n:-0} param URLs"
  # Record the host as crawled REGARDLESS of yield — the consumer cools it so the
  # sliding window rotates past it (a param-poor host won't be retried until its
  # cooldown lapses; by then the window has moved far through the ~600k pool).
  printf '%s\n' "$host" > "$hd/scanned"
  [[ "${raw_n:-0}" -eq 0 ]] && return 0
  if [[ -x "$QSREPLACE" ]]; then "$QSREPLACE" FUZZ < "$hd/raw" 2>/dev/null | sort -u > "$hd/urls"; else cp "$hd/raw" "$hd/urls" 2>/dev/null || : > "$hd/urls"; fi
  [[ -s "$hd/urls" ]] || return 0
  : > "$hd/classified.tsv"
  local cls
  for cls in $PARAMS_CLASSES; do "$GF" "$cls" < "$hd/urls" 2>/dev/null | sed "s|\$|\t$cls|" >> "$hd/classified.tsv"; done
  [[ -s "$hd/classified.tsv" ]] || return 0
  for cls in $PARAMS_CLASSES; do awk -F'\t' -v c="$cls" '$2==c{print $1}' "$hd/classified.tsv" > "$hd/cls.$cls" 2>/dev/null || true; done
  awk -F'\t' '{a[$1]=a[$1]","$2} END{for(u in a){sub(/^,/,"",a[u]); print u"\t"a[u]}}' "$hd/classified.tsv" \
  | while IFS=$'\t' read -r u classes; do
      local iso id; iso="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"; id="$(printf '%s' "$u" | sha1sum | cut -c1-40)"
      jq -nc --arg u "$u" --arg id "$id" --arg h "$host" --arg rd "$root" --arg pr "$program" --arg ti "$tier" \
            --argjson tf "${fresh:-false}" --arg fs "$fseen" --arg ca "$iso" --arg cl "$classes" \
        '{index:{_id:$id}}, {url:$u,host:$h,root_domain:$rd,vuln_classes:($cl|split(",")),program:$pr,payout_tier:$ti,true_fresh:$tf,first_seen:(if $fs=="" then null else $fs end),cataloged_at:$ca}' 2>/dev/null >> "$hd/bulk.part"
    done
  wc -l < "$hd/urls" | tr -d ' ' > "$hd/urlcount"
}

# ---------------------------------------------------------------------------
# requeue_stale — bounce jobs whose consumer crashed/overran (claimed > JOB_TTL
# ago, still in processing/) back to inbox with a .retryN bump; drop after
# PARAMS_JOB_MAX_RETRY. Mirrors recon_validate.sh's retry discipline.
requeue_stale() {
  local now f; now="$(date +%s)"
  for f in "$PARAMS_PROCESSING"/*.tsv; do
    [[ -e "$f" ]] || continue
    local mt age; mt="$(stat -c %Y "$f" 2>/dev/null || echo "$now")"; age=$(( now - mt ))
    (( age < PARAMS_JOB_TTL )) && continue
    local base; base="$(basename "$f")"
    local rc=0; [[ "$base" =~ \.retry([0-9]+)\.tsv$ ]] && rc="${BASH_REMATCH[1]}"
    if (( rc >= PARAMS_JOB_MAX_RETRY )); then warn "dropping job $base after $rc retries"; rm -f "$f"; continue; fi
    local stem="${base%.tsv}"; stem="${stem%.retry*}"
    mv "$f" "$PARAMS_INBOX/${stem}.retry$((rc+1)).tsv" 2>/dev/null && log "requeued stale job $base (retry $((rc+1)))"
  done
}

# stamp_cooldown WORKDIR — set recon_alive.<params_scanned_at> = now for every host this
# crawl touched (collected from $wd/*/scanned, one host per file). ONE filtered
# _update_by_query, bounded by job size; conflicts=proceed so a concurrent doc update
# can't fail it. This ES field IS the cooldown ledger that slides the producer window.
stamp_cooldown() {
  local wd="$1" hosts terms ts
  hosts="$(cat "$wd"/*/scanned 2>/dev/null | sort -u)"
  [[ -n "$hosts" ]] || return 0
  terms="$(printf '%s\n' "$hosts" | jq -R . | jq -cs .)"
  ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  es -H 'Content-Type: application/json' -X POST "$ES_URL/$INDEX_NAME/_update_by_query?conflicts=proceed" -d "{
    \"query\":{\"terms\":{\"host\":$terms}},
    \"script\":{\"lang\":\"painless\",\"source\":\"ctx._source.$PARAMS_SCANNED_FIELD=params.ts\",\"params\":{\"ts\":\"$ts\"}}
  }" >/dev/null 2>&1 || warn "cooldown stamp failed for $(printf '%s\n' "$hosts" | wc -l | tr -d ' ') host(s)"
}

# cool_hosts FILE — stamp params_scanned_at=now on every hostname in FILE (one per
# line). The PRODUCER uses this to COOL filtered-out junk: hosts with zero param
# surface (UUID cloud tenants, api/auth/infra leftmost-labels, embedded dev/test/
# staging/preprod/CI/internal markers) are never crawled, so they were never stamped —
# which meant they permanently re-occupied the top of the score-sorted candidate window
# and starved real hosts (the 2026-06-14 "enqueued 2 hosts/cycle" freeze). Cooling them
# slides the window past them. The filter is deterministic, so a 7d cooldown is safe: a
# false-dropped real host just returns after the TTL. Chunked to stay well under
# index.max_terms_count; conflicts=proceed so a concurrent update can't fail it.
cool_hosts() {
  local f="$1" ts c; [[ -s "$f" ]] || return 0
  ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  split -l 1000 "$f" "$f.chunk_"
  for c in "$f".chunk_*; do
    [[ -s "$c" ]] || continue
    local terms; terms="$(jq -R . < "$c" | jq -cs .)"
    es -H 'Content-Type: application/json' -X POST "$ES_URL/$INDEX_NAME/_update_by_query?conflicts=proceed" -d "{
      \"query\":{\"terms\":{\"host\":$terms}},
      \"script\":{\"lang\":\"painless\",\"source\":\"ctx._source.$PARAMS_SCANNED_FIELD=params.ts\",\"params\":{\"ts\":\"$ts\"}}
    }" >/dev/null 2>&1 || warn "cool_hosts stamp failed for a chunk"
  done
  rm -f "$f".chunk_*
  log "cooled $(wc -l < "$f" | tr -d ' ') filtered junk host(s) so the window advances"
}

# compute_dead_roots — DATA-DRIVEN product-class fan-out suppression. Echoes a JSON array
# of root_domains we've sampled enough of (crawled >= MIN_SAMPLE) to prove they yield
# essentially no params (< MAX_YIELD params/crawled-host) — quora/artstation/statuspage/
# elastic.dev-style per-user/per-tenant fan-out. Two cheap aggs (crawled-per-root over
# recon_alive, cataloged-per-root over recon_params), joined in jq. Echoes "[]" if none or
# on any error (fail-open: a suppression bug must never starve the producer). The producer
# adds these to its candidate query's must_not so the class stops consuming crawl cycles.
compute_dead_roots() {
  local ms="${PARAMS_DEADROOT_MIN_SAMPLE:-20}" my="${PARAMS_DEADROOT_MAX_YIELD:-0.05}" mf="${PARAMS_DEADROOT_MIN_FANOUT:-8000}" eligible crawled cataloged
  # eligible-per-root (the fan-out size: in-scope + paying hosts under the root)
  eligible="$(es -H 'Content-Type: application/json' -X POST "$ES_URL/$INDEX_NAME/_search" -d '{
    "size":0,"query":{"bool":{"filter":[{"term":{"triage_in_scope":true}},{"term":{"triage_pays":true}}]}},
    "aggs":{"r":{"terms":{"field":"root_domain","size":5000}}}}' 2>/dev/null)"
  # crawled-per-root (how many we've already sampled for params)
  crawled="$(es -H 'Content-Type: application/json' -X POST "$ES_URL/$INDEX_NAME/_search" -d '{
    "size":0,"query":{"exists":{"field":"'"$PARAMS_SCANNED_FIELD"'"}},
    "aggs":{"r":{"terms":{"field":"root_domain","size":5000}}}}' 2>/dev/null)"
  # cataloged-per-root (param-URLs we actually got)
  cataloged="$(es -H 'Content-Type: application/json' -X POST "$ES_URL/$PARAMS_INDEX/_search" -d '{
    "size":0,"aggs":{"r":{"terms":{"field":"root_domain","size":5000}}}}' 2>/dev/null)"
  # default empties to a literal '{}' on their OWN line — `${var:-{}}` is ambiguous in bash
  # (parses as `${var:-{}` + a stray `}`) and corrupts otherwise-valid JSON for --argjson.
  [[ -n "$eligible"  ]] || eligible='{}'
  [[ -n "$crawled"   ]] || crawled='{}'
  [[ -n "$cataloged" ]] || cataloged='{}'
  # DEAD = mass fan-out (eligible >= mf) AND well-sampled (crawled >= ms) AND ~zero yield
  # (params/crawled < my). All three gates required; fail-open to [] on any parse error.
  jq -cn --argjson e "$eligible" --argjson c "$crawled" --argjson p "$cataloged" \
         --argjson ms "$ms" --argjson my "$my" --argjson mf "$mf" '
    (($e.aggregations.r.buckets // []) | map({(.key): .doc_count}) | add // {}) as $em
    | (($p.aggregations.r.buckets // []) | map({(.key): .doc_count}) | add // {}) as $pm
    | (($c.aggregations.r.buckets // []))
    | map(select(
        .doc_count >= $ms
        and (($em[.key] // 0) >= $mf)
        and ((($pm[.key] // 0) / .doc_count) < $my)
      ) | .key)
  ' 2>/dev/null || echo '[]'
}

# index_workdir WORKDIR — aggregate ONE crawl's per-host outputs: bulk-index to
# recon_params, append per-class files, and stamp the cooldown ledger. Echoes the
# indexed doc count on stdout.
index_workdir() {
  local wd="$1" cls
  local bulk="$wd/bulk.ndjson"; : > "$bulk"
  cat "$wd"/*/bulk.part >> "$bulk" 2>/dev/null || true
  stamp_cooldown "$wd"
  for cls in $PARAMS_CLASSES; do
    cat "$wd"/*/cls."$cls" >> "$PARAMS_DIR/$cls.txt" 2>/dev/null || true
    [[ -f "$PARAMS_DIR/$cls.txt" ]] && sort -u "$PARAMS_DIR/$cls.txt" -o "$PARAMS_DIR/$cls.txt" 2>/dev/null || true
  done
  local indexed=0
  if [[ -s "$bulk" ]]; then
    local bulk_resp
    bulk_resp="$(es -H 'Content-Type: application/x-ndjson' -X POST "$ES_URL/$PARAMS_INDEX/_bulk" --data-binary @"$bulk" 2>/dev/null)"
    if [[ -n "$bulk_resp" ]]; then
      indexed="$(printf '%s' "$bulk_resp" | jq '[.items[]?.index | select(.result=="created" or .result=="updated")] | length' 2>/dev/null || echo 0)"
      local errs; errs="$(printf '%s' "$bulk_resp" | jq -r '[.items[]?.index | select(.error) | .error.reason] | unique | .[:3] | join(" | ")' 2>/dev/null)"
      [[ -n "$errs" ]] && warn "bulk index errors: $errs"
    else
      warn "bulk index: no response from ES (connection issue?)"
    fi
  fi
  printf '%s' "$indexed"
}

# ---------------------------------------------------------------------------
# PRODUCER — ES-only candidate selection → small job files in the queue. No
# target traffic, so it takes its OWN light lock (not the egress-gated consumer
# lock). Recovers crashed jobs and honours inbox backpressure before any ES work.
cmd_enqueue() {
  es_up || { warn "ES not reachable"; exit 0; }
  ensure_index
  ensure_alive_field
  exec 9>"$STATE_DIR/params_enqueue.lock"; flock -n 9 || { warn "params enqueue already running"; exit 0; }
  python3 -c "import fcntl;fcntl.fcntl(9,fcntl.F_SETFD,fcntl.FD_CLOEXEC)" 2>/dev/null || true

  requeue_stale
  local pending; pending="$(find "$PARAMS_INBOX" -maxdepth 1 -name '*.tsv' -type f 2>/dev/null | wc -l | tr -d ' ')"
  local free=$(( PARAMS_INBOX_CAP - pending ))
  (( free > 0 )) || { log "inbox full ($pending/$PARAMS_INBOX_CAP jobs) — not enqueuing"; exit 0; }

  WORK="$(mktemp -d)"; trap '[[ -n "${WORK:-}" ]] && rm -rf "$WORK"' EXIT
  : > "$WORK/cand.tsv"

  # Product-class fan-out suppression (server-side): exclude roots PROVEN zero-yield by a
  # real sample, so they stop consuming crawl cycles. Fail-open — never starve the producer.
  local DEADROOTS DEAD_CLAUSE=""
  DEADROOTS="$(compute_dead_roots)"; [[ -n "$DEADROOTS" ]] || DEADROOTS='[]'
  if [[ "$DEADROOTS" != "[]" ]]; then
    DEAD_CLAUSE=",{\"terms\":{\"root_domain\":$DEADROOTS}}"
    printf '%s\n' "$DEADROOTS" | jq -r '.[]' > "$STATE_DIR/params_deadroots.txt" 2>/dev/null || true
    log "suppressing $(printf '%s' "$DEADROOTS" | jq 'length') proven zero-yield product-class root(s) (≥${PARAMS_DEADROOT_MIN_SAMPLE} crawled, <${PARAMS_DEADROOT_MAX_YIELD} params/host)"
  fi

  # SLIDING-WINDOW candidate query. Highest triage_score first (GAU/web-archive
  # coverage drives param yield — established hosts have years of history; CT-fresh
  # UUID subdomains have none). first_seen ASC tiebreaks; host ASC is the unique
  # search_after tiebreaker. The must_not range on params_scanned_at EXCLUDES hosts
  # crawled within the cooldown window SERVER-SIDE, so the query always returns the
  # top NOT-recently-crawled hosts and walks deeper into the ~600k pool on its own —
  # the producer can't go idle while uncrawled hosts remain, and never re-hammers one.
  #
  # ES caps from+size at index.max_result_window (default 10000) — a single
  # "size">10000 errors out (search_phase_execution_exception) → 0 rows → silent
  # freeze (the 2026-06-11 bug). PARAMS_CANDIDATE_POOL is just the page size now (the
  # range filter, not pool depth, slides the window); paged via SEARCH_AFTER regardless.
  local PAGE=$(( PARAMS_CANDIDATE_POOL < 10000 ? PARAMS_CANDIDATE_POOL : 10000 ))
  local got=0 after=""
  while (( got < PARAMS_CANDIDATE_POOL )); do
    local sa=""; [[ -n "$after" ]] && sa=",\"search_after\":$after"
    local resp; resp="$(es -H 'Content-Type: application/json' -X POST "$ES_URL/$INDEX_NAME/_search" -d "{
      \"size\": $PAGE,
      \"_source\":[\"host\",\"url\",\"root_domain\",\"triage_program\",\"triage_payout_tier\",\"triage_score\",\"triage_true_fresh\",\"first_seen\"],
      \"query\":{\"bool\":{\"filter\":[{\"term\":{\"triage_in_scope\":true}},{\"term\":{\"triage_pays\":true}}],\"must_not\":[{\"term\":{\"triage_out_of_scope\":true}},{\"range\":{\"$PARAMS_SCANNED_FIELD\":{\"gte\":\"now-${PARAMS_COOLDOWN_DAYS}d\"}}}$DEAD_CLAUSE]}},
      \"sort\":[{\"triage_score\":{\"order\":\"desc\",\"missing\":\"_last\"}},{\"first_seen\":{\"order\":\"asc\",\"missing\":\"_last\"}},{\"host\":{\"order\":\"asc\"}}]$sa
    }" 2>/dev/null)" || { warn "ES query failed (curl)"; exit 0; }
    # An ES-side error must NEVER masquerade as "no candidates" and silently
    # freeze the pillar — surface it loudly and bail so MONITOR can catch it.
    if printf '%s' "$resp" | jq -e '.error' >/dev/null 2>&1; then
      warn "ES candidate query error: $(printf '%s' "$resp" | jq -r '.error.root_cause[0].reason // .error.reason // .error.type' 2>/dev/null)"
      exit 1
    fi
    local n; n="$(printf '%s' "$resp" | jq -rc '.hits.hits[]?._source | [(.host//""),(.url//("https://"+(.host//""))),(.root_domain//""),(.triage_program//""),(.triage_payout_tier//"none"),((.triage_true_fresh//false)|tostring),(.first_seen//"")] | @tsv' 2>/dev/null | tee -a "$WORK/cand.tsv" | wc -l | tr -d ' ')"
    got=$(( got + n ))
    (( n < PAGE )) && break    # short page → candidate pool exhausted
    after="$(printf '%s' "$resp" | jq -c '.hits.hits[-1].sort // empty' 2>/dev/null)"
    [[ -z "$after" ]] && break
  done
  [[ -s "$WORK/cand.tsv" ]] || { log "no in-scope-paying candidates"; exit 0; }

  local NOW; NOW=$(date +%s)
  # Cooldown is enforced SERVER-SIDE by the query's params_scanned_at range above, so
  # the only client-side exclusion left is queue-dedup: drop hosts already sitting in
  # the queue (inbox+processing) so a host is never enqueued twice while it waits.
  : > "$WORK/done.set"
  cat "$PARAMS_INBOX"/*.tsv "$PARAMS_PROCESSING"/*.tsv 2>/dev/null | cut -f1 | sort -u > "$WORK/done.set"

  # FILTER FIRST (before the diversity cap) so we can COOL every junk host in the
  # window — not just 3-per-root. Hosts that are structurally useless for URL-archive
  # lookups:
  #   - UUID-named cloud infra (unifi-hosting, etc.) — no public URL history
  #   - mta-sts.* — MTA-STS policy records, not web apps
  #   - cdn-*.* / assets.* / static.* — CDN edge nodes
  #   - api/auth/infra leftmost-labels (POST/JSON, no GET params), device/IoT/message
  #     brokers, mail/DNS records — no archive param-URLs, index 0, burn GAU quota.
  # EPHEMERAL/NON-PROD (2026-06-13): dev/test/staging/qa/preprod/CI/internal markers
  # EMBEDDED anywhere as a whole DNS label / hyphen-token ((^|[.-])marker([.-]|$)) —
  # never substring-FP a real host ("developers", "latest", "investor" are NOT matched).
  # Out-of-scope corp/internal infra is caught here as a side effect.
  #
  # COOL-ON-EXAMINE (2026-06-14): these filtered hosts are never crawled, so they were
  # never stamped params_scanned_at — which meant the score-sorted candidate window
  # stayed permanently anchored to uncoolable junk (unifi UUID tenants score 25/16,
  # backblaze S3 buckets, *-internal infra) and the producer only ever surfaced the 2-3
  # real hosts mixed into the top 30k → "enqueued 2 hosts/cycle" forever. We now run the
  # filter on the RAW window, COOL the junk via cool_hosts (so the window slides past
  # it), THEN diversity-cap the survivors.
  grep -vE '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.' \
       "$WORK/cand.tsv" \
  | grep -vE '^(mta-sts|cdn-[0-9]|assets\.|static\.|media\.)' \
  | grep -vE '^(api|apis|graphql|grpc|gql|mqtt|push|device|devices|iot|broker|smtp|imap|pop3?|mx[0-9]*|ns[0-9]+|dns)[.-]' \
  | grep -vE '^(auth|login|signin|sso|oauth|oidc|idp|saml|adfs|keycloak|prometheus|alertmanager|grafana|metrics|daemon|repo|repos|registry|artifactory|nexus)[.-]' \
  | grep -viE '(^|[.-])(dev|test|tests|testing|qa|uat|sit|stg|stage|staging|preprod|prprd|nonprod|sandbox|sbx|demo|preview|storybook|ephemeral|internal|intranet|corp|canary|perf|loadtest|feature|pr[0-9]+|ci|jenkins|gerrit|vpn|np)([.-]|$)' \
  > "$WORK/cand_clean.tsv"
  # cool the junk = (raw window) − (clean survivors): every examined zero-param-surface
  # host, regardless of root, so high-cardinality junk roots actually drain.
  cut -f1 "$WORK/cand.tsv"        | sort -u > "$WORK/win.hosts"
  cut -f1 "$WORK/cand_clean.tsv"  | sort -u > "$WORK/clean.hosts"
  comm -23 "$WORK/win.hosts" "$WORK/clean.hosts" > "$WORK/junk.hosts"
  cool_hosts "$WORK/junk.hosts"

  # Diversity: cap hosts per root_domain so one program (e.g. 15 airbnb locale
  # subdomains) can't consume the entire cycle. Applied to the CLEAN survivors only.
  local MAX_PER_ROOT="${PARAMS_MAX_PER_ROOT:-3}"
  awk -F'\t' -v m="$MAX_PER_ROOT" '{if(++seen[$3]<=m)print}' "$WORK/cand_clean.tsv" > "$WORK/cand.tsv"
  rm -f "$WORK/cand_clean.tsv" "$WORK/win.hosts" "$WORK/clean.hosts" "$WORK/junk.hosts"

  # PHASE 5: bias toward roots with PROVEN archive/param coverage. A root already in
  # the params catalog has GAU/wayback history that yields param-URLs; a brand-new
  # in-scope host may have none. Float hosts under proven roots to the front (new
  # roots still get scanned, just after) — turns "any fresh in-scope host" into
  # "hosts likely to actually produce a candidate". root_domain is a keyword field
  # in the catalog (no .keyword subfield); graceful no-op if catalog unavailable.
  local covered="$WORK/covered_roots.set"; : > "$covered"
  es -H 'Content-Type: application/json' -X POST "$ES_URL/$PARAMS_INDEX/_search" -d '{
    "size":0,"aggs":{"r":{"terms":{"field":"root_domain","size":5000}}}}' 2>/dev/null \
    | jq -r '.aggregations.r.buckets[]?.key // empty' 2>/dev/null | sort -u > "$covered" || true
  if [[ -s "$covered" ]]; then
    # stable sort: proven-root hosts (key 0) before the rest (key 1), score order kept
    awk -F'\t' 'NR==FNR{c[$1]=1;next}{print (($3 in c)?0:1)"\t"$0}' "$covered" "$WORK/cand.tsv" \
      | sort -t$'\t' -k1,1 -s | cut -f2- > "$WORK/cand.sorted" 2>/dev/null \
      && mv "$WORK/cand.sorted" "$WORK/cand.tsv"
    log "candidate bias: $(wc -l < "$covered") proven-coverage root(s) floated to front"
  fi

  # Pick up to (free inbox slots × JOB_SIZE) not-yet-queued, not-cooled hosts and
  # split them into PARAMS_JOB_SIZE-host job files. Score/proven-root order is kept;
  # any job containing a true_fresh host gets the 00_ lane prefix so the consumer
  # drains it first (00_ sorts before 50_).
  local worklist="$WORK/worklist.tsv"; : > "$worklist"
  local picked=0 limit=$(( free * PARAMS_JOB_SIZE ))
  while IFS=$'\t' read -r host url root program tier fresh fseen; do
    (( picked >= limit )) && break
    [[ -z "$host" ]] && continue
    grep -qxF "$host" "$WORK/done.set" && continue
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$host" "$url" "$root" "$program" "$tier" "$fresh" "$fseen" >> "$worklist"
    picked=$((picked+1))
  done < "$WORK/cand.tsv"
  (( picked > 0 )) || { log "no fresh in-scope candidates to enqueue (all cooled or already queued)"; exit 0; }

  split -l "$PARAMS_JOB_SIZE" -d "$worklist" "$WORK/job_"
  local jobs=0 jf
  for jf in "$WORK"/job_*; do
    [[ -e "$jf" ]] || continue
    local pfx=50; awk -F'\t' '$6=="true"{e=1} END{exit !e}' "$jf" 2>/dev/null && pfx=00
    local dest="$PARAMS_INBOX/${pfx}_${NOW}_$(printf '%s' "$jf" | sha1sum | cut -c1-8).tsv"
    mv "$jf" "$dest" 2>/dev/null && jobs=$((jobs+1))
  done
  log "enqueued $picked host(s) as $jobs job(s) (inbox $(find "$PARAMS_INBOX" -maxdepth 1 -name '*.tsv' -type f 2>/dev/null | wc -l | tr -d ' ')/$PARAMS_INBOX_CAP)"
}

# ---------------------------------------------------------------------------
# CONSUMER — claim ONE job, crawl its hosts (PARAM_PARALLEL-wide), index this job
# to recon_params immediately, move it to done. Target-facing → invoked via the
# daemon's run_scanner (egress slot + vpn gate). One job/cycle keeps the egress
# footprint bounded and honest. A crash leaves the job in processing/ for
# requeue_stale to bounce back (re-crawl is idempotent: already-scanned hosts are
# skipped via the cooldown ledger).
cmd_crawl() {
  for t in "$KATANA" "$GF"; do [[ -x "$t" ]] || { warn "missing tool: $t"; exit 1; }; done
  [[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down set — skipping crawl"; exit 0; }
  es_up || { warn "ES not reachable"; exit 0; }
  ensure_index
  ensure_alive_field
  exec 9>"$LOCK_FILE"; flock -n 9 || { warn "params crawl already running"; exit 0; }
  python3 -c "import fcntl;fcntl.fcntl(9,fcntl.F_SETFD,fcntl.FD_CLOEXEC)" 2>/dev/null || true

  requeue_stale

  # claim ONE job atomically (mv inbox→processing); 00_ fresh lane first (sort order).
  local job="" f
  while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    local target="$PARAMS_PROCESSING/$(basename "$f")"
    if mv "$f" "$target" 2>/dev/null; then job="$target"; break; fi
  done < <(find "$PARAMS_INBOX" -maxdepth 1 -name '*.tsv' -type f 2>/dev/null | sort)
  [[ -n "$job" ]] || { log "no jobs in queue"; exit 0; }

  local njob; njob="$(wc -l < "$job" | tr -d ' ')"
  log "claimed $(basename "$job") — $njob host(s), ${PARAM_PARALLEL}-wide"

  WORK="$(mktemp -d)"; trap '[[ -n "${WORK:-}" ]] && rm -rf "$WORK"' EXIT

  # Crawl every host in the job (the producer already excluded cooled + queued hosts
  # server-side, so there is no per-host re-check here). A crash before index_workdir
  # means none were stamped → requeue re-crawls the whole job, idempotently.
  local running=0 crawled=0 halted=0
  while IFS=$'\t' read -r host url root program tier fresh fseen; do
    [[ -z "$host" ]] && continue
    [[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down mid-crawl — halting; job will requeue"; halted=1; break; }
    crawl_host "$host" "$url" "$root" "$program" "$tier" "$fresh" "$fseen" "$WORK" &
    running=$((running+1)); crawled=$((crawled+1))
    if (( running >= PARAM_PARALLEL )); then wait -n 2>/dev/null || wait; running=$((running-1)); fi
  done < "$job"
  wait

  local indexed; indexed="$(index_workdir "$WORK")"
  local total_urls; total_urls="$(cat "$WORK"/*/urlcount 2>/dev/null | awk '{s+=$1} END{print s+0}')"

  if (( halted )); then
    log "crawled $crawled/$njob host(s), $total_urls param-URLs, indexed $indexed (vpn_down — job left for requeue)"
  else
    mv "$job" "$PARAMS_DONE/$(basename "$job")" 2>/dev/null || rm -f "$job"
    # prune the done archive to the most-recent PARAMS_DONE_KEEP
    find "$PARAMS_DONE" -maxdepth 1 -name '*.tsv' -type f -printf '%T@ %p\n' 2>/dev/null \
      | sort -rn | tail -n +"$((PARAMS_DONE_KEEP+1))" | cut -d' ' -f2- | xargs -r rm -f 2>/dev/null || true
    log "job done: crawled $crawled/$njob host(s), $total_urls param-URLs, indexed $indexed catalog entries"
  fi
}

# ---------------------------------------------------------------------------
cmd_list() {
  local cls="${1:-}" n="${2:-200}"
  local cls_oneline; cls_oneline="$(printf '%s' "$PARAMS_CLASSES" | tr '\n' ' ' | sed 's/ $//')"
  if [[ -z "$cls" ]]; then
    printf 'usage: recon-params <class> [N]\n' >&2
    printf 'classes: %s\n' "$cls_oneline" >&2
    exit 2
  fi
  # If N looks non-numeric, treat it as not provided
  [[ "$n" =~ ^[0-9]+$ ]] || n=200
  es_up || { warn "ES not reachable"; exit 1; }
  local resp; resp="$(es -H 'Content-Type: application/json' -X POST "$ES_URL/$PARAMS_INDEX/_search" -d "{
    \"size\": $n,
    \"_source\":[\"url\",\"program\",\"payout_tier\",\"true_fresh\"],
    \"query\":{\"term\":{\"vuln_classes\":\"$cls\"}},
    \"sort\":[{\"true_fresh\":{\"order\":\"desc\"}},{\"cataloged_at\":{\"order\":\"desc\"}}]
  }" 2>/dev/null)" || { warn "query failed"; exit 1; }
  local hits; hits="$(printf '%s' "$resp" | jq -r '.hits.total.value // 0' 2>/dev/null)"
  printf '%s\n' "$resp" | jq -r '.hits.hits[]?._source | ((if .true_fresh then "⚡" else "  " end)) + " [" + (.payout_tier//"?") + "] " + (.program//"?") + "  " + .url' 2>/dev/null
  printf -- '--- %s: %s of %s in-scope-paying URL(s) ---\n' "$cls" "$(( hits < n ? hits : n ))" "$hits" >&2
}

# ---------------------------------------------------------------------------
# cmd_confirm — ON-DEMAND confirmation engine for the ranked XSS/SQLi worklist.
#   confirm xss  [host] [N]   dalfox (context-aware: reflection ≠ XSS — break-out must
#                             EXECUTE) on the host's / top-N catalog URLs.
#   confirm sqli [host] [N]   SAFE ' vs '' DIFFERENTIAL (error-based + boolean length-diff).
#                             HARD LINE: never sqlmap / never --dump / never a data harvest —
#                             confirm the param is injectable, then STOP.
# DOCTRINE: manual/on-demand ONLY (NOT a daemon loop — dalfox fans out many requests/URL,
# which would burn the Mullvad egress and trip "no automated scanners" program rules).
# Rate-limited (DALFOX_DELAY ms, 1 worker; per-probe jitter for sqli), Mullvad-gated,
# param-set-deduped (test one rep per param-surface, not 44 category pages). Unauthenticated.
DALFOX="${DALFOX:-$(command -v dalfox 2>/dev/null || echo "$GOBIN/dalfox")}"
DALFOX_DELAY="${DALFOX_DELAY:-300}"     # ms between requests (anti-burn politeness)
cmd_confirm() {
  local cls="${1:-}"; shift 2>/dev/null || true
  local host="" n="" a AUTH_COOKIE="" AUTH_HEADER=""
  # AUTHED mode: operator supplies their OWN logged-in session (--cookie / --header) so the
  # SAFE confirm runs against the authenticated param surface. Human-in-the-loop ONLY — this
  # is operator-initiated, never a daemon/autonomous authed request (hard line). The primitive
  # stays SAFE: xss=dalfox must EXECUTE, sqli=' vs '' differential — NEVER sqlmap/--dump/harvest.
  while [[ $# -gt 0 ]]; do
    a="$1"
    case "$a" in
      --cookie) AUTH_COOKIE="${2:-}"; shift 2 || true ;;
      --cookie=*) AUTH_COOKIE="${a#--cookie=}"; shift ;;
      --header) AUTH_HEADER="${2:-}"; shift 2 || true ;;
      --header=*) AUTH_HEADER="${a#--header=}"; shift ;;
      *) if [[ "$a" =~ ^[0-9]+$ ]]; then n="$a"; else host="$a"; fi; shift ;;
    esac
  done
  case "$cls" in
    xss|sqli) ;;
    *) printf 'usage: recon-params confirm <xss|sqli> [host] [N] [--cookie "<c>"] [--header "<h>"]\n' >&2
       printf '  xss  — dalfox context-aware (break-out must EXECUTE, not merely reflect)\n' >&2
       printf '  sqli — SAFE %s vs %s differential (NEVER dumps data / never sqlmap)\n' "'" "''" >&2
       printf '  --cookie/--header — AUTHED: your OWN session (operator-initiated, SAFE, human-in-loop only)\n' >&2
       exit 2 ;;
  esac
  [[ -n "$AUTH_COOKIE$AUTH_HEADER" ]] && warn "confirm($cls): AUTHED mode — using operator-supplied session (SAFE primitives only; 2 owned accounts; never harvest)"
  [[ -z "$n" ]] && { [[ -n "$host" ]] && n=40 || n=30; }

  [[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down set — skipping confirm"; exit 0; }
  es_up || { warn "ES not reachable"; exit 1; }
  [[ -x "$QSREPLACE" ]] || { warn "qsreplace not found: $QSREPLACE"; exit 1; }

  # pull catalog URLs for the class (paying only, freshest first), optional host filter.
  local host_clause=""
  [[ -n "$host" ]] && host_clause=",{\"term\":{\"host\":\"$host\"}}"
  local resp
  resp="$(es -H 'Content-Type: application/json' -X POST "$ES_URL/$PARAMS_INDEX/_search" -d "{
    \"size\": $(( n * 6 )),
    \"_source\": [\"url\",\"host\",\"program\",\"payout_tier\",\"true_fresh\"],
    \"query\": {\"bool\": {\"filter\": [{\"term\": {\"vuln_classes\": \"$cls\"}}$host_clause],
                          \"must_not\": [{\"term\": {\"payout_tier\": \"none\"}},{\"term\":{\"live_status\":\"dead\"}}]}},
    \"sort\": [{\"true_fresh\": {\"order\": \"desc\"}}, {\"cataloged_at\": {\"order\": \"desc\"}}]
  }" 2>/dev/null)"
  if printf '%s' "$resp" | jq -e '.error' >/dev/null 2>&1; then
    warn "confirm: ES error: $(printf '%s' "$resp" | jq -r '.error.root_cause[0].reason // .error.reason' 2>/dev/null)"; exit 1
  fi
  local total; total="$(printf '%s' "$resp" | jq -r '.hits.total.value // 0' 2>/dev/null)"

  local WORK; WORK="$(mktemp -d)"; trap '[[ -n "${WORK:-}" ]] && rm -rf "$WORK"' EXIT
  printf '%s' "$resp" \
    | jq -r '.hits.hits[]?._source | [.url,(.program//"?"),(.payout_tier//"?"),(if .true_fresh then "FRESH" else "" end)] | @tsv' \
    2>/dev/null > "$WORK/raw.tsv"

  # param-set dedup: collapse N category pages sharing the same param surface to one rep
  # (numeric path-IDs normalized), so confirm tests the surface once. Mirrors the ranker.
  python3 - "$WORK/raw.tsv" > "$WORK/urls.tsv" <<'PY'
import sys, re
from urllib.parse import urlsplit, parse_qsl
seen=set()
for line in open(sys.argv[1]):
    parts=line.rstrip("\n").split("\t")
    if not parts or not parts[0]: continue
    sp=urlsplit(parts[0])
    names=frozenset(k.lower() for k,_ in parse_qsl(sp.query))
    if not names: continue
    key=(sp.netloc, re.sub(r"/\d{2,}","/{id}",sp.path), names)
    if key in seen: continue
    seen.add(key); sys.stdout.write(line)
PY
  head -n "$n" "$WORK/urls.tsv" > "$WORK/urls.head.tsv" && mv "$WORK/urls.head.tsv" "$WORK/urls.tsv"
  cut -f1 "$WORK/urls.tsv" > "$WORK/urls.txt"
  local url_count; url_count="$(wc -l < "$WORK/urls.tsv" | tr -d ' ')"
  [[ "${url_count:-0}" -gt 0 ]] || { log "confirm($cls): no catalog URLs${host:+ for $host} — run collect first"; exit 0; }
  log "confirm($cls): ${url_count} deduped param-surfaces${host:+ on $host} (of $total catalog URLs)"

  local out_file="$PARAMS_DIR/confirm_${cls}.jsonl"; mkdir -p "$PARAMS_DIR"
  local ua='Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0'

  if [[ "$cls" == "xss" ]]; then
    [[ -x "$DALFOX" ]] || { warn "dalfox not found ($DALFOX) — install it; no naive-canary fallback (it mislabels reflection as confirmed)"; exit 1; }
    log "confirm(xss): dalfox, ${DALFOX_DELAY}ms delay, 1 worker, GET-only, mining off (polite)"
    # dalfox pipe: test ONLY the given params (--skip-mining-all), no basic-other-vuln
    # noise (--skip-bav), GET, rate-limited. --silence prints only PoCs. A [POC] line =
    # dalfox VERIFIED the payload reflects executably (its own headless check), not bare
    # reflection — this is the real confirmation the old canary check lacked.
    # --waf-evasion: on WAF detection dalfox self-throttles (worker=1, 3s delay) so a confirm
    #   run never gets the shared Mullvad exit WAF-banned (anti-burn; harmless when no WAF).
    local dfx_auth=()
    [[ -n "$AUTH_COOKIE" ]] && dfx_auth+=(--cookie "$AUTH_COOKIE")
    [[ -n "$AUTH_HEADER" ]] && dfx_auth+=(--header "$AUTH_HEADER")
    "$DALFOX" pipe --silence --no-color --no-spinner --skip-bav --skip-mining-all --waf-evasion \
      --delay "$DALFOX_DELAY" --worker 1 --timeout 12 --user-agent "$ua" "${dfx_auth[@]}" \
      --format plain < "$WORK/urls.txt" 2>/dev/null | tee "$WORK/dalfox.raw" || true
    # FP GATE (recon_xss_poc_verify.py): dalfox's headless check false-positives on inert
    # reflections — Next.js RSC path echoes (self.__next_f.push on the __next_error__ page),
    # WAF-403'd payloads, JSON-nosniff / encoded reflections. Re-fetch each PoC and keep only
    # those with a genuine unencoded break-out. Drops logged to stderr; survivors → dalfox.out.
    # (Verified FP 2026-07-17: hmh247.org /wp-json/oembed, 6 dalfox PoC all inert.)
    local POC_VERIFY="${POC_VERIFY:-$SCRIPT_DIR/recon_xss_poc_verify.py}"
    if [[ -f "$POC_VERIFY" ]] && grep -qE '\[POC\]' "$WORK/dalfox.raw" 2>/dev/null; then
      grep -E '\[POC\]' "$WORK/dalfox.raw" | python3 "$POC_VERIFY" > "$WORK/dalfox.out" 2>>"$STATE_DIR/xss_poc_verify.log" || cp "$WORK/dalfox.raw" "$WORK/dalfox.out"
    else
      cp "$WORK/dalfox.raw" "$WORK/dalfox.out"
    fi
    # grep -c prints 0 AND exits 1 on no-match; a trailing "|| echo 0" would append a 2nd 0
    # (pocs="0\n0") and break the arithmetic test — count safely instead.
    local pocs; pocs="$(grep -cE '\[POC\]' "$WORK/dalfox.out" 2>/dev/null)"; pocs="${pocs//[^0-9]/}"; pocs="${pocs:-0}"
    if [[ "${pocs:-0}" -gt 0 ]]; then
      grep -E '\[POC\]' "$WORK/dalfox.out" | while IFS= read -r poc; do
        jq -nc --arg p "$poc" --arg c xss --arg ts "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
          '{poc:$p, class:$c, confirmed:true, engine:"dalfox", confirmed_at:$ts}' >> "$out_file" 2>/dev/null || true
      done
    fi
    printf -- '--- confirm(xss): %s dalfox PoC(s) / %s surfaces probed ---\n' "$pocs" "$url_count" >&2
    [[ "${pocs:-0}" -gt 0 ]] && printf '    saved → %s  (CLAUDE VERIFY before any report)\n' "$out_file" >&2
    return 0
  fi

  # ---- SQLi: SAFE ' vs '' differential (doctrine: injectable-or-not, never a harvest) ----
  local sqli_re='SQL syntax|mysql_num_rows|ORA-[0-9]+|SQLSTATE|You have an error in your SQL|Microsoft OLE DB|ODBC SQL Server|Warning.*mysql_|Unclosed quotation mark|quoted string not properly terminated|pg_query\(\)|supplied argument is not a valid MySQL|PostgreSQL.*ERROR|SQLite/JDBCDriver|valid PostgreSQL result'
  # AUTHED session (operator-supplied) threaded into the SAFE GETs — still read-only/no-harvest.
  local curl_auth=()
  [[ -n "$AUTH_COOKIE" ]] && curl_auth+=(-H "Cookie: $AUTH_COOKIE")
  [[ -n "$AUTH_HEADER" ]] && curl_auth+=(-H "$AUTH_HEADER")
  local hits=0 checked=0
  while IFS=$'\t' read -r url program tier fresh_tag; do
    [[ -z "$url" ]] && continue
    checked=$((checked+1))
    # set ALL param values to a numeric baseline, then a single-quote inject, then an
    # escaped (doubled) control. Error on inject but NOT on control, or a length swing
    # back to baseline on control = the quote reached SQL = injectable (SAFE: 3 GETs, no data).
    local u_base u_inj u_ctl
    u_base="$(printf '%s\n' "$url" | "$QSREPLACE" "1"   2>/dev/null)"
    u_inj="$( printf '%s\n' "$url" | "$QSREPLACE" "1'"  2>/dev/null)"
    u_ctl="$( printf '%s\n' "$url" | "$QSREPLACE" "1''" 2>/dev/null)"
    [[ -z "$u_inj" ]] && continue
    sleep "0.$(( RANDOM % 6 + 3 ))"
    local b_base b_inj b_ctl
    b_base="$(curl -sS -m10 -k -A "$ua" "${curl_auth[@]}" "$u_base" 2>/dev/null | head -c 200000)"
    b_inj="$( curl -sS -m10 -k -A "$ua" "${curl_auth[@]}" "$u_inj"  2>/dev/null | head -c 200000)"
    b_ctl="$( curl -sS -m10 -k -A "$ua" "${curl_auth[@]}" "$u_ctl"  2>/dev/null | head -c 200000)"
    local status=""
    if printf '%s' "$b_inj" | grep -qiE "$sqli_re" && ! printf '%s' "$b_base" | grep -qiE "$sqli_re"; then
      status="error-based"
    else
      # boolean/length differential: inject differs from baseline, control returns to baseline
      local lb li lc; lb="${#b_base}"; li="${#b_inj}"; lc="${#b_ctl}"
      local d_bi=$(( li>lb ? li-lb : lb-li )); local d_bc=$(( lc>lb ? lc-lb : lb-lc ))
      # significant swing on ' (>500 bytes & >2%) that the '' control recovers from
      if (( d_bi > 500 )) && (( d_bi * 50 > lb )) && (( d_bc * 4 < d_bi )); then
        status="boolean-diff"
      fi
    fi
    if [[ -n "$status" ]]; then
      hits=$((hits+1))
      printf '[SQLI %s]  %s [%s]  %s\n' "$status" "$program" "$tier" "$u_inj"
      jq -nc --arg u "$url" --arg p "$u_inj" --arg c sqli --arg pr "$program" --arg ti "$tier" \
             --arg fr "$fresh_tag" --arg st "$status" --arg ts "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
        '{url:$u, probe_url:$p, class:$c, program:$pr, tier:$ti, fresh:($fr=="FRESH"), status:$st, confirmed:true, method:"safe-differential", confirmed_at:$ts}' \
        >> "$out_file" 2>/dev/null || true
    fi
  done < "$WORK/urls.tsv"
  printf -- '--- confirm(sqli): %s injectable / %s probed (SAFE diff; never a data harvest) ---\n' "$hits" "$checked" >&2
  [[ "$hits" -gt 0 ]] && printf '    saved → %s  (CLAUDE VERIFY before any report)\n' "$out_file" >&2
}

# ---------------------------------------------------------------------------
# LIVENESS VERIFIER — archive URLs (wayback/gau) are historical; many are dead 404s.
# Probe a bounded batch of catalog URLs (deduped by path so it's one probe per page, not
# per param-variant), KEEP the live (mark live_status/live_checked_at), DELETE the dead so
# only worth-keeping params remain. Target-facing → invoked via run_scanner (egress slot +
# vpn gate); per-probe jitter keeps it gentle. Robust: loud ES-error detection, transient
# failures (000/5xx/timeout) are left for retry — NEVER deleted on a flaky probe.
cmd_verify_live() {
  [[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down set — skipping verify-live"; exit 0; }
  es_up || { warn "ES not reachable"; exit 0; }
  exec 9>"$STATE_DIR/params_live.lock"; flock -n 9 || { warn "params verify-live already running"; exit 0; }
  python3 -c "import fcntl;fcntl.fcntl(9,fcntl.F_SETFD,fcntl.FD_CLOEXEC)" 2>/dev/null || true
  # ensure the liveness fields are mapped (idempotent, additive)
  es -fsS -X PUT "$ES_URL/$PARAMS_INDEX/_mapping" -H 'Content-Type: application/json' \
    -d '{"properties":{"live_status":{"type":"keyword"},"live_checked_at":{"type":"date"}}}' >/dev/null 2>&1 || true

  local NOW_ISO CUTOFF_ISO
  NOW_ISO="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  CUTOFF_ISO="$(date -u -d "-${PARAMS_LIVE_TTL_DAYS} days" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo '1970-01-01T00:00:00Z')"

  # batch: never-checked OR checked > TTL ago; oldest/unchecked first
  local resp
  resp="$(es -H 'Content-Type: application/json' -X POST "$ES_URL/$PARAMS_INDEX/_search" -d "{
    \"size\": $PARAMS_LIVE_BATCH,
    \"_source\":[\"url\"],
    \"query\":{\"bool\":{\"should\":[
        {\"bool\":{\"must_not\":[{\"exists\":{\"field\":\"live_checked_at\"}}]}},
        {\"range\":{\"live_checked_at\":{\"lt\":\"$CUTOFF_ISO\"}}}
      ],\"minimum_should_match\":1}},
    \"sort\":[{\"live_checked_at\":{\"order\":\"asc\",\"missing\":\"_first\"}}]
  }" 2>/dev/null)" || { warn "ES query failed (curl)"; exit 0; }
  if printf '%s' "$resp" | jq -e '.error' >/dev/null 2>&1; then
    warn "verify-live ES error: $(printf '%s' "$resp" | jq -r '.error.root_cause[0].reason // .error.reason // .error.type' 2>/dev/null)"; exit 1
  fi

  WORK="$(mktemp -d)"; trap '[[ -n "${WORK:-}" ]] && rm -rf "$WORK"' EXIT
  printf '%s' "$resp" | jq -rc '.hits.hits[]? | [._id, ._source.url] | @tsv' 2>/dev/null > "$WORK/batch.tsv"
  local n; n="$(wc -l < "$WORK/batch.tsv" | tr -d ' ')"
  [[ "${n:-0}" -gt 0 ]] || { log "verify-live: nothing to check"; exit 0; }

  local ua='Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0'
  : > "$WORK/bulk.ndjson"
  declare -A PATHRES
  local alive=0 dead=0 trans=0 probed=0
  while IFS=$'\t' read -r id url; do
    [[ -z "$id" || -z "$url" ]] && continue
    [[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down mid-run — halting verify-live"; break; }
    local pk="${url%%\?*}"
    local res="${PATHRES[$pk]:-}"
    if [[ -z "$res" ]]; then
      sleep "0.$(( RANDOM % 5 + 2 ))"   # min-gap jitter (anti-burn)
      local code
      code="$(curl -sS -m"$PARAMS_LIVE_TIMEOUT" -k -I -A "$ua" -o /dev/null -w '%{http_code}' "$pk" 2>/dev/null)"
      case "$code" in 000|405|501|""|400) code="$(curl -sS -m"$PARAMS_LIVE_TIMEOUT" -k -A "$ua" -o /dev/null -w '%{http_code}' "$pk" 2>/dev/null)" ;; esac
      case "$code" in
        2[0-9][0-9]|301|302|303|307|308|401|403|429) res=alive ;;
        404|410)                                     res=dead  ;;
        *)                                           res=trans ;;   # 000/5xx/timeout → retry later, do NOT delete
      esac
      PATHRES[$pk]="$res"; probed=$((probed+1))
    fi
    case "$res" in
      alive) printf '{"update":{"_id":"%s"}}\n{"doc":{"live_status":"alive","live_checked_at":"%s"}}\n' "$id" "$NOW_ISO" >> "$WORK/bulk.ndjson"; alive=$((alive+1)) ;;
      dead)  printf '{"delete":{"_id":"%s"}}\n' "$id" >> "$WORK/bulk.ndjson"; dead=$((dead+1)) ;;
      trans) trans=$((trans+1)) ;;
    esac
  done < "$WORK/batch.tsv"

  local applied=0
  if [[ -s "$WORK/bulk.ndjson" ]]; then
    local br; br="$(es -H 'Content-Type: application/x-ndjson' -X POST "$ES_URL/$PARAMS_INDEX/_bulk" --data-binary @"$WORK/bulk.ndjson" 2>/dev/null)"
    applied="$(printf '%s' "$br" | jq '[.items[]?|(.update//.delete)|select(.result=="updated" or .result=="deleted")]|length' 2>/dev/null || echo 0)"
    local errs; errs="$(printf '%s' "$br" | jq -r '[.items[]?|(.update//.delete)|select(.error)|.error.reason]|unique|.[:3]|join(" | ")' 2>/dev/null)"
    [[ -n "$errs" ]] && warn "verify-live bulk errors: $errs"
  fi
  log "verify-live: $alive alive / $dead dead(deleted) / $trans transient · $probed pages probed · $applied catalog ops"
}

# one-shot: refill the queue, then crawl ONE job. Manual convenience AND the
# compatibility path for a not-yet-restarted daemon still invoking `collect`
# (zero-downtime migration to the split enqueue/crawl loops). Separate processes
# so each keeps its own lock/exit semantics.
cmd_collect() { bash "$0" enqueue || true; bash "$0" crawl || true; }

# on-demand SINGLE-HOST crawl — the hunt's queue-bypass. When the hunt finds an interesting
# host (tech-match for a param class: XSS/SQLi/…), crawl it NOW for its live param surface
# instead of waiting for the sliding-window producer to reach it. Same engine as the daemon
# (katana + gau-passive + Wayback-CDX-via-proxy → gf-classify → catalog), just aimed at one
# host. Pulls scope metadata (program/tier/root/fresh) from recon_alive so the catalog entry
# is correct, indexes it, and PRINTS the discovered param-URLs per class so a confirm can run
# immediately. Target-facing (katana) → Mullvad-gated + rate-limited like the daemon path.
cmd_crawl_host() {
  local host="" url="" a AUTH_COOKIE="" AUTH_HEADER=""
  while [[ $# -gt 0 ]]; do
    a="$1"
    case "$a" in
      --cookie) AUTH_COOKIE="${2:-}"; shift 2 || true ;;
      --cookie=*) AUTH_COOKIE="${a#--cookie=}"; shift ;;
      --header) AUTH_HEADER="${2:-}"; shift 2 || true ;;
      --header=*) AUTH_HEADER="${a#--header=}"; shift ;;
      --arjun) export PARAMS_ARJUN=1; shift ;;
      *) if [[ -z "$host" ]]; then host="$a"; elif [[ -z "$url" ]]; then url="$a"; fi; shift ;;
    esac
  done
  [[ -n "$host" ]] || { warn "usage: recon_params.sh crawl-host <host> [url] [--cookie \"<c>\"] [--header \"<h>\"] [--arjun]"; exit 2; }
  [[ "${PARAMS_ARJUN:-0}" == "1" ]] && { [[ -n "$ARJUN" && -x "$ARJUN" ]] || { warn "--arjun requested but arjun not installed (pip install arjun)"; exit 1; }; }
  for t in "$KATANA" "$GF"; do [[ -x "$t" ]] || { warn "missing tool: $t"; exit 1; }; done
  [[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down set — skipping crawl-host"; exit 0; }
  es_up || { warn "ES not reachable"; exit 1; }
  ensure_index; ensure_alive_field
  # AUTHED crawl (operator's OWN session) — human-in-the-loop only, exported to crawl_host's katana.
  [[ -n "$AUTH_COOKIE" ]] && export KATANA_AUTH_HEADER="Cookie: $AUTH_COOKIE"
  [[ -n "$AUTH_HEADER" ]] && export KATANA_AUTH_HEADER="$AUTH_HEADER"
  [[ -n "${KATANA_AUTH_HEADER:-}" ]] && warn "crawl-host: AUTHED crawl — operator session (2 owned accounts; read-only discovery)"

  # scope metadata from recon_alive (so the catalog entry carries the right program/tier/root)
  local hit root program tier fresh fseen
  hit="$(es -H 'Content-Type: application/json' -X POST "$ES_URL/$INDEX_NAME/_search" -d "{
    \"size\":1,\"_source\":[\"url\",\"root_domain\",\"triage_program\",\"triage_payout_tier\",\"triage_true_fresh\",\"first_seen\"],
    \"query\":{\"term\":{\"host\":\"$host\"}}}" 2>/dev/null | jq -c '.hits.hits[0]._source // {}' 2>/dev/null)"
  [[ -z "$url" ]] && url="$(printf '%s' "$hit" | jq -r '.url // empty' 2>/dev/null)"
  [[ -n "$url" ]] || url="https://$host"
  root="$(printf '%s' "$hit" | jq -r '.root_domain // empty' 2>/dev/null)"; [[ -n "$root" ]] || root="$host"
  program="$(printf '%s' "$hit" | jq -r '.triage_program // empty' 2>/dev/null)"
  tier="$(printf '%s' "$hit" | jq -r '.triage_payout_tier // "none"' 2>/dev/null)"
  fresh="$(printf '%s' "$hit" | jq -r '(.triage_true_fresh // false)|tostring' 2>/dev/null)"
  fseen="$(printf '%s' "$hit" | jq -r '.first_seen // empty' 2>/dev/null)"

  WORK="$(mktemp -d)"; trap '[[ -n "${WORK:-}" ]] && rm -rf "$WORK"' EXIT
  log "crawl-host: $host ($url) program=${program:-?} tier=$tier — ON-DEMAND (queue bypass)"
  crawl_host "$host" "$url" "$root" "$program" "$tier" "$fresh" "$fseen" "$WORK"
  local indexed; indexed="$(index_workdir "$WORK")"
  log "crawl-host: indexed $indexed catalog entries for $host"

  # surface what we found, grouped by class, so the hunt can confirm right away
  local cls f n
  printf -- '--- discovered param-URLs by class (%s) ---\n' "$host" >&2
  local any=0
  for cls in $PARAMS_CLASSES; do
    f="$(cat "$WORK"/*/cls."$cls" 2>/dev/null | sort -u)"
    [[ -n "$f" ]] || continue
    n="$(printf '%s\n' "$f" | grep -c .)"
    printf '[%s] %s surface(s):\n' "$cls" "$n" >&2
    printf '%s\n' "$f" | head -30 >&2
    any=1
  done
  [[ "$any" -eq 0 ]] && printf '  (no param URLs discovered — host may be login-walled / SPA / no linked params)\n' >&2
}

case "${1:-}" in
  enqueue)        shift; cmd_enqueue "$@" ;;
  crawl)          shift; cmd_crawl "$@" ;;
  crawl-host)     shift; cmd_crawl_host "$@" ;;
  arjun)          shift; cmd_crawl_host "$@" --arjun ;;   # crawl-host + ACTIVE hidden-param discovery
  collect)        shift; cmd_collect "$@" ;;
  verify-live)    shift; cmd_verify_live "$@" ;;
  list)           shift; cmd_list "$@" ;;
  confirm|verify) shift; cmd_confirm "$@" ;;   # verify = back-compat alias for confirm
  candidates)     shift; exec python3 "$SCRIPT_DIR/recon_xss_sqli_candidates.py" "$@" ;;
  *) echo "usage: recon_params.sh {enqueue | crawl | crawl-host <host> [url] [--cookie/--header] | collect | verify-live | list <class> [N] | confirm <xss|sqli> [host] [N] [--cookie/--header] | candidates [--class xss|sqli|both]}" >&2; exit 2 ;;
esac

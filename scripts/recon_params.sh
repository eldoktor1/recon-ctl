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
GF="${GF:-$(command -v gf 2>/dev/null || echo "$GOBIN/gf")}"; QSREPLACE="${QSREPLACE:-$GOBIN/qsreplace}"

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
PARAMS_CANDIDATE_POOL="${PARAMS_CANDIDATE_POOL:-30000}"  # candidate reach (search_after-paged). MUST be deep: ephemeral/CI junk scores HIGH so it clusters in the top ~10k (measured ~77% junk there), while real param-bearing web apps sit DEEPER (a 40k sample was ~77% real post-filter). A shallow pool only ever sees the junk tier → ~0-yield crawls. Only queried when the queue has room (backpressure-gated), so the deeper pull is cheap. Server-side cooldown range still slides the window through the ~600k pool.
PARAMS_INTER_HOST_SLEEP="${PARAMS_INTER_HOST_SLEEP:-5}"   # max pre-gau jitter (provider stealth)
KATANA_DEPTH="${KATANA_DEPTH:-2}"
KATANA_CRAWL_TIMEOUT="${KATANA_CRAWL_TIMEOUT:-90}"
KATANA_RL="${KATANA_RL:-15}"
GAU_TIMEOUT="${GAU_TIMEOUT:-30}"    # otx+urlscan are fast; 30s is ample; 60 wasted when providers blocked
MAX_URLS_PER_HOST="${PARAMS_MAX_URLS_PER_HOST:-2000}"
PARAMS_SCANNED_FIELD="${PARAMS_SCANNED_FIELD:-params_scanned_at}"   # recon_alive date field = per-host cooldown ledger (ES source of truth)
# Archive proxy (Cloudflare worker) — restores Wayback CDX param-URL discovery that the
# Internet Archive blocks from our Mullvad datacenter egress (it blackholes wayback for
# VPN/DC ranges). URL + secret live in FILES, never git: ~/.recon_cdx_url, ~/.recon_cdx_key.
# Empty ⇒ archive_fetch is a no-op (katana-only). Only the public-archive lookup egresses
# via Cloudflare; the bug-bounty host is NEVER contacted by it. Be gentle — don't burn the CF
# path: the per-host 7d cooldown means each host hits wayback ~once/7d, and the worker caches.
PARAMS_ARCHIVE_URL="${PARAMS_ARCHIVE_URL:-$(tr -d '\r\n' < "$HOME/.recon_cdx_url" 2>/dev/null)}"
PARAMS_ARCHIVE_KEY="${PARAMS_ARCHIVE_KEY:-$(tr -d '\r\n' < "$HOME/.recon_cdx_key" 2>/dev/null)}"
PARAMS_ARCHIVE_TIMEOUT="${PARAMS_ARCHIVE_TIMEOUT:-30}"

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
  { timeout "$KATANA_CRAWL_TIMEOUT" "$KATANA" -u "$url" -d "$KATANA_DEPTH" -jc -fs rdn -silent -nc -rl "$KATANA_RL" 2>/dev/null
    # gau: otx+urlscan only — wayback (web.archive.org) + commoncrawl block our Mullvad
    # egress, so asking gau for them just burns the timeout. Wayback comes via the worker.
    [[ -x "$GAU" ]] && printf '%s\n' "$host" | timeout "$GAU_TIMEOUT" "$GAU" --providers otx,urlscan --threads 5 --subs 2>/dev/null
    # Wayback CDX archive URLs, proxied through Cloudflare (escapes IA's Mullvad block).
    archive_fetch "$host"
  } | grep -E '^https?://' | grep -F '?' | sort -u | head -n "$MAX_URLS_PER_HOST" > "$hd/raw" || true
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
      \"query\":{\"bool\":{\"filter\":[{\"term\":{\"triage_in_scope\":true}},{\"term\":{\"triage_pays\":true}}],\"must_not\":[{\"term\":{\"triage_out_of_scope\":true}},{\"range\":{\"$PARAMS_SCANNED_FIELD\":{\"gte\":\"now-${PARAMS_COOLDOWN_DAYS}d\"}}}]}},
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

  # Diversity: cap hosts per root_domain so one program (e.g. 15 airbnb locale
  # subdomains) can't consume the entire 20-host cycle.
  local MAX_PER_ROOT="${PARAMS_MAX_PER_ROOT:-3}"
  awk -F'\t' -v m="$MAX_PER_ROOT" '{if(++seen[$3]<=m)print}' "$WORK/cand.tsv" > "$WORK/cand_div.tsv"

  # Filter out hosts that are structurally useless for URL-archive lookups:
  #   - UUID-named cloud infra (unifi-hosting, etc.) — no public URL history
  #   - mta-sts.* — MTA-STS policy records, not web apps
  #   - cdn-*.* / assets.* / static.* — CDN edge nodes
  #   - *.api.* where the subdomain itself starts with an API path fragment
  # These consume GAU quota and always return 0; skipping them saves rate limit.
  # PHASE 5: also drop host shapes with no GET-parameter web surface — API/RPC
  # endpoints (POST/JSON, no GET params), device/IoT/message brokers, and mail/DNS
  # records. They have no archive param-URLs, index 0, and burn GAU quota.
  #
  # EPHEMERAL/NON-PROD filter (2026-06-13): the leftmost-label rules above missed
  # dev/test/staging/qa/preprod/CI hosts whose marker is EMBEDDED (e.g.
  # foo.staging.runnr.in, nginx-ingress-test-92224.ea-ci-systems-dev.elastic.dev,
  # thanos-...-preprod-...). Measured: ~77% of the top uncooled candidate field was
  # this junk — zero param surface, so the consumer ground out 0-yield jobs while
  # real hosts waited. Match the markers as whole DNS labels / hyphen-tokens
  # ((^|[.-])marker([.-]|$)) so we never substring-FP a real host (e.g. "developers",
  # "latest", "investor" are NOT matched). Out-of-scope corp/internal infra is caught
  # here too as a side effect.
  grep -vE '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.' \
       "$WORK/cand_div.tsv" \
  | grep -vE '^(mta-sts|cdn-[0-9]|assets\.|static\.|media\.)' \
  | grep -vE '^(api|apis|graphql|grpc|gql|mqtt|push|device|devices|iot|broker|smtp|imap|pop3?|mx[0-9]*|ns[0-9]+|dns)[.-]' \
  | grep -vE '^(auth|login|signin|sso|oauth|oidc|idp|saml|adfs|keycloak|prometheus|alertmanager|grafana|metrics|daemon|repo|repos|registry|artifactory|nexus)[.-]' \
  | grep -viE '(^|[.-])(dev|test|tests|testing|qa|uat|sit|stg|stage|staging|preprod|prprd|nonprod|sandbox|sbx|demo|preview|storybook|ephemeral|internal|intranet|corp|canary|perf|loadtest|feature|pr[0-9]+)([.-]|$)' \
  > "$WORK/cand.tsv"
  rm -f "$WORK/cand_div.tsv"

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
cmd_verify() {
  local cls="${1:-}" n="${2:-50}"
  case "$cls" in
    xss|sqli) ;;
    "")
      printf 'usage: recon-params verify <xss|sqli> [N]\n' >&2
      printf '  xss  — inject d0k_recon canary, check if param reflects it in response\n' >&2
      printf '  sqli — inject '"'"''"'"' payload, check response for DB error signatures\n' >&2
      exit 2
      ;;
    *) printf 'verify supports: xss sqli\n' >&2; exit 2 ;;
  esac
  [[ "$n" =~ ^[0-9]+$ ]] || n=50

  [[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down set — skipping verify"; exit 0; }
  es_up || { warn "ES not reachable"; exit 1; }
  [[ -x "$QSREPLACE" ]] || { warn "qsreplace not found: $QSREPLACE"; exit 1; }

  local resp
  # scope discipline: only probe PAYING catalog targets (payout_tier != none), freshest first
  resp="$(es -H 'Content-Type: application/json' -X POST "$ES_URL/$PARAMS_INDEX/_search" -d "{
    \"size\": $n,
    \"_source\": [\"url\",\"program\",\"payout_tier\",\"true_fresh\"],
    \"query\": {\"bool\": {\"filter\": [{\"term\": {\"vuln_classes\": \"$cls\"}}],
                          \"must_not\": [{\"term\": {\"payout_tier\": \"none\"}}]}},
    \"sort\": [{\"true_fresh\": {\"order\": \"desc\"}}, {\"cataloged_at\": {\"order\": \"desc\"}}]
  }" 2>/dev/null)"

  local total; total="$(printf '%s' "$resp" | jq -r '.hits.total.value // 0' 2>/dev/null)"
  local WORK; WORK="$(mktemp -d)"; trap '[[ -n "${WORK:-}" ]] && rm -rf "$WORK"' EXIT
  printf '%s' "$resp" \
    | jq -r '.hits.hits[]?._source | [.url, (.program//"?"), (.payout_tier//"?"), (if .true_fresh then "FRESH" else "" end)] | @tsv' \
    2>/dev/null > "$WORK/urls.tsv"

  local url_count; url_count="$(wc -l < "$WORK/urls.tsv" | tr -d ' ')"
  if [[ "$url_count" -eq 0 ]]; then
    log "verify($cls): no URLs in catalog — run collect first"
    exit 0
  fi
  log "verify($cls): probing $url_count / $total catalog entries"

  local canary="d0kxss"
  local sqli_re='SQL syntax|mysql_num_rows|ORA-[0-9]+|SQLSTATE|You have an error in your SQL|Microsoft OLE DB|ODBC SQL Server|Warning.*mysql_|Unclosed quotation mark|quoted string not properly terminated|pg_query\(\)|supplied argument is not a valid MySQL'
  local ua='Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0'
  local out_file="$PARAMS_DIR/verify_${cls}.jsonl"
  mkdir -p "$PARAMS_DIR"

  local hits=0 checked=0
  while IFS=$'\t' read -r url program tier fresh_tag; do
    [[ -z "$url" ]] && continue
    checked=$((checked+1))

    local probe_url payload
    case "$cls" in
      # PHASE 4 — XSS must BREAK OUT of context, not merely reflect. Inject a
      # payload that closes common contexts and opens a UNIQUE tag <d0kxss>. If
      # that tag survives UNENCODED in the response it is an executable HTML
      # injection (CONFIRMED). If only the bare marker reflects (angle brackets
      # entity-encoded), it is reflected-not-exploitable (LEAD, never CONFIRMED).
      xss)  payload="'\"></script><${canary}>"
            probe_url="$(printf '%s\n' "$url" | "$QSREPLACE" "$payload" 2>/dev/null)" ;;
      sqli) probe_url="$(printf '%s\n' "$url" | "$QSREPLACE" "'" 2>/dev/null)" ;;
    esac
    [[ -z "$probe_url" ]] && continue

    # anti-burn: min-gap + jitter between probes so the single Mullvad egress IP isn't
    # hammered (the loop spans many hosts; this keeps the aggregate request rate polite).
    sleep "0.$(( RANDOM % 6 + 2 ))"

    local body
    body="$(curl -sS -m10 -k -L --max-redirs 2 -A "$ua" "$probe_url" 2>/dev/null | head -c 65536)"

    local hit=0 status="confirmed"
    case "$cls" in
      xss)
        if printf '%s' "$body" | grep -qiF "<${canary}>"; then hit=1; status="confirmed"
        elif printf '%s' "$body" | grep -qiF "$canary"; then hit=1; status="reflected-not-exploitable"
        fi ;;
      sqli) printf '%s' "$body" | grep -qiE "$sqli_re" && hit=1 ;;
    esac

    if [[ "$hit" -eq 1 ]]; then
      local label
      if [[ "$status" == "confirmed" ]]; then
        hits=$((hits+1)); label="[${cls^^} CONFIRMED]"
      else
        # LEAD — reflected but break-out chars were encoded; not exploitable, not counted
        label="[${cls^^} reflected-not-exploitable]"
      fi
      [[ "$fresh_tag" == "FRESH" ]] && label="$label [FRESH]"
      printf '%s  %s [%s]  %s\n' "$label" "$program" "$tier" "$probe_url"
      jq -nc --arg u "$url" --arg p "$probe_url" --arg c "$cls" \
             --arg pr "$program" --arg ti "$tier" --arg fr "$fresh_tag" \
             --arg st "$status" \
             --arg ts "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
        '{url:$u, probe_url:$p, class:$c, program:$pr, tier:$ti, fresh:($fr=="FRESH"), status:$st, confirmed:($st=="confirmed"), confirmed_at:$ts}' \
        >> "$out_file" 2>/dev/null || true
    fi

    sleep 0.3
  done < "$WORK/urls.tsv"

  printf -- '--- verify(%s): %s confirmed / %s probed  (catalog total: %s) ---\n' \
    "$cls" "$hits" "$checked" "$total" >&2
  [[ "$hits" -gt 0 ]] && printf '    saved → %s\n' "$out_file" >&2
}

# one-shot: refill the queue, then crawl ONE job. Manual convenience AND the
# compatibility path for a not-yet-restarted daemon still invoking `collect`
# (zero-downtime migration to the split enqueue/crawl loops). Separate processes
# so each keeps its own lock/exit semantics.
cmd_collect() { bash "$0" enqueue || true; bash "$0" crawl || true; }

case "${1:-}" in
  enqueue) shift; cmd_enqueue "$@" ;;
  crawl)   shift; cmd_crawl "$@" ;;
  collect) shift; cmd_collect "$@" ;;
  list)    shift; cmd_list "$@" ;;
  verify)  shift; cmd_verify "$@" ;;
  *) echo "usage: recon_params.sh {enqueue | crawl | collect | list <class> [N] | verify <xss|sqli> [N]}" >&2; exit 2 ;;
esac

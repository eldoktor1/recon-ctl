#!/usr/bin/env bash
# =============================================================================
# recon_params.sh — sus_params targeting catalog (g0ldencybersec gf-patterns)
#
# A queryable inventory of IN-SCOPE-PAYING URLs-with-parameters, classified by
# vuln class, so you can pull "all in-scope SQLi targets" / "all XSS targets" on
# demand — for manual hunting or feeding sqlmap/dalfox/nuclei.
#
#   collect        crawl in-scope-paying hosts (FRESH-FIRST), gf-classify their
#                  parameterised URLs, store per-class files + ES recon_params
#                  index. Bounded per run; 7d per-host cooldown. (daemon loop /
#                  manual). Target-facing → run as reconrun via Mullvad.
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
# v3.2 throughput (balanced): the serial 10-host/cycle loop covered only ~13 hosts/day
# (0.05% of in-scope), starving the confirmers. Parallelise the per-host crawl PARAM_PARALLEL-wide
# and raise hosts/cycle — per-host rate limits (KATANA_RL, gau jitter) are unchanged so we
# buy throughput without becoming aggressive (the article's ban cautionary tale).
PARAMS_HOSTS_PER_CYCLE="${PARAMS_HOSTS_PER_CYCLE:-30}"
PARAM_PARALLEL="${PARAM_PARALLEL:-5}"           # balanced safe-max: concurrent per-host crawls (each per-host rate-limited)
PARAMS_COOLDOWN_DAYS="${PARAMS_COOLDOWN_DAYS:-7}"
PARAMS_ZERO_COOLDOWN_DAYS="${PARAMS_ZERO_COOLDOWN_DAYS:-30}"   # param-POOR hosts: long cooldown so they don't hog the cycle (was a 6h re-crawl that starved new-host discovery)
PARAMS_CANDIDATE_POOL="${PARAMS_CANDIDATE_POOL:-3000}"   # was 1200: too shallow once the 30d zero-param cooldown parks the top hosts → cycles starved to 1-5; reach deeper for un-cooled candidates
PARAMS_INTER_HOST_SLEEP="${PARAMS_INTER_HOST_SLEEP:-5}"   # max pre-gau jitter (provider stealth)
WAYBACKURLS="${WAYBACKURLS:-$(command -v waybackurls 2>/dev/null || echo '')}"  # gau fallback
KATANA_DEPTH="${KATANA_DEPTH:-2}"
KATANA_CRAWL_TIMEOUT="${KATANA_CRAWL_TIMEOUT:-90}"
KATANA_RL="${KATANA_RL:-15}"
GAU_TIMEOUT="${GAU_TIMEOUT:-30}"    # otx+urlscan are fast; 30s is ample; 60 wasted when providers blocked
MAX_URLS_PER_HOST="${PARAMS_MAX_URLS_PER_HOST:-2000}"
SCANNED_FILE="$STATE_DIR/.params_scanned.tsv"

mkdir -p "$PARAMS_DIR" "$STATE_DIR"
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

# crawl_host — all per-host work, writing ONLY into its own dir under $wd so N copies
# run concurrently without clobbering shared files. Emits: bulk.part (ndjson), scanned
# (cooldown marker), cls.<class> (per-class URLs), urlcount. katana(live)+gau(archive),
# waybackurls fallback when gau yields nothing. Target-facing; per-host rate-limited.
crawl_host() {
  local host="$1" url="$2" root="$3" program="$4" tier="$5" fresh="$6" fseen="$7" wd="$8"
  local hd="$wd/$(printf '%s' "$host" | tr '/:.' '___')"; mkdir -p "$hd"
  local now; now="$(date +%s)"
  sleep $(( (RANDOM % PARAMS_INTER_HOST_SLEEP) + 1 ))   # jitter so N parallel gau hits don't burst a provider
  { timeout "$KATANA_CRAWL_TIMEOUT" "$KATANA" -u "$url" -d "$KATANA_DEPTH" -jc -fs rdn -silent -nc -rl "$KATANA_RL" 2>/dev/null
    [[ -x "$GAU" ]] && printf '%s\n' "$host" | timeout "$GAU_TIMEOUT" "$GAU" --threads 5 --subs 2>/dev/null
  } | grep -E '^https?://' | grep -F '?' | sort -u | head -n "$MAX_URLS_PER_HOST" > "$hd/raw" || true
  local raw_n; raw_n="$(wc -l < "$hd/raw" 2>/dev/null | tr -d ' ')"
  # gau fallback: different archive provider when gau is rate-limited / empty
  if [[ "${raw_n:-0}" -eq 0 && -n "$WAYBACKURLS" ]]; then
    printf '%s\n' "$host" | timeout "$GAU_TIMEOUT" "$WAYBACKURLS" 2>/dev/null \
      | grep -E '^https?://' | grep -F '?' | sort -u | head -n "$MAX_URLS_PER_HOST" > "$hd/raw" || true
    raw_n="$(wc -l < "$hd/raw" 2>/dev/null | tr -d ' ')"
  fi
  log "  $host — ${raw_n:-0} param URLs"
  if [[ "${raw_n:-0}" -eq 0 ]]; then
    # param-POOR host (API/staging/SPA, no query-string surface): FUTURE-shift the scanned
    # stamp so it stays in cooldown for PARAMS_ZERO_COOLDOWN_DAYS. The old code shifted it
    # into the PAST (6h re-crawl), so high-score param-less hosts got re-crawled every cycle
    # and starved out new-host discovery — that's why the catalog plateaued. Now the budget
    # goes to hosts that actually yield params.
    printf '%s\t%s\n' "$(( now + (PARAMS_ZERO_COOLDOWN_DAYS - PARAMS_COOLDOWN_DAYS)*86400 ))" "$host" > "$hd/scanned"
    return 0
  fi
  if [[ -x "$QSREPLACE" ]]; then "$QSREPLACE" FUZZ < "$hd/raw" 2>/dev/null | sort -u > "$hd/urls"; else cp "$hd/raw" "$hd/urls" 2>/dev/null || : > "$hd/urls"; fi
  [[ -s "$hd/urls" ]] || { printf '%s\t%s\n' "$now" "$host" > "$hd/scanned"; return 0; }
  : > "$hd/classified.tsv"
  local cls
  for cls in $PARAMS_CLASSES; do "$GF" "$cls" < "$hd/urls" 2>/dev/null | sed "s|\$|\t$cls|" >> "$hd/classified.tsv"; done
  [[ -s "$hd/classified.tsv" ]] || { printf '%s\t%s\n' "$now" "$host" > "$hd/scanned"; return 0; }
  for cls in $PARAMS_CLASSES; do awk -F'\t' -v c="$cls" '$2==c{print $1}' "$hd/classified.tsv" > "$hd/cls.$cls" 2>/dev/null || true; done
  awk -F'\t' '{a[$1]=a[$1]","$2} END{for(u in a){sub(/^,/,"",a[u]); print u"\t"a[u]}}' "$hd/classified.tsv" \
  | while IFS=$'\t' read -r u classes; do
      local iso id; iso="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"; id="$(printf '%s' "$u" | sha1sum | cut -c1-40)"
      jq -nc --arg u "$u" --arg id "$id" --arg h "$host" --arg rd "$root" --arg pr "$program" --arg ti "$tier" \
            --argjson tf "${fresh:-false}" --arg fs "$fseen" --arg ca "$iso" --arg cl "$classes" \
        '{index:{_id:$id}}, {url:$u,host:$h,root_domain:$rd,vuln_classes:($cl|split(",")),program:$pr,payout_tier:$ti,true_fresh:$tf,first_seen:(if $fs=="" then null else $fs end),cataloged_at:$ca}' 2>/dev/null >> "$hd/bulk.part"
    done
  printf '%s\t%s\n' "$now" "$host" > "$hd/scanned"
  wc -l < "$hd/urls" | tr -d ' ' > "$hd/urlcount"
}

# ---------------------------------------------------------------------------
cmd_collect() {
  for t in "$KATANA" "$GF"; do [[ -x "$t" ]] || { warn "missing tool: $t"; exit 1; }; done
  # VPN gate — never crawl while the leak guard has tripped.
  [[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down set — skipping collect"; exit 0; }
  exec 9>"$LOCK_FILE"; flock -n 9 || { warn "params collect already running"; exit 0; }
  python3 -c "import fcntl;fcntl.fcntl(9,fcntl.F_SETFD,fcntl.FD_CLOEXEC)" 2>/dev/null || true
  es_up || { warn "ES not reachable"; exit 0; }
  ensure_index
  touch "$SCANNED_FILE"

  # Score-first in-scope-paying host candidates. Sorting by triage_score DESC
  # (not fresh-first) because GAU/web-archive coverage is what drives param
  # discovery — established high-signal hosts have years of crawl history;
  # CT-log-fresh UUID subdomains have zero. first_seen ASC as tiebreaker so
  # older hosts (more archive data) beat equally-scored newer ones.
  local resp; resp="$(es -H 'Content-Type: application/json' -X POST "$ES_URL/$INDEX_NAME/_search" -d "{
    \"size\": $PARAMS_CANDIDATE_POOL,
    \"_source\":[\"host\",\"url\",\"root_domain\",\"triage_program\",\"triage_payout_tier\",\"triage_score\",\"triage_true_fresh\",\"first_seen\"],
    \"query\":{\"bool\":{\"filter\":[{\"term\":{\"triage_in_scope\":true}},{\"term\":{\"triage_pays\":true}}],\"must_not\":[{\"term\":{\"triage_out_of_scope\":true}}]}},
    \"sort\":[{\"triage_score\":{\"order\":\"desc\",\"missing\":\"_last\"}},{\"first_seen\":{\"order\":\"asc\",\"missing\":\"_last\"}}]
  }" 2>/dev/null)" || { warn "ES query failed"; exit 0; }

  WORK="$(mktemp -d)"; trap '[[ -n "${WORK:-}" ]] && rm -rf "$WORK"' EXIT
  printf '%s' "$resp" | jq -rc '.hits.hits[]?._source | [(.host//""),(.url//("https://"+(.host//""))),(.root_domain//""),(.triage_program//""),(.triage_payout_tier//"none"),((.triage_true_fresh//false)|tostring),(.first_seen//"")] | @tsv' 2>/dev/null > "$WORK/cand.tsv"
  [[ -s "$WORK/cand.tsv" ]] || { log "no in-scope-paying candidates"; exit 0; }

  local NOW CUTOFF; NOW=$(date +%s); CUTOFF=$(( NOW - PARAMS_COOLDOWN_DAYS*86400 ))
  awk -F'\t' -v c="$CUTOFF" '$1>=c' "$SCANNED_FILE" > "$SCANNED_FILE.tmp" 2>/dev/null && mv "$SCANNED_FILE.tmp" "$SCANNED_FILE"
  awk -F'\t' '{print $2}' "$SCANNED_FILE" | sort -u > "$WORK/done.set"

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
  grep -vE '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.' \
       "$WORK/cand_div.tsv" \
  | grep -vE '^(mta-sts|cdn-[0-9]|assets\.|static\.|media\.)' \
  | grep -vE '^(api|apis|graphql|grpc|gql|mqtt|push|device|devices|iot|broker|smtp|imap|pop3?|mx[0-9]*|ns[0-9]+|dns)[.-]' \
  | grep -vE '^(auth|login|signin|sso|oauth|oidc|idp|saml|adfs|keycloak|prometheus|alertmanager|grafana|metrics|daemon|repo|repos|registry|artifactory|nexus)[.-]' \
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

  # Build the worklist: up to PER_CYCLE not-yet-scanned hosts (cooldown-respecting).
  local worklist="$WORK/worklist.tsv"; : > "$worklist"
  local picked=0
  while IFS=$'\t' read -r host url root program tier fresh fseen; do
    [[ "$picked" -ge "$PARAMS_HOSTS_PER_CYCLE" ]] && break
    [[ -z "$host" ]] && continue
    grep -qxF "$host" "$WORK/done.set" && continue
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$host" "$url" "$root" "$program" "$tier" "$fresh" "$fseen" >> "$worklist"
    picked=$((picked+1))
  done < "$WORK/cand.tsv"
  [[ "$picked" -gt 0 ]] || { log "no fresh in-scope candidates this cycle (all in cooldown)"; exit 0; }
  log "crawling $picked host(s), ${PARAM_PARALLEL}-wide"

  # Parallel pool: PARAM_PARALLEL concurrent crawl_host jobs, each isolated to its own
  # dir (no shared-file races). Per-host rate limits + gau jitter keep egress polite.
  local running=0
  while IFS=$'\t' read -r host url root program tier fresh fseen; do
    crawl_host "$host" "$url" "$root" "$program" "$tier" "$fresh" "$fseen" "$WORK" &
    running=$((running+1))
    if (( running >= PARAM_PARALLEL )); then wait -n 2>/dev/null || wait; running=$((running-1)); fi
  done < "$worklist"
  wait

  # Aggregate per-host outputs (serial — no races now that all jobs are done).
  local bulk="$WORK/bulk.ndjson"; : > "$bulk"
  cat "$WORK"/*/bulk.part >> "$bulk"         2>/dev/null || true
  cat "$WORK"/*/scanned   >> "$SCANNED_FILE" 2>/dev/null || true
  local cls
  for cls in $PARAMS_CLASSES; do cat "$WORK"/*/cls."$cls" >> "$PARAMS_DIR/$cls.txt" 2>/dev/null || true; done
  local total_urls; total_urls="$(cat "$WORK"/*/urlcount 2>/dev/null | awk '{s+=$1} END{print s+0}')"

  # dedup per-class files
  local cls
  for cls in $PARAMS_CLASSES; do [[ -f "$PARAMS_DIR/$cls.txt" ]] && sort -u "$PARAMS_DIR/$cls.txt" -o "$PARAMS_DIR/$cls.txt" 2>/dev/null || true; done
  # bulk index to ES — capture response to get real indexed count and surface errors
  local indexed=0
  if [[ -s "$bulk" ]]; then
    local bulk_resp
    bulk_resp="$(es -H 'Content-Type: application/x-ndjson' -X POST "$ES_URL/$PARAMS_INDEX/_bulk" \
      --data-binary @"$bulk" 2>/dev/null)"
    if [[ -n "$bulk_resp" ]]; then
      indexed="$(printf '%s' "$bulk_resp" | jq '[.items[]?.index | select(.result=="created" or .result=="updated")] | length' 2>/dev/null || echo 0)"
      # Surface any per-doc errors so they show up in the daemon log
      local errs; errs="$(printf '%s' "$bulk_resp" | jq -r '[.items[]?.index | select(.error) | .error.reason] | unique | .[:3] | join(" | ")' 2>/dev/null)"
      [[ -n "$errs" ]] && warn "bulk index errors: $errs"
    else
      warn "bulk index: no response from ES (connection issue?)"
    fi
  fi
  log "collected $picked host(s), $total_urls param-URLs, indexed $indexed catalog entries"
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

case "${1:-}" in
  collect) shift; cmd_collect "$@" ;;
  list)    shift; cmd_list "$@" ;;
  verify)  shift; cmd_verify "$@" ;;
  *) echo "usage: recon_params.sh {collect | list <class> [N] | verify <xss|sqli> [N]}" >&2; exit 2 ;;
esac

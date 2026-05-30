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
PARAMS_HOSTS_PER_CYCLE="${PARAMS_HOSTS_PER_CYCLE:-10}"
PARAMS_COOLDOWN_DAYS="${PARAMS_COOLDOWN_DAYS:-7}"
PARAMS_ZERO_COOLDOWN_HOURS="${PARAMS_ZERO_COOLDOWN_HOURS:-6}"
PARAMS_CANDIDATE_POOL="${PARAMS_CANDIDATE_POOL:-400}"
PARAMS_INTER_HOST_SLEEP="${PARAMS_INTER_HOST_SLEEP:-5}"
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
  grep -vE '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.' \
       "$WORK/cand_div.tsv" \
  | grep -vE '^(mta-sts|cdn-[0-9]|assets\.|static\.|media\.)' > "$WORK/cand.tsv"
  rm -f "$WORK/cand_div.tsv"

  local picked=0 bulk="$WORK/bulk.ndjson"; : > "$bulk"
  local total_urls=0
  while IFS=$'\t' read -r host url root program tier fresh fseen; do
    [[ "$picked" -ge "$PARAMS_HOSTS_PER_CYCLE" ]] && break
    [[ -z "$host" ]] && continue
    grep -qxF "$host" "$WORK/done.set" && continue
    picked=$((picked+1))
    local hd="$WORK/$(printf '%s' "$host" | tr '/:.' '___')"; mkdir -p "$hd"
    # crawl (katana live + gau historical), keep param URLs, dedup by structure
    # -fs rdn keeps katana within the seed's root domain (= in-scope program),
    # so the catalog never collects off-scope URLs from wandered links.
    { timeout "$KATANA_CRAWL_TIMEOUT" "$KATANA" -u "$url" -d "$KATANA_DEPTH" -jc -fs rdn -silent -nc -rl "$KATANA_RL" 2>/dev/null
      [[ -x "$GAU" ]] && printf '%s\n' "$host" | timeout "$GAU_TIMEOUT" "$GAU" --threads 5 --subs 2>/dev/null
    } | grep -E '^https?://' | grep -F '?' | sort -u | head -n "$MAX_URLS_PER_HOST" > "$hd/raw" || true
    local raw_n; raw_n="$(wc -l < "$hd/raw" 2>/dev/null | tr -d ' ')"
    log "  [$picked/$PARAMS_HOSTS_PER_CYCLE] $host — ${raw_n} param URLs"
    # Zero-result cooldown: write a short-term entry so the host isn't retried
    # every 30-min cycle. Entry timestamp is back-dated so it expires after
    # PARAMS_ZERO_COOLDOWN_HOURS (default 6h) instead of the full 7-day window.
    # This breaks the GAU rate-limit death-loop where the same 20 hosts are
    # hammered every cycle because nothing was ever written to the scanned file.
    if [[ "$raw_n" -eq 0 ]]; then
      local zero_secs=$(( ${PARAMS_ZERO_COOLDOWN_HOURS:-6} * 3600 ))
      local short_ts=$(( NOW - PARAMS_COOLDOWN_DAYS*86400 + zero_secs ))
      printf '%s\t%s\n' "$short_ts" "$host" >> "$SCANNED_FILE"
      continue
    fi
    if [[ -x "$QSREPLACE" && -s "$hd/raw" ]]; then "$QSREPLACE" FUZZ < "$hd/raw" 2>/dev/null | sort -u > "$hd/urls"; else cp "$hd/raw" "$hd/urls" 2>/dev/null || : > "$hd/urls"; fi
    [[ -s "$hd/urls" ]] || { printf '%s\t%s\n' "$NOW" "$host" >> "$SCANNED_FILE"; continue; }
    # Brief pause between hosts — OTX/urlscan rate-limit quickly under back-to-back requests.
    sleep "${PARAMS_INTER_HOST_SLEEP:-5}"
    : > "$hd/classified.tsv"
    local cls
    for cls in $PARAMS_CLASSES; do
      "$GF" "$cls" < "$hd/urls" 2>/dev/null | sed "s|\$|\t$cls|" >> "$hd/classified.tsv"
    done
    [[ -s "$hd/classified.tsv" ]] || { printf '%s\t%s\n' "$NOW" "$host" >> "$SCANNED_FILE"; continue; }
    # per-class files (append; deduped at end)
    for cls in $PARAMS_CLASSES; do
      awk -F'\t' -v c="$cls" '$2==c{print $1}' "$hd/classified.tsv" >> "$PARAMS_DIR/$cls.txt" 2>/dev/null || true
    done
    # ES docs: one per url with vuln_classes[]
    awk -F'\t' '{a[$1]=a[$1]","$2} END{for(u in a){sub(/^,/,"",a[u]); print u"\t"a[u]}}' "$hd/classified.tsv" \
    | while IFS=$'\t' read -r u classes; do
        local iso; iso="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        local id; id="$(printf '%s' "$u" | sha1sum | cut -c1-40)"
        jq -nc --arg u "$u" --arg id "$id" --arg h "$host" --arg rd "$root" --arg pr "$program" --arg ti "$tier" \
              --argjson tf "${fresh:-false}" --arg fs "$fseen" --arg ca "$iso" --arg cl "$classes" \
          '{index:{_id:$id}}, {url:$u,host:$h,root_domain:$rd,vuln_classes:($cl|split(",")),program:$pr,payout_tier:$ti,true_fresh:$tf,first_seen:(if $fs=="" then null else $fs end),cataloged_at:$ca}' 2>/dev/null >> "$bulk"
      done
    total_urls=$(( total_urls + $(wc -l < "$hd/urls" | tr -d ' ') ))
    printf '%s\t%s\n' "$NOW" "$host" >> "$SCANNED_FILE"
  done < "$WORK/cand.tsv"

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
  resp="$(es -H 'Content-Type: application/json' -X POST "$ES_URL/$PARAMS_INDEX/_search" -d "{
    \"size\": $n,
    \"_source\": [\"url\",\"program\",\"payout_tier\",\"true_fresh\"],
    \"query\": {\"term\": {\"vuln_classes\": \"$cls\"}},
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

  local canary="d0k_recon"
  local sqli_re='SQL syntax|mysql_num_rows|ORA-[0-9]+|SQLSTATE|You have an error in your SQL|Microsoft OLE DB|ODBC SQL Server|Warning.*mysql_|Unclosed quotation mark|quoted string not properly terminated|pg_query\(\)|supplied argument is not a valid MySQL'
  local ua='Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0'
  local out_file="$PARAMS_DIR/verify_${cls}.jsonl"
  mkdir -p "$PARAMS_DIR"

  local hits=0 checked=0
  while IFS=$'\t' read -r url program tier fresh_tag; do
    [[ -z "$url" ]] && continue
    checked=$((checked+1))

    local probe_url
    case "$cls" in
      xss)  probe_url="$(printf '%s\n' "$url" | "$QSREPLACE" "$canary" 2>/dev/null)" ;;
      sqli) probe_url="$(printf '%s\n' "$url" | "$QSREPLACE" "'" 2>/dev/null)" ;;
    esac
    [[ -z "$probe_url" ]] && continue

    local body
    body="$(curl -sS -m10 -k -L --max-redirs 2 -A "$ua" "$probe_url" 2>/dev/null | head -c 65536)"

    local hit=0
    case "$cls" in
      xss)  printf '%s' "$body" | grep -qi "$canary" && hit=1 ;;
      sqli) printf '%s' "$body" | grep -qiE "$sqli_re" && hit=1 ;;
    esac

    if [[ "$hit" -eq 1 ]]; then
      hits=$((hits+1))
      local label="[${cls^^} CONFIRMED]"
      [[ "$fresh_tag" == "FRESH" ]] && label="$label [FRESH]"
      printf '%s  %s [%s]  %s\n' "$label" "$program" "$tier" "$probe_url"
      jq -nc --arg u "$url" --arg p "$probe_url" --arg c "$cls" \
             --arg pr "$program" --arg ti "$tier" --arg fr "$fresh_tag" \
             --arg ts "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
        '{url:$u, probe_url:$p, class:$c, program:$pr, tier:$ti, fresh:($fr=="FRESH"), confirmed_at:$ts}' \
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

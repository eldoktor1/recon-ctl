#!/usr/bin/env bash
# =============================================================================
# recon_dast.sh — Fresh-first DAST param-fuzzing lane (v2.8)
#
# PIPELINE
#   1. Pull in-scope-PAYING hosts from ES, FRESH-ENGINE FIRST: triage_true_fresh
#      hosts (the gungnir CT feed) sort ahead of everything, then newest
#      external_first_seen / first_seen. Hosts scanned within DAST_COOLDOWN_DAYS
#      are skipped so each cycle always works the freshest UNSCANNED assets.
#   2. Crawl each host (katana live-crawl + gau historical URLs), keep URLs that
#      carry query parameters, canonicalise with qsreplace to drop dup params.
#   3. gf-filter the URL set per vuln class using the g0ldencybersec sus_params
#      patterns (xss/sqli/ssrf/lfi/redirect/ssti/cmdi) installed in ~/.gf.
#   4. Fuzz: dalfox on XSS candidates, nuclei -dast on the rest.
#   5. Findings -> ~/recon/dast/findings.jsonl (+ Discord notify) and the host is
#      recorded in the cooldown file.
#
# EGRESS  Target-facing (crawl + fuzz). Invoked by the daemon via run_scanner
#   (sudo -u reconrun) so it egresses through Mullvad. Every external tool here
#   is Go (katana/gau/qsreplace/dalfox/nuclei) so none can wedge in WSL2 D-state.
# =============================================================================
set -uo pipefail
IFS=$'\n\t'

log()  { printf '[%s DAST] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s DAST WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
DAST_DIR="$BASE_DIR/dast"
RESULTS_DIR="$DAST_DIR/results"
FINDINGS_FILE="$DAST_DIR/findings.jsonl"
SCANNED_FILE="$DAST_DIR/scanned_hosts.tsv"   # <epoch>\t<host>
LOCK_FILE="$STATE_DIR/dast.lock"
KILL_FILE="$STATE_DIR/kill/v2_dast"

ES_URL="${ES_URL:-http://127.0.0.1:9200}"
ES_USER="${ES_USER:-elastic}"
ES_PASS="${ES_PASS:-$(tr -d '[:space:]' < "$HOME/.recon_es_pass" 2>/dev/null || true)}"
INDEX_NAME="${INDEX_NAME:-recon_alive}"
DISCORD_WEBHOOK="${DISCORD_WEBHOOK:-$(cat "$HOME/.recon_discord" 2>/dev/null || true)}"

# Tool paths (prefer go/bin)
GOBIN="$HOME/go/bin"
KATANA="${KATANA:-$GOBIN/katana}"
GAU="${GAU:-$GOBIN/gau}"
GF="${GF:-$GOBIN/gf}"
QSREPLACE="${QSREPLACE:-$GOBIN/qsreplace}"
DALFOX="${DALFOX:-$GOBIN/dalfox}"
NUCLEI="${NUCLEI:-$GOBIN/nuclei}"

# Bounds
DAST_HOSTS_PER_CYCLE="${DAST_HOSTS_PER_CYCLE:-15}"
DAST_COOLDOWN_DAYS="${DAST_COOLDOWN_DAYS:-7}"
DAST_CANDIDATE_POOL="${DAST_CANDIDATE_POOL:-300}"     # how many fresh hosts to pull before cooldown subtraction
KATANA_DEPTH="${KATANA_DEPTH:-2}"
KATANA_CRAWL_TIMEOUT="${KATANA_CRAWL_TIMEOUT:-90}"    # seconds per host
GAU_TIMEOUT="${GAU_TIMEOUT:-60}"
DAST_MAX_URLS_PER_HOST="${DAST_MAX_URLS_PER_HOST:-1500}"
DALFOX_TIMEOUT="${DALFOX_TIMEOUT:-600}"
NUCLEI_DAST_TIMEOUT="${NUCLEI_DAST_TIMEOUT:-900}"
DAST_CLASSES="${DAST_CLASSES:-xss sqli ssrf lfi redirect ssti cmdi}"
# Per-HOST politeness. DAST tools hammer a SINGLE target with many requests, so
# (unlike breadth tools) they must be gentle or the shared Mullvad exit IP gets
# WAF-banned — which hurts every other scan. Keep these low.
KATANA_RL="${KATANA_RL:-15}"            # crawl requests/sec to one host
NUCLEI_DAST_RL="${NUCLEI_DAST_RL:-15}"  # fuzz requests/sec to one host
DALFOX_WORKERS="${DALFOX_WORKERS:-20}"  # dalfox default 100 is too aggressive per host
DALFOX_DELAY="${DALFOX_DELAY:-50}"      # ms between requests to same host

mkdir -p "$RESULTS_DIR" "$(dirname "$KILL_FILE")"
touch "$FINDINGS_FILE" "$SCANNED_FILE"

[[ -f "$KILL_FILE" ]] && { warn "dast killed by $KILL_FILE"; exit 0; }

exec 9>"$LOCK_FILE"
flock -n 9 || { warn "dast already running"; exit 0; }
python3 -c "import fcntl; fcntl.fcntl(9, fcntl.F_SETFD, fcntl.FD_CLOEXEC)" 2>/dev/null || true

for t in "$KATANA" "$GF" "$DALFOX" "$NUCLEI"; do
  [[ -x "$t" ]] || { warn "required tool missing: $t"; exit 0; }
done
command -v jq >/dev/null 2>&1 || { warn "jq missing"; exit 0; }

# ---- 1. Fresh-first in-scope-paying target selection from ES ---------------
es_up() {
  local code; code="$(curl -sS -o /dev/null -m 5 -u "$ES_USER:$ES_PASS" -w '%{http_code}' "$ES_URL" 2>/dev/null || echo 000)"
  [[ "$code" == "200" ]]
}
es_up || { warn "ES not reachable — cannot select targets"; exit 0; }

# triage_true_fresh first (desc: true>false), then newest external_first_seen,
# then newest first_seen. Only in-scope, paying, not explicitly out-of-scope.
QUERY=$(cat <<JSON
{
  "size": ${DAST_CANDIDATE_POOL},
  "_source": ["host","url","triage_true_fresh","triage_external_first_seen","first_seen"],
  "query": {"bool": {"filter": [
    {"term": {"triage_in_scope": true}},
    {"term": {"triage_pays": true}},
    {"term": {"triage_out_of_scope": false}}
  ]}},
  "sort": [
    {"triage_true_fresh": {"order": "desc", "missing": "_last"}},
    {"triage_external_first_seen": {"order": "desc", "missing": "_last"}},
    {"first_seen": {"order": "desc", "missing": "_last"}}
  ]
}
JSON
)

resp="$(curl -sS -m 30 -u "$ES_USER:$ES_PASS" -H 'Content-Type: application/json' \
        -X POST "$ES_URL/$INDEX_NAME/_search" -d "$QUERY" 2>/dev/null)" || resp=""
[[ -z "$resp" ]] && { warn "ES query failed"; exit 0; }

CAND="$(mktemp)"
WORK="$(mktemp -d)"
trap 'rm -rf "$CAND" "$WORK"' EXIT

# Emit "host<TAB>url<TAB>fresh" preserving ES sort order (fresh-first)
printf '%s' "$resp" | jq -r '
  .hits.hits[]?._source |
  [(.host // ""), (.url // ("https://" + (.host // ""))), ((.triage_true_fresh // false)|tostring)] | @tsv
' 2>/dev/null | awk -F'\t' 'NF>=2 && $1!=""' > "$CAND"

[[ -s "$CAND" ]] || { log "no in-scope-paying candidates in ES"; exit 0; }

# ---- Cooldown subtraction: skip hosts scanned within DAST_COOLDOWN_DAYS -----
NOW=$(date +%s)
CUTOFF=$(( NOW - DAST_COOLDOWN_DAYS * 86400 ))
# Prune old entries, keep the cooldown file bounded
awk -F'\t' -v c="$CUTOFF" '$1>=c' "$SCANNED_FILE" > "$SCANNED_FILE.tmp" 2>/dev/null && mv "$SCANNED_FILE.tmp" "$SCANNED_FILE"
awk -F'\t' '{print $2}' "$SCANNED_FILE" | sort -u > "$WORK/scanned.set"

# Take the freshest hosts not in cooldown, up to the per-cycle cap
TARGETS="$WORK/targets.tsv"
: > "$TARGETS"
picked=0
while IFS=$'\t' read -r host url fresh; do
  [[ "$picked" -ge "$DAST_HOSTS_PER_CYCLE" ]] && break
  grep -qxF "$host" "$WORK/scanned.set" && continue
  printf '%s\t%s\t%s\n' "$host" "$url" "$fresh" >> "$TARGETS"
  picked=$((picked+1))
done < "$CAND"

ntargets="$(wc -l < "$TARGETS" | tr -d ' ')"
[[ "$ntargets" -eq 0 ]] && { log "all freshest candidates already scanned within ${DAST_COOLDOWN_DAYS}d cooldown"; exit 0; }
nfresh="$(awk -F'\t' '$3=="true"' "$TARGETS" | wc -l | tr -d ' ')"
log "selected $ntargets host(s) for DAST ($nfresh from fresh engine, cooldown ${DAST_COOLDOWN_DAYS}d)"

# ---- Discord notify helper -------------------------------------------------
notify_discord() {
  [[ -n "$DISCORD_WEBHOOK" ]] || return 0
  local title="$1" desc="$2"
  local payload
  payload="$(jq -nc --arg t "$title" --arg d "$desc" \
    '{embeds:[{title:$t,description:$d,color:15158332,footer:{text:"recon_v2 · DAST"}}]}')"
  curl -sS -m 10 -H 'Content-Type: application/json' -X POST -d "$payload" "$DISCORD_WEBHOOK" >/dev/null 2>&1 || true
}

# ---- nuclei -dast support detection (once) ---------------------------------
NUCLEI_HAS_DAST=0
"$NUCLEI" -h 2>&1 | grep -q -- '-dast' && NUCLEI_HAS_DAST=1

# ---- 2-5. Per-host crawl -> gf -> fuzz -------------------------------------
total_findings=0
while IFS=$'\t' read -r host url fresh; do
  [[ -z "$host" ]] && continue
  hdir="$WORK/$(printf '%s' "$host" | tr '/:.' '___')"
  mkdir -p "$hdir"
  urls="$hdir/urls.txt"

  # --- crawl: katana (live) + gau (historical), bounded ---
  {
    timeout "$KATANA_CRAWL_TIMEOUT" "$KATANA" -u "$url" -d "$KATANA_DEPTH" -jc -kf all \
      -silent -nc -rl "$KATANA_RL" 2>/dev/null
    [[ -x "$GAU" ]] && printf '%s\n' "$host" | timeout "$GAU_TIMEOUT" "$GAU" --threads 5 --subs 2>/dev/null
  } | grep -E '^https?://' | grep -F '?' | sort -u | head -n "$DAST_MAX_URLS_PER_HOST" > "$urls.raw" || true

  # canonicalise so /a?id=1 and /a?id=2 collapse to one test case. qsreplace
  # dedups by host+path+param-keys; the FUZZ placeholder value is irrelevant
  # since dalfox/nuclei replace param values with their own payloads anyway.
  if [[ -x "$QSREPLACE" && -s "$urls.raw" ]]; then
    "$QSREPLACE" FUZZ < "$urls.raw" 2>/dev/null | sort -u > "$urls" || cp "$urls.raw" "$urls"
  else
    cp "$urls.raw" "$urls" 2>/dev/null || : > "$urls"
  fi

  nurls="$(wc -l < "$urls" 2>/dev/null | tr -d ' ')"
  if [[ "${nurls:-0}" -eq 0 ]]; then
    printf '%s\t%s\n' "$NOW" "$host" >> "$SCANNED_FILE"
    continue
  fi
  log "  $host: $nurls param-URL(s) to fuzz"

  # --- gf-filter into per-class candidate sets ---
  declare -A classfile=()
  for cls in $DAST_CLASSES; do
    [[ -f "$HOME/.gf/$cls.json" ]] || continue
    cf="$hdir/$cls.txt"
    "$GF" "$cls" < "$urls" 2>/dev/null | sort -u > "$cf"
    [[ -s "$cf" ]] && classfile["$cls"]="$cf"
  done

  host_findings="$hdir/findings.jsonl"
  : > "$host_findings"

  # --- dalfox on XSS candidates ---
  if [[ -n "${classfile[xss]:-}" ]]; then
    timeout "$DALFOX_TIMEOUT" "$DALFOX" pipe --silence --no-color --skip-bav --format json \
      -w "$DALFOX_WORKERS" --delay "$DALFOX_DELAY" \
      < "${classfile[xss]}" 2>/dev/null \
      | jq -c --arg host "$host" 'select(type=="object") | {host:$host, tool:"dalfox", type:(.type // "XSS"), url:(.data // .url // ""), severity:(.severity // "medium"), evidence:(.message // .poc // "")}' 2>/dev/null \
      >> "$host_findings" || true
  fi

  # --- nuclei -dast on the remaining suspicious URLs ---
  if [[ "$NUCLEI_HAS_DAST" -eq 1 ]]; then
    nuc_in="$hdir/nuclei_urls.txt"
    cat "${classfile[@]:-/dev/null}" 2>/dev/null | sort -u > "$nuc_in"
    if [[ -s "$nuc_in" ]]; then
      timeout "$NUCLEI_DAST_TIMEOUT" "$NUCLEI" -l "$nuc_in" -dast -silent -jsonl -nc \
        -rl "$NUCLEI_DAST_RL" -timeout 15 2>/dev/null \
        | jq -c --arg host "$host" 'select(type=="object") | {host:$host, tool:"nuclei", type:(."template-id" // "dast"), url:(."matched-at" // .url // ""), severity:(.info.severity // "unknown"), evidence:(.info.name // "")}' 2>/dev/null \
        >> "$host_findings" || true
    fi
  fi

  # --- record findings + cooldown ---
  hf="$(wc -l < "$host_findings" 2>/dev/null | tr -d ' ')"
  if [[ "${hf:-0}" -gt 0 ]]; then
    cat "$host_findings" >> "$FINDINGS_FILE"
    cp "$host_findings" "$RESULTS_DIR/$(date -u +%Y%m%dT%H%M%SZ)_$(printf '%s' "$host" | tr '/:.' '___').jsonl"
    total_findings=$(( total_findings + hf ))
    local_fresh_tag=""; [[ "$fresh" == "true" ]] && local_fresh_tag=" [FRESH]"
    log "  $host: $hf finding(s)$local_fresh_tag"
    # Notify highest-signal findings (high/critical) individually
    while IFS= read -r f; do
      sev="$(printf '%s' "$f" | jq -r '.severity // "unknown"' 2>/dev/null)"
      case "$sev" in
        high|critical)
          notify_discord "[DAST $sev] $(printf '%s' "$f" | jq -r '.type' 2>/dev/null) on $host$local_fresh_tag" \
                         "$(printf '%s' "$f" | jq -r '"URL: " + (.url|tostring) + "\n" + (.evidence|tostring)' 2>/dev/null | head -c 1500)" ;;
      esac
    done < "$host_findings"
  fi
  unset classfile
  printf '%s\t%s\n' "$NOW" "$host" >> "$SCANNED_FILE"
done < "$TARGETS"

log "DAST cycle done — $total_findings finding(s) across $ntargets host(s)"
[[ "$total_findings" -gt 0 ]] && notify_discord "DAST cycle: $total_findings finding(s)" "Across $ntargets fresh-first in-scope-paying host(s); $nfresh from the fresh engine."
exit 0

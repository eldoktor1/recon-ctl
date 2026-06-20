#!/usr/bin/env bash
# =============================================================================
# recon_graphql.sh — GraphQL schema → human-test worklist lane (the under-hunted money class)
#
# THE EDGE: the crowd runs subfinder|httpx|nuclei and at most flags "introspection enabled"
# (Info/dup). We harvest the introspection SCHEMA and REASON over the graph (sensitive unauth
# mutations, object-ref args = IDOR, injectable args = SQLi/NoSQLi, PII-returning queries) →
# a ranked LEAD worklist for the operator's 2-account / injection tests. Claude's understanding
# where commodity tools are blind (the MOTTO).
#
# SAFETY: sends ONLY read-only GraphQL — a benign {__typename} liveness probe + the standard
# introspection query. NEVER a mutation, a data-returning field query, or auth. Everything it
# surfaces is a LEAD; IDOR/injection/auth-bypass confirmation is HUMAN-IN-THE-LOOP (2 owned
# accounts, never third-party IDs — hard line). Anti-burn: bounded batch, per-endpoint 7d
# cooldown, scope+pays gate, Mullvad via run_scanner.
#
# OUTPUT: briefings/graphql_candidates_<date>.md + graphql_worklist.jsonl + ES stamp; surfaced
# in the 6:30 briefing. KB: docs/knowledge/class-graphql.md.
#
# USAGE: recon_graphql.sh [scan] | check <url> | results [N]
# =============================================================================
set -uo pipefail
IFS=$'\n\t'
log()  { printf '[%s GRAPHQL] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s GRAPHQL WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/recon_net.sh"
setup_es_netrc
ES_AUTH=(--netrc-file "$HOME/.recon_es_netrc")

BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"
INDEX_NAME="${INDEX_NAME:-recon_alive}"
SCOPE_CHECK="${SCOPE_CHECK:-$SCRIPT_DIR/recon_scope_check.sh}"
HELPER="$SCRIPT_DIR/recon_graphql.py"
JSINTEL="${JSINTEL:-$BASE_DIR/js_recon/endpoints.jsonl}"
BRIEF_DIR="${BRIEF_DIR:-$BASE_DIR/briefings}"

GQL_DIR="$BASE_DIR/graphql"
WORKLIST="$GQL_DIR/graphql_worklist.jsonl"
SCANNED="$GQL_DIR/scanned.tsv"          # endpoint<TAB>epoch (dedup/cooldown ledger)
WORK="$GQL_DIR/work"
LOCK_FILE="$STATE_DIR/graphql.lock"

GQL_BATCH="${GQL_BATCH:-80}"            # candidate endpoints probed per cycle
GQL_COOLDOWN_DAYS="${GQL_COOLDOWN_DAYS:-7}"
GQL_PATHS="${GQL_PATHS:-/graphql /api/graphql /graphql/api /v1/graphql /v2/graphql /query /gql /api/gql /graphql/console /graphiql /playground /api}"

mkdir -p "$GQL_DIR" "$WORK" "$BRIEF_DIR" "$STATE_DIR" 2>/dev/null || true
touch "$WORKLIST" "$SCANNED" 2>/dev/null || true
command -v jq >/dev/null 2>&1 || { warn "jq missing"; exit 0; }

vpn_gate() { [[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down — refusing target-facing graphql work"; exit 0; }; }
es_curl() { curl -sS -m30 "${ES_AUTH[@]}" -H 'Content-Type: application/json' "$@"; }

# ---- candidate endpoint discovery (in-scope provenance, dup-resistant) ----
# A) jsintel endpoints that look like graphql; B) ES recon_alive in-scope hosts whose url/title/tech
# signal graphql (exact url used as-is; tech/title-only hosts get bounded path expansion).
discover_endpoints() {   # -> host<TAB>url<TAB>program  on stdout
  # A) jsintel
  if [[ -s "$JSINTEL" ]]; then
    jq -rc 'select((.endpoint//"")|test("graphql|/gql";"i")) | [.host,(.endpoint//""),(.program//"")] | @tsv' "$JSINTEL" 2>/dev/null \
      | while IFS=$'\t' read -r h ep prog; do
          [[ -z "$h" ]] && continue
          if [[ "$ep" == http* ]]; then printf '%s\t%s\t%s\n' "$h" "$ep" "$prog"
          elif [[ "$ep" == /* ]]; then printf '%s\thttps://%s%s\t%s\n' "$h" "$h" "$ep" "$prog"
          fi
        done
  fi
  # B) ES recon_alive: in-scope + not benched, url~graphql OR title~graphql OR tech~graphql
  local q resp
  q='{"size":1500,"_source":["host","url","triage_program","tech","title"],
      "query":{"bool":{
        "filter":[{"term":{"triage_in_scope":true}}],
        "must_not":[{"range":{"ignore_expires_at":{"gt":"now"}}}],
        "minimum_should_match":1,
        "should":[{"wildcard":{"url":"*graphql*"}},{"wildcard":{"url":"*/gql*"}},
                  {"match":{"title":"graphql"}},{"match":{"tech":"graphql"}}]}}}'
  resp="$(es_curl -X POST "$ES_URL/$INDEX_NAME/_search" -d "$q" 2>/dev/null)" || resp=""
  printf '%s' "$resp" | jq -rc '.hits.hits[]?._source
      | [.host, (.url//""), (.triage_program//""), ((.tech//"")+" "+(.title//""))] | @tsv' 2>/dev/null \
    | while IFS=$'\t' read -r h url prog hint; do
        [[ -z "$h" ]] && continue
        if printf '%s' "$url" | grep -qiE 'graphql|/gql'; then
          printf '%s\t%s\t%s\n' "$h" "$url" "$prog"
        else
          # tech/title says graphql but no path → bounded path expansion
          local p
          for p in $GQL_PATHS; do printf '%s\thttps://%s%s\t%s\n' "$h" "$h" "$p" "$prog"; done
        fi
      done
}

es_stamp() {   # stamp graphql posture onto the host doc (best-effort)
  local host="$1" intro="$2" nsens="$3"; [[ -z "$host" ]] && return 0
  local now; now="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  es_curl -X POST "$ES_URL/$INDEX_NAME/_update/$host" \
    -d "$(jq -nc --argjson i "$intro" --argjson n "$nsens" --arg t "$now" \
      '{doc:{graphql_endpoint:true,graphql_introspection:$i,graphql_sensitive_ops:$n,graphql_scan_at:$t}}')" \
    >/dev/null 2>&1 || true
}
note_host() { local h="$1" t="$2"; [[ -z "$h" ]] && return 0; bash "$SCRIPT_DIR/recon_ctl.sh" note "$h" "$t" >/dev/null 2>&1 || true; }

# ---- one bounded cycle ----
cmd_scan() {
  vpn_gate
  exec 9>"$LOCK_FILE"; flock -n 9 || { log "another graphql scan running"; exit 0; }
  local cand="$WORK/cand.tsv" gated="$WORK/gated.tsv"; : > "$cand"; : > "$gated"

  discover_endpoints | awk 'NF' | sort -u > "$cand" || true
  local ncand; ncand="$(wc -l < "$cand" | tr -d ' ')"
  [[ "$ncand" -eq 0 ]] && { log "no graphql candidate endpoints discovered"; exit 0; }
  log "discovered $ncand candidate endpoint(s)"

  # scope + pays gate on the hosts
  local inscope="$WORK/inscope.txt"
  cut -f1 "$cand" | sort -u | bash "$SCOPE_CHECK" --filter in-scope-paying 2>/dev/null | sort -u > "$inscope" || true
  [[ -s "$inscope" ]] || { log "no candidate host is in-scope+paying"; exit 0; }
  awk -F'\t' 'NR==FNR{ok[$1]=1;next} ($1 in ok)' "$inscope" "$cand" > "$gated" || true

  # dedup vs 7d cooldown ledger (by endpoint url), cap batch
  local cutoff; cutoff=$(( $(date +%s) - GQL_COOLDOWN_DAYS*86400 ))
  local batch="$WORK/batch.tsv"; : > "$batch"; local kept=0
  while IFS=$'\t' read -r h url prog; do
    [[ "$kept" -ge "$GQL_BATCH" ]] && break
    local last; last="$(awk -F'\t' -v u="$url" '$1==u{print $2}' "$SCANNED" | tail -1)"
    [[ -n "$last" && "$last" =~ ^[0-9]+$ && "$last" -gt "$cutoff" ]] && continue
    printf '%s\t%s\t%s\n' "$h" "$url" "$prog" >> "$batch"; kept=$((kept+1))
  done < "$gated"
  [[ "$kept" -eq 0 ]] && { log "all in-scope candidates within cooldown"; exit 0; }
  log "probing $kept endpoint(s)"

  # analyze (python: read-only {__typename} + introspection per URL)
  local live="$WORK/live.jsonl"
  cut -f2 "$batch" | python3 "$HELPER" analyze > "$live" 2>/dev/null || true

  # record everything probed in the cooldown ledger
  local nowep; nowep="$(date +%s)"
  cut -f2 "$batch" | while IFS= read -r u; do printf '%s\t%s\n' "$u" "$nowep" >> "$SCANNED"; done

  local nlive nsens_total=0 nintro=0
  nlive="$(wc -l < "$live" | tr -d ' ')"
  [[ "$nlive" -eq 0 ]] && { log "no live graphql endpoints this cycle"; exit 0; }

  # route: enrich each live endpoint with host/program (join via batch), append worklist, stamp, note
  : > "$WORK/enriched.jsonl"
  while IFS= read -r rec; do
    [[ -z "$rec" ]] && continue
    local ep host prog intro nsens
    ep="$(jq -r '.endpoint' <<<"$rec")"
    host="$(awk -F'\t' -v u="$ep" '$2==u{print $1; exit}' "$batch")"; [[ -n "$host" ]] || host="$(printf '%s' "$ep" | sed -E 's#https?://([^/]+).*#\1#')"
    prog="$(awk -F'\t' -v u="$ep" '$2==u{print $3; exit}' "$batch")"
    intro="$(jq -r '.introspection_enabled' <<<"$rec")"
    nsens="$(jq -r '.n_sensitive // 0' <<<"$rec")"
    local now; now="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    jq -c --arg h "$host" --arg p "$prog" --arg ts "$now" '. + {host:$h,program:$p,ts:$ts,status:"to-test"}' <<<"$rec" >> "$WORK/enriched.jsonl"
    es_stamp "$host" "$intro" "$nsens"
    nsens_total=$(( nsens_total + nsens ))
    [[ "$intro" == "true" ]] && nintro=$((nintro+1))
    if [[ "$intro" == "true" && "$nsens" -gt 0 ]]; then
      note_host "$host" "graphql: introspection ON, $nsens sensitive op(s) — see graphql_worklist (human 2-acct/injection test)"
    fi
  done < "$live"

  cat "$WORK/enriched.jsonl" >> "$WORKLIST" 2>/dev/null || true
  write_briefing
  log "cycle done — 🔮 $nlive live · introspection-on $nintro · sensitive ops $nsens_total → worklist"
}

# ---- ranked briefing markdown ----
write_briefing() {
  local today md; today="$(date '+%Y-%m-%d')"; md="$BRIEF_DIR/graphql_candidates_$today.md"
  # recent (3d) live endpoints, deduped by endpoint, introspection-on + sensitive first
  local recent; recent="$(tail -n 400 "$WORKLIST" 2>/dev/null | jq -c '.' 2>/dev/null \
    | jq -s 'map(select(.ts and (.ts >= (now - 3*86400 | todate)))) | unique_by(.endpoint)
             | sort_by( (if .introspection_enabled then 1000 else 0 end) + (.n_sensitive//0)*10 ) | reverse' 2>/dev/null || echo '[]')"
  {
    printf '# 🔮 GraphQL worklist — %s\n\n' "$today"
    printf '_Read-only introspection only. IDOR/injection/auth-bypass = human test with 2 OWNED accounts (never third-party IDs)._\n\n'
    printf '%s' "$recent" | jq -r '.[] |
      "## \(.host) — `\(.endpoint)`",
      "- introspection: \(if .introspection_enabled then "**ENABLED**" else "off (consider field-suggestion recovery)" end) · queries \(.n_queries) · mutations \(.n_mutations) · sensitive \(.n_sensitive) · program \(.program // "?")",
      ( .candidates[]? | select(.sensitive or (.idor_args|length>0) or (.injectable_args|length>0))
        | "  - [\(.score)] **\(.op_type) \(.name)** — \(.reason)" ),
      ""' 2>/dev/null
  } > "$md" 2>/dev/null
  log "briefing → $md"
}

cmd_check() {
  vpn_gate
  local url="${1:?usage: check <graphql-url>}"
  printf '%s\n' "$url" | python3 "$HELPER" analyze \
    | jq -r '"endpoint: \(.endpoint)\nintrospection: \(.introspection_enabled) · queries \(.n_queries) · mutations \(.n_mutations) · sensitive \(.n_sensitive)\n--- top ops ---",
             (.candidates[]? | "[\(.score)] \(.op_type) \(.name)  args=[\(.args|join(","))]  \(.reason)")' 2>/dev/null \
    || echo "not a live GraphQL endpoint (or introspection off): $url"
}

cmd_results() {
  local n="${1:-15}"
  tail -n 200 "$WORKLIST" 2>/dev/null | jq -c '.' 2>/dev/null | jq -s "unique_by(.endpoint) | sort_by(.ts) | reverse | .[0:$n][]" 2>/dev/null \
    | jq -r '"\(.ts // "?")  \(.host)  \(.endpoint)  introspection=\(.introspection_enabled) sensitive=\(.n_sensitive)"' 2>/dev/null || true
}

case "${1:-scan}" in
  scan|"")   cmd_scan ;;
  check)     shift; cmd_check "$@" ;;
  results|list) shift; cmd_results "$@" ;;
  *) echo "usage: $0 [scan|check <url>|results [N]]" >&2; exit 2 ;;
esac

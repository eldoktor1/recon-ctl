#!/usr/bin/env bash
# =============================================================================
# recon_wcd.sh — Web-Cache-Deception / Poisoning LEAD surfacer (SAFE, detect-only)
#
# Detects the cacheability DISCREPANCY (the LEAD), never the impact. Every probe carries a
# UNIQUE cache-buster so we test under OUR OWN cache key and NEVER poison the shared cache real
# users hit (the critical safety primitive). GET-only, unauth, no redirect-follow, Mullvad via
# run_scanner. Impact PoC (private data lands in cache / poison persists) is OPERATOR + owned
# account — this only mints LEADs → briefing.
#
# Input: in-scope + paying hosts that sit behind a CDN/cache (no cache ⇒ no WCD ⇒ skip).
# Confirm on-demand: `recon-wcd confirm <host>` → WCVS deception test (throttled, operator).
#
# USAGE: recon_wcd.sh [scan] | confirm <host> [url] | purge <host> [path] | results [N]
# KB: docs/knowledge/class-cache-deception.md
# =============================================================================
set -uo pipefail
IFS=$'\n\t'
log()  { printf '[%s WCD] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s WCD WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/recon_net.sh"
setup_es_netrc
ES_AUTH=(--netrc-file "$HOME/.recon_es_netrc")

BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"
INDEX_NAME="${INDEX_NAME:-recon_alive}"
SCOPE_CHECK="${SCOPE_CHECK:-$SCRIPT_DIR/recon_scope_check.sh}"
HELPER="$SCRIPT_DIR/recon_wcd.py"
BRIEF_DIR="${BRIEF_DIR:-$BASE_DIR/briefings}"

WCD_DIR="$BASE_DIR/wcd"
LEADS="$WCD_DIR/leads.jsonl"
SCANNED="$WCD_DIR/scanned.tsv"
WORK="$WCD_DIR/work"
LOCK_FILE="$STATE_DIR/wcd.lock"
WCVS_BIN="${WCVS_BIN:-$HOME/go/bin/Web-Cache-Vulnerability-Scanner}"

WCD_BATCH="${WCD_BATCH:-30}"            # CDN-fronted hosts probed per cycle (~15 req each)
WCD_COOLDOWN_DAYS="${WCD_COOLDOWN_DAYS:-7}"

mkdir -p "$WCD_DIR" "$WORK" "$BRIEF_DIR" "$STATE_DIR" 2>/dev/null || true
touch "$LEADS" "$SCANNED" 2>/dev/null || true
command -v jq >/dev/null 2>&1 || { warn "jq missing"; exit 0; }

vpn_gate() { [[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down — refusing target-facing wcd work"; exit 0; }; }
es_curl() { curl -sS -m30 "${ES_AUTH[@]}" -H 'Content-Type: application/json' "$@"; }

# in-scope + paying hosts behind a CDN/cache (cdn_name set, or webserver/tech = a CDN)
discover_cdn_hosts() {   # -> host<TAB>url
  local q resp
  q='{"size":2000,"_source":["host","url"],
      "query":{"bool":{
        "filter":[{"term":{"triage_in_scope":true}},{"term":{"triage_pays":true}}],
        "must_not":[{"range":{"ignore_expires_at":{"gt":"now"}}}],
        "minimum_should_match":1,
        "should":[{"exists":{"field":"cdn_name"}},{"exists":{"field":"cdn_type"}},
                  {"match":{"webserver":"cloudflare"}},{"match":{"webserver":"akamai"}},
                  {"match":{"webserver":"fastly"}},{"match":{"tech":"cloudflare"}},
                  {"match":{"tech":"fastly"}},{"match":{"tech":"akamai"}},{"match":{"tech":"varnish"}}]}}}'
  resp="$(es_curl -X POST "$ES_URL/$INDEX_NAME/_search" -d "$q" 2>/dev/null)" || resp=""
  printf '%s' "$resp" | jq -rc '.hits.hits[]?._source | [.host,(.url//("https://"+.host))] | @tsv' 2>/dev/null
}

es_stamp() { local h="$1" cls="$2"; [[ -z "$h" ]] && return 0; local n; n="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  es_curl -X POST "$ES_URL/$INDEX_NAME/_update/$h" \
    -d "$(jq -nc --arg c "$cls" --arg t "$n" '{doc:{wcd_lead:$c,wcd_scan_at:$t}}')" >/dev/null 2>&1 || true; }
note_host() { local h="$1" t="$2"; [[ -z "$h" ]] && return 0; bash "$SCRIPT_DIR/recon_ctl.sh" note "$h" "$t" >/dev/null 2>&1 || true; }

cmd_scan() {
  vpn_gate
  exec 9>"$LOCK_FILE"; flock -n 9 || { log "another wcd scan running"; exit 0; }
  local cand="$WORK/cand.tsv" gated="$WORK/gated.tsv"; : > "$cand"; : > "$gated"

  discover_cdn_hosts | awk 'NF' | sort -u > "$cand" || true
  local ncand; ncand="$(wc -l < "$cand" | tr -d ' ')"
  [[ "$ncand" -eq 0 ]] && { log "no CDN-fronted in-scope+paying hosts found"; exit 0; }

  # per-asset authoritative scope+pays gate
  local inscope="$WORK/inscope.txt"
  cut -f1 "$cand" | sort -u | bash "$SCOPE_CHECK" --filter in-scope-paying 2>/dev/null | sort -u > "$inscope" || true
  [[ -s "$inscope" ]] || { log "no candidate host is in-scope+paying"; exit 0; }
  awk -F'\t' 'NR==FNR{ok[$1]=1;next} ($1 in ok)' "$inscope" "$cand" > "$gated" || true

  # dedup vs cooldown, cap batch
  local cutoff; cutoff=$(( $(date +%s) - WCD_COOLDOWN_DAYS*86400 ))
  local batch="$WORK/batch.tsv"; : > "$batch"; local kept=0
  while IFS=$'\t' read -r h url; do
    [[ "$kept" -ge "$WCD_BATCH" ]] && break
    local last; last="$(awk -F'\t' -v k="$h" '$1==k{print $2}' "$SCANNED" | tail -1)"
    [[ -n "$last" && "$last" =~ ^[0-9]+$ && "$last" -gt "$cutoff" ]] && continue
    printf '%s\t%s\n' "$h" "$url" >> "$batch"; kept=$((kept+1))
  done < "$gated"
  [[ "$kept" -eq 0 ]] && { log "all CDN hosts within cooldown"; exit 0; }
  log "probing $kept CDN-fronted host(s) (cache-busted, detect-only)"

  local out="$WORK/leads.jsonl"
  python3 "$HELPER" scan < "$batch" > "$out" 2>/dev/null || true

  local nowep; nowep="$(date +%s)"
  cut -f1 "$batch" | while IFS= read -r h; do printf '%s\t%s\n' "$h" "$nowep" >> "$SCANNED"; done

  local nlead; nlead="$(wc -l < "$out" | tr -d ' ')"
  [[ "$nlead" -eq 0 ]] && { log "no cache discrepancy LEADs this cycle"; exit 0; }
  local now; now="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  while IFS= read -r lead; do
    [[ -z "$lead" ]] && continue
    jq -c --arg ts "$now" '. + {ts:$ts}' <<<"$lead" >> "$LEADS"
    local h cls ev; h="$(jq -r .host <<<"$lead")"; cls="$(jq -r .class <<<"$lead")"; ev="$(jq -r .evidence <<<"$lead")"
    es_stamp "$h" "$cls"
    local action="owned-account impact PoC" ccmd="recon-wcd confirm $h"
    [[ "$cls" == "cache-purge" ]] && { action="unauth PURGE confirm"; ccmd="recon-wcd purge $h"; }
    note_host "$h" "wcd: $cls LEAD — $ev (operator: $action; $ccmd)"
    log "LEAD $cls: $h"
  done < "$out"
  write_briefing
  log "cycle done — ☁️ $nlead cache-discrepancy LEAD(s)"
}

write_briefing() {
  local today md; today="$(date '+%Y-%m-%d')"; md="$BRIEF_DIR/wcd_candidates_$today.md"
  local recent; recent="$(tail -n 300 "$LEADS" 2>/dev/null | jq -c '.' 2>/dev/null \
    | jq -s 'map(select(.ts and (.ts >= (now - 3*86400 | todate)))) | unique_by(.host+.kind)
             | sort_by(if .severity=="high" then 2 else 1 end) | reverse' 2>/dev/null || echo '[]')"
  { printf '# ☁️ Web-cache deception/poisoning LEADs — %s\n\n' "$today"
    printf '_Detect-only (cache-busted, never poisons real cache). Impact PoC = owned account, operator._\n\n'
    printf '%s' "$recent" | jq -r '.[] | "- **[\(.severity)] \(.kind)** `\(.host)` \(.url)\n  - \(.evidence)\n  - probe: `\(.probe)` · confirm: `\(if .class=="cache-purge" then "recon-wcd purge" else "recon-wcd confirm" end) \(.host)`"' 2>/dev/null
  } > "$md" 2>/dev/null
}

# on-demand confirm via WCVS (throttled, deception test, operator-overseen)
cmd_confirm() {
  vpn_gate
  local host="${1:?usage: confirm <host> [url]}" url="${2:-https://$host/}"
  [[ -x "$WCVS_BIN" ]] || { warn "WCVS not found at $WCVS_BIN (go install github.com/Hackmanit/Web-Cache-Vulnerability-Scanner@latest)"; exit 1; }
  log "WCVS deception test on $url (rate 0.5/s, cache-buster cbwcvs) — operator-overseen"
  "$WCVS_BIN" -u "$url" -ot deception -rr 0.5 -gr -gp "$WCD_DIR/wcvs_$(printf '%s' "$host" | tr '/:.' '___').json" 2>&1 | tail -30
}

# on-demand Varnish unauth PURGE confirm (operator; ONE state-changing PURGE, scope+pays-gated, Mullvad).
# PURGE only EVICTS a cache entry (re-fetched from origin next request) = non-destructive + minimal per
# the active-PoC doctrine. 200/204 = CONFIRMED reportable primitive → mint → verify gate → #review.
cmd_purge() {
  vpn_gate
  local host="${1:?usage: purge <host> [path]}" path="${2:-/}"
  [[ "$path" == /* ]] || path="/$path"
  # authoritative per-asset scope+pays gate — never fire an active method at a non-paying/OOS host
  if ! printf '%s\n' "$host" | bash "$SCOPE_CHECK" --filter in-scope-paying 2>/dev/null | grep -qxF "$host"; then
    warn "$host is not in-scope+paying (authoritative gate) — refusing PURGE"; exit 1
  fi
  local url="https://${host}${path}" code
  log "unauth PURGE $url (single shot, no redirect-follow) — operator-overseen"
  code="$(curl -sS -m20 -o /dev/null -w '%{http_code}' -X PURGE "$url" \
     -H 'User-Agent: Mozilla/5.0 (compatible; recon-wcd/1.0)' 2>/dev/null)" || code="000"
  log "PURGE $url -> HTTP $code"
  case "$code" in
    200|204)
      local prog evj; prog="$(bash "$SCOPE_CHECK" "$host" 2>/dev/null | jq -r '.program // "unknown"' 2>/dev/null)"; [[ -n "$prog" ]] || prog="unknown"
      evj="$(jq -nc --arg u "$url" --arg c "$code" '{probe:"unauth-http-purge",source:"recon-wcd",vuln_class:"cache-purge-unauth",severity:"high",evidence:("unauth PURGE "+$u+" returned HTTP "+$c+" — cache eviction without authentication")}')"
      db_confirm "$host" "$url" "$prog" "wcd-purge" "cache-purge-unauth" "10" "0.9" "$evj"
      note_host "$host" "wcd: CONFIRMED unauth Varnish PURGE ($code) on $path — minted → verify gate → #review"
      log "🔥 CONFIRMED unauth cache PURGE ($code) — minted → verify gate → #review" ;;
    401|403|405)
      note_host "$host" "wcd: Varnish PURGE secured (HTTP $code) on $path — FP/by-design"
      log "secure — PURGE returned $code (auth/method restricted). Noted, not minted." ;;
    *)
      log "inconclusive (HTTP $code) — verify Varnish/path; not minted." ;;
  esac
}

cmd_results() {
  local n="${1:-15}"
  tail -n 200 "$LEADS" 2>/dev/null | jq -c '.' 2>/dev/null | jq -s "unique_by(.host+.kind) | sort_by(.ts) | reverse | .[0:$n][]" 2>/dev/null \
    | jq -r '"\(.ts // "?")  [\(.severity)] \(.kind)  \(.host)  \(.evidence)"' 2>/dev/null || true
}

case "${1:-scan}" in
  scan|"")     cmd_scan ;;
  confirm)     shift; cmd_confirm "$@" ;;
  purge)       shift; cmd_purge "$@" ;;
  results|list) shift; cmd_results "$@" ;;
  *) echo "usage: $0 [scan|confirm <host> [url]|purge <host> [path]|results [N]]" >&2; exit 2 ;;
esac

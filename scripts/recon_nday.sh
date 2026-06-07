#!/usr/bin/env bash
# =============================================================================
# recon_nday.sh — n-day RACING pillar: be first on fresh CVEs, without the KEV false-positive.
#
# The pipeline already matches KEV/breaking CVEs to assets by tech class (triage_kev_*).
# But a tech-class match is a LEAD, not a bug (our own doctrine: "KEV match without a
# confirmed in-range version = FP"). The unique edge is Claude doing the VERSION reasoning
# the crowd skips: given the detected tech/version, is the host LIKELY in the vulnerable
# range? Is a public exploit out? What is the single safest way to verify, right now, in the
# race window before everyone's templates catch up? Reasoning only -> high-value candidates
# land on the worklist for the briefing; the human/gate verifies. Runs as d0k (Claude auth).
# =============================================================================
set -uo pipefail
IFS=$'\n\t'
log()  { printf '[%s NDAY] %s\n'      "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s NDAY WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/recon_net.sh" 2>/dev/null || true
BASE_DIR="${BASE_DIR:-$HOME/recon}"; STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"; INDEX_NAME="${INDEX_NAME:-recon_alive}"
NETRC="${NETRC:-$HOME/.recon_es_netrc}"
WORKLIST="${IDOR_WORKLIST:-$BASE_DIR/idor_worklist.jsonl}"   # shared worklist -> briefing
SEEN="${NDAY_SEEN:-$STATE_DIR/nday_seen.txt}"
CLAUDE_BIN="${CLAUDE_BIN:-$HOME/.local/bin/claude}"; [[ -x "$CLAUDE_BIN" ]] || CLAUDE_BIN="$(command -v claude 2>/dev/null || echo '')"
CLAUDE_MODEL="${CLAUDE_NDAY_MODEL:-sonnet}"
CLAUDE_TIMEOUT="${CLAUDE_TIMEOUT:-150}"
NDAY_HOSTS="${NDAY_HOSTS:-12}"
es() { curl -fsS -m 25 --netrc-file "$NETRC" -H 'Content-Type: application/json' "$@"; }

mkdir -p "$STATE_DIR" "$(dirname "$WORKLIST")"; touch "$SEEN"
exec 9>"$STATE_DIR/nday.lock"; flock -n 9 || { warn "already running"; exit 0; }
[[ -n "$CLAUDE_BIN" && -x "$CLAUDE_BIN" ]] || { warn "claude CLI not found — skipping"; exit 0; }
command -v jq >/dev/null 2>&1 || { warn "jq missing"; exit 0; }

SCHEMA='{"type":"object","additionalProperties":false,"properties":{"likely_vulnerable":{"type":"boolean"},"cve":{"type":"string"},"reason":{"type":"string"},"exploit_available":{"type":"boolean"},"verify_method":{"type":"string"},"impact":{"type":"string","enum":["critical","high","medium","low"]},"confidence":{"type":"number","minimum":0,"maximum":1}},"required":["likely_vulnerable","reason","verify_method","impact","confidence"]}'

# in-scope+paying assets with a KEV/breaking-vuln match, freshest first, not yet assessed
q="$(jq -nc --argjson n "$NDAY_HOSTS" '{size:($n*4),
  _source:["host","tech","webserver","status_code","title","triage_kev_cves","triage_program","triage_breaking_vuln"],
  query:{bool:{filter:[{term:{triage_in_scope:true}},{term:{triage_pays:true}}],
               should:[{term:{triage_kev_match:true}},{exists:{field:"triage_kev_cves"}},{term:{triage_breaking_vuln:true}}],
               minimum_should_match:1, must_not:[{term:{triage_out_of_scope:true}}]}},
  sort:[{triage_true_fresh:{order:"desc",missing:"_last"}},{triage_score:{order:"desc",missing:"_last"}}]}')"
resp="$(es "$ES_URL/$INDEX_NAME/_search" -d "$q" 2>/dev/null)"
mapfile -t rows < <(printf '%s' "$resp" | jq -c '.hits.hits[]._source' 2>/dev/null \
  | while IFS= read -r r; do h="$(printf '%s' "$r" | jq -r '.host // empty')"; grep -qxF "$h" "$SEEN" 2>/dev/null || printf '%s\n' "$r"; done | head -n "$NDAY_HOSTS")
[[ "${#rows[@]}" -gt 0 ]] || { log "no fresh KEV/CVE-matched assets to assess"; exit 0; }
log "🏁 ─── N-DAY RACE ─── ${#rows[@]} CVE-matched asset(s) · Claude version-reasoning (kill the KEV FP) ───"

leads=0
for r in "${rows[@]}"; do
  host="$(printf '%s' "$r" | jq -r '.host // empty')"; [[ -z "$host" ]] && continue
  printf '%s\n' "$host" >> "$SEEN"
  prog="$(printf '%s' "$r" | jq -r '.triage_program // ""')"
  cves="$(printf '%s' "$r" | jq -r '(.triage_kev_cves // []) | if type=="array" then join(",") else tostring end' 2>/dev/null)"
  tech="$(printf '%s' "$r" | jq -r '(.tech // []) | join(", ")' 2>/dev/null)"
  prompt="$(cat <<EOF
An in-scope host matched a known-exploited / breaking CVE BY TECH CLASS. A tech-class match
is NOT a bug — most are false positives because the running version isn't actually in the
vulnerable range. Do the reasoning the crowd skips.

HOST: $host
PROGRAM: ${prog:-?}
DETECTED TECH/VERSIONS: ${tech:-unknown}
WEBSERVER: $(printf '%s' "$r" | jq -r '.webserver // "?"')
TITLE: $(printf '%s' "$r" | jq -r '(.title // "")[0:90]')
MATCHED CVE(s): ${cves:-unknown}

Judge: is this host LIKELY actually vulnerable (running version plausibly in range for the
CVE), or is it just a same-product tech-class match (FP)? Is a public exploit/PoC available?
Give the single SAFEST way to verify it right now (a version banner, a specific path, a
benign request — not exploitation). Rate impact + confidence. Set likely_vulnerable=false if
the evidence is only a product-name match with no version signal.
EOF
)"
  out="$(timeout "$CLAUDE_TIMEOUT" "$CLAUDE_BIN" -p "$prompt" --model "$CLAUDE_MODEL" --tools "" \
         --no-session-persistence --json-schema "$SCHEMA" --output-format json </dev/null 2>/dev/null)"
  so="$(printf '%s' "$out" | jq -c '.structured_output // empty' 2>/dev/null)"
  [[ -z "$so" || "$so" == "null" ]] && continue
  lv="$(printf '%s' "$so" | jq -r '.likely_vulnerable // false')"
  conf="$(printf '%s' "$so" | jq -r '.confidence // 0')"
  if [[ "$lv" == "true" ]] && awk "BEGIN{exit !(${conf:-0}>=0.5)}"; then
    ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf '%s' "$so" | jq -c --arg h "$host" --arg p "$prog" --arg c "$cves" --arg t "$ts" \
      '{host:$h,program:$p,endpoint:("CVE: "+(.cve // $c)),vuln_type:"n-day-cve",
        why:.reason,test:.verify_method,impact:.impact,confidence:.confidence,
        exploit_available:(.exploit_available//false),at:$t,status:"to-test"}' >> "$WORKLIST" 2>/dev/null
    leads=$((leads+1))
    log "   🏁 LIKELY VULN · $host · ${cves:-?} · $(printf '%s' "$so" | jq -r '.impact')/$(printf '%s' "$so" | jq -r '.confidence') → worklist"
  else
    log "   · $host — KEV FP (tech-class only, not in-range)"
  fi
done
tail -n 8000 "$SEEN" > "$SEEN.tmp" 2>/dev/null && mv "$SEEN.tmp" "$SEEN" 2>/dev/null || true
log "🏁 n-day done · 🏁 $leads likely-vulnerable candidate(s) → worklist"

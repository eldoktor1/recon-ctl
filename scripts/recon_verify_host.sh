#!/usr/bin/env bash
# =============================================================================
# recon_verify_host.sh — on-demand Claude verification of a digest lead / host.
#
# The briefing hands you leads; this lets you ask Claude to scrutinise ONE before
# you spend evening time on it. Claude reads the ES asset context + the lead + the
# JS endpoints and gives a verdict (worth-testing / likely-fp / needs-human), and
# it may REQUEST safe unauthenticated probes (GET/HEAD/OPTIONS) which the trusted
# harness runs via recon_safe_probe.sh — Claude never executes anything itself.
#
# Usage:
#   recon_verify_host.sh list                 # list current digest leads (indexed)
#   recon_verify_host.sh <host>               # verify a specific host
#   recon_verify_host.sh <N>                  # verify the Nth lead from `list`
#
# READ-ONLY + SAFE. Unauthenticated probes only, scope+pays-gated, Mullvad-only,
# rate-limited (all enforced by recon_safe_probe.sh). Reasoning only; you exploit.
# Runs as d0k (Claude Max auth, no API key).
# =============================================================================
set -uo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/recon_net.sh" 2>/dev/null || true
BASE_DIR="${BASE_DIR:-$HOME/recon}"; STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"; INDEX_NAME="${INDEX_NAME:-recon_alive}"
NETRC="${NETRC:-$HOME/.recon_es_netrc}"
WORKLIST="${IDOR_WORKLIST:-$BASE_DIR/idor_worklist.jsonl}"
EP_STORE="${JS_ENDPOINT_STORE:-$BASE_DIR/js_recon/endpoints.jsonl}"
SAFE_PROBE="${SAFE_PROBE:-$SCRIPT_DIR/recon_safe_probe.sh}"
CLAUDE_BIN="${CLAUDE_BIN:-$HOME/.local/bin/claude}"; [[ -x "$CLAUDE_BIN" ]] || CLAUDE_BIN="$(command -v claude 2>/dev/null || echo '')"
CLAUDE_MODEL="${CLAUDE_VERIFY_MODEL:-sonnet}"
CLAUDE_TIMEOUT="${CLAUDE_TIMEOUT:-180}"
PROBE_ROUNDS="${PROBE_ROUNDS:-2}"
LIST_CACHE="$STATE_DIR/verify_list.tsv"

c0=$'\033[0m'; cb=$'\033[1m'; cg=$'\033[32m'; cy=$'\033[33m'; cr=$'\033[31m'; cc=$'\033[36m'
es() { curl -fsS -m 20 --netrc-file "$NETRC" -H 'Content-Type: application/json' "$@" 2>/dev/null; }
die() { printf '%berror:%b %s\n' "$cr" "$c0" "$*" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || die "jq missing"

# ---- ordered lead list (same source the briefing ranks) -------------------------
build_list() {  # -> TSV: idx<TAB>host<TAB>vuln_type<TAB>endpoint_or_cve<TAB>impact<TAB>conf
  grep -aE '"status":"to-test"' "$WORKLIST" 2>/dev/null \
    | jq -c '.' 2>/dev/null \
    | jq -rs 'unique_by(.host + (.endpoint//"") + (.cve//""))
             | map(. + {rank: (({"critical":4,"high":3,"medium":2,"low":1}[.impact]) // 0) + (.confidence // 0)})
             | sort_by(-.rank)
             | to_entries[] | [(.key+1), .value.host, (.value.vuln_type//"?"),
                               ((.value.endpoint // "") | if .=="" then "" else . end) + (.value.cve//""),
                               (.value.impact//"?"), (.value.confidence//0)] | @tsv' 2>/dev/null
}

cmd_list() {
  build_list | tee "$LIST_CACHE" | awk -F'\t' -v cb="$(printf '\033[1m')" -v c0="$(printf '\033[0m')" -v cc="$(printf '\033[36m')" '
    BEGIN{printf "%s%-4s %-46s %-22s %-9s %s%s\n", cb, "#", "HOST", "TYPE", "IMPACT", "LEAD", c0}
    {printf "%-4s %s%-46s%s %-22s %-9s %s\n", $1, cc, substr($2,1,46), c0, substr($3,1,22), $5, substr($4,1,40)}'
  local n; n="$(wc -l < "$LIST_CACHE" 2>/dev/null | tr -d ' ')"
  printf '\n%b%s leads.%b  Verify one with:  %brecon-verify <#>%b  or  %brecon-verify <host>%b\n' \
    "$cb" "${n:-0}" "$c0" "$cg" "$c0" "$cg" "$c0"
}

resolve_host() {  # arg -> host (accepts index or host)
  local a="$1"
  if [[ "$a" =~ ^[0-9]+$ ]]; then
    [[ -s "$LIST_CACHE" ]] || build_list > "$LIST_CACHE"
    awk -F'\t' -v i="$a" '$1==i{print $2; exit}' "$LIST_CACHE"
  else
    printf '%s' "$a"
  fi
}

# ---- gather context for a host --------------------------------------------------
host_context() {  # host -> compact JSON of ES asset + leads + endpoints
  local h="$1"
  local esdoc; esdoc="$(es "$ES_URL/$INDEX_NAME/_doc/$h" | jq -c '._source // {} | {
      program:.triage_program, in_scope:.triage_in_scope, pays:.triage_pays, payout_tier:.triage_payout_tier,
      url, status:.http_status, title:.http_title, tech:(.tech // .technologies // []),
      classes:.triage_classes, kev:.triage_kev_cves, score:.triage_score, first_seen, last_seen,
      claude_prev:.claude_verdict }' 2>/dev/null)"
  [[ -n "$esdoc" && "$esdoc" != "null" ]] || esdoc='{}'
  local leads; leads="$(grep -aE '"status":"to-test"' "$WORKLIST" 2>/dev/null \
    | jq -c --arg h "$h" 'select(.host==$h) | {vuln_type,endpoint,cve,why,test,impact,confidence}' 2>/dev/null | jq -sc '.' 2>/dev/null)"
  [[ -n "$leads" ]] || leads='[]'
  local eps; eps="$(jq -r --arg h "$h" 'select(.host==$h)|.endpoint' "$EP_STORE" 2>/dev/null | awk 'NF&&!s[$0]++' | head -40 | jq -Rsc 'split("\n")|map(select(length>0))' 2>/dev/null)"
  [[ -n "$eps" ]] || eps='[]'
  jq -nc --arg h "$h" --argjson es "$esdoc" --argjson leads "$leads" --argjson eps "$eps" \
    '{host:$h, asset:$es, leads:$leads, js_endpoints:$eps}'
}

VSCHEMA='{"type":"object","additionalProperties":false,"properties":{
  "verdict":{"type":"string","enum":["worth-testing","likely-fp","needs-human","needs-probe"]},
  "confidence":{"type":"number","minimum":0,"maximum":1},
  "reasoning":{"type":"string"},
  "recommended_next_step":{"type":"string"},
  "probe_requests":{"type":"array","maxItems":4,"items":{"type":"object","additionalProperties":false,
    "properties":{"url":{"type":"string"},"method":{"type":"string","enum":["GET","HEAD","OPTIONS"]}},
    "required":["url","method"]}}},
  "required":["verdict","confidence","reasoning","recommended_next_step"]}'

ask_claude() {  # ctx_json  probe_results_json -> structured_output json
  local ctx="$1" probes="$2"
  local prompt; prompt="$(cat <<EOF
You are a bug-bounty access-control & vuln verifier. Assess this ONE lead and decide if it is
worth the human's limited evening time, or a false positive. Be skeptical: a route appearing in
JS, or a tech-class CVE match, is a LEAD not a finding. Reward only genuinely promising unauth /
broken-access surface; kill cosmetic/version-only/SPA-shell noise.

You may REQUEST safe unauthenticated probes (GET/HEAD/OPTIONS only) by setting verdict="needs-probe"
and listing probe_requests (the harness runs them and returns real responses; you never execute).
Use probes to disambiguate (e.g. does the admin route 200 with data, or 401/login, or a 200 SPA
shell?). Otherwise give: worth-testing | likely-fp | needs-human, a confidence, crisp reasoning,
and the single best recommended_next_step (the exact 2-account test, or why to skip).

LEAD CONTEXT (ES asset + worklist leads + JS endpoints):
$ctx

PROBE RESULTS SO FAR (real responses from the safe harness; empty if none yet):
$probes
EOF
)"
  timeout "$CLAUDE_TIMEOUT" "$CLAUDE_BIN" -p "$prompt" --model "$CLAUDE_MODEL" --tools "" \
    --no-session-persistence --json-schema "$VSCHEMA" --output-format json </dev/null 2>/dev/null \
    | jq -c '.structured_output // empty' 2>/dev/null
}

cmd_verify() {
  local host; host="$(resolve_host "$1")"
  [[ -n "$host" ]] || die "could not resolve '$1' to a host (try: recon-verify list)"
  [[ -n "$CLAUDE_BIN" && -x "$CLAUDE_BIN" ]] || die "claude CLI not found"

  # scope+pays gate up front
  local sp; sp="$(es "$ES_URL/$INDEX_NAME/_doc/$host" | jq -c '{in_scope:._source.triage_in_scope, pays:._source.triage_pays}' 2>/dev/null)"
  printf '%b▸ verifying%b %s%s%s   (scope/pays: %s)\n' "$cb" "$c0" "$cc" "$host" "$c0" "${sp:-unknown}"
  if [[ "$(printf '%s' "$sp" | jq -r '.pays // false')" != "true" ]]; then
    printf '%b⚠ this host is not pays=true — leads here have no payout. Verifying anyway (read-only).%b\n' "$cy" "$c0"
  fi

  local ctx; ctx="$(host_context "$host")"
  local probes='[]' round=0 out
  while :; do
    out="$(ask_claude "$ctx" "$probes")"
    [[ -n "$out" ]] || die "claude returned nothing (timeout or auth?)"
    local v; v="$(printf '%s' "$out" | jq -r '.verdict')"
    if [[ "$v" == "needs-probe" && "$round" -lt "$PROBE_ROUNDS" ]]; then
      round=$((round+1))
      printf '%b  ↳ probe round %s%b\n' "$cy" "$round" "$c0"
      local newres="[]"
      while IFS= read -r pr; do
        [[ -z "$pr" ]] && continue
        local purl pm res
        purl="$(printf '%s' "$pr" | jq -r '.url')"; pm="$(printf '%s' "$pr" | jq -r '.method')"
        printf '    %s %s ... ' "$pm" "$purl"
        res="$(bash "$SAFE_PROBE" "$purl" "$pm" 2>/dev/null)"
        # harden: safe_probe may return empty / a blocked-message / non-JSON — coerce to valid JSON
        printf '%s' "$res" | jq -e . >/dev/null 2>&1 || res='{"ok":false,"error":"no-response-or-blocked"}'
        printf '%s\n' "$(printf '%s' "$res" | jq -rc '{status:(.status//null),content_type:(.content_type//.headers."content-type"//null),len:(.body_len//.len//null),blocked:(.error//null)}' 2>/dev/null)"
        newres="$(printf '%s' "$newres" | jq -c --arg u "$purl" --arg m "$pm" --argjson r "$res" '. + [{url:$u,method:$m,response:$r}]' 2>/dev/null)"
      done < <(printf '%s' "$out" | jq -c '.probe_requests[]?' 2>/dev/null)
      probes="$(printf '%s' "$probes" | jq -c --argjson b "$newres" '. + $b' 2>/dev/null)"
      continue
    fi
    # final verdict
    local vi; case "$v" in
      worth-testing) vi="${cg}✅ WORTH TESTING${c0}" ;;
      likely-fp)     vi="${cr}🔴 LIKELY FP${c0}" ;;
      needs-human)   vi="${cy}🟡 NEEDS HUMAN${c0}" ;;
      *)             vi="${cy}? $v${c0}" ;;
    esac
    printf '\n%b  conf=%s  model=%s\n' "$vi" "$(printf '%s' "$out" | jq -r '.confidence')" "$CLAUDE_MODEL"
    printf '%b  reasoning:%b %s\n' "$cb" "$c0" "$(printf '%s' "$out" | jq -r '.reasoning')"
    printf '%b  next step:%b %s\n' "$cb" "$c0" "$(printf '%s' "$out" | jq -r '.recommended_next_step')"
    break
  done
}

case "${1:-}" in
  ""|list|ls)   cmd_list ;;
  *)            cmd_verify "$1" ;;
esac

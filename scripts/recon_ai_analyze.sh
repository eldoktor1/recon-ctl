#!/usr/bin/env bash
# =============================================================================
# recon_ai_analyze.sh — Claude-Max ANALYSIS agent (conscious surface selection).
#
# The article fires a fixed testing agent per vuln-class at everything. v3 does it
# smarter: Claude READS every in-scope asset and decides what is actually worth
# verifying and which vuln class — so we maximize the surface we cover while staying
# selective (no blanket scanning). This is pure reasoning over stored asset data +
# the knowledge base; it issues NO target traffic itself.
#
# Per cycle it pulls a quota-bounded, PRIORITISED batch (true-fresh first, then
# triage score) of in-scope + paying assets not analysed within the TTL, asks Claude
# (Haiku — cheap/bulk; cost control = match model to task) for a per-asset verdict,
# injects relevant PAST OUTCOMES from the knowledge base (RAG-lite: "seen this stack
# before? what broke?"), and writes back to ES:
#     claude_worth, claude_interest, claude_analysis, claude_suggested_class,
#     claude_analyzed_at, claude_analyze_model
# For worth + auto-probeable classes it also marks the asset an EVIDENCE-GATE
# candidate (triage_gate_state=candidate) so the deterministic gate gathers evidence
# next — that is how analysis FEEDS the verify layer. Classes we must not auto-test
# (sqli/ssrf/idor/business-logic — the hard line) are surfaced as operator leads only.
#
# Runs as d0k (Claude Code auth + ES netrc are per-user). No API key, billed to Max.
# Not target-facing, but honours vpn_down to stay quiet during incidents.
# =============================================================================
set -uo pipefail
IFS=$'\n\t'

log()  { printf '[%s AI-ANALYZE] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s AI-ANALYZE WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
V3_DB="${V3_DB:-$BASE_DIR/v3/findings.db}"
STATE_PY="${STATE_PY:-$SCRIPT_DIR/../engine/state.py}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"
INDEX_NAME="${INDEX_NAME:-recon_alive}"
NETRC="${NETRC:-$HOME/.recon_es_netrc}"
CLAUDE_BIN="${CLAUDE_BIN:-$HOME/.local/bin/claude}"; [[ -x "$CLAUDE_BIN" ]] || CLAUDE_BIN="$(command -v claude 2>/dev/null || echo '')"
CLAUDE_ANALYZE_MODEL="${CLAUDE_ANALYZE_MODEL:-haiku}"   # bulk/cheap; match model to task
CLAUDE_TIMEOUT="${CLAUDE_TIMEOUT:-120}"
ANALYZE_BATCH="${ANALYZE_BATCH:-30}"        # assets per cycle (quota-bounded)
ANALYZE_CHUNK="${ANALYZE_CHUNK:-10}"        # assets per Claude call
ANALYZE_TTL="${ANALYZE_TTL:-14d}"           # re-analyse cadence (ES date math)
KB_CONTEXT="${KB_CONTEXT:-3}"               # prior lessons injected per asset

es() { curl -fsS -m 30 --netrc-file "$NETRC" -H 'Content-Type: application/json' "$@"; }

mkdir -p "$STATE_DIR"
exec 9>"$STATE_DIR/ai_analyze.lock"; flock -n 9 || { warn "ai-analyze already running"; exit 0; }
[[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down — skipping"; exit 0; }
[[ -n "$CLAUDE_BIN" && -x "$CLAUDE_BIN" ]] || { warn "claude CLI not found — skipping"; exit 0; }
command -v jq >/dev/null 2>&1 || { warn "jq missing"; exit 0; }
[[ -f "$NETRC" ]] || { warn "ES netrc missing ($NETRC)"; exit 0; }

# one-time headless sanity — bail quietly if auth/headless is broken
timeout 60 "$CLAUDE_BIN" -p "Reply with exactly: OK" 2>/dev/null | grep -q "OK" \
  || { warn "claude headless not responding (auth?) — skipping"; exit 0; }

# ---- map Claude's suggested vuln class -> deterministic evidence-gate class ----
# Returns a gate class for auto-probeable findings, or "" for classes that must stay
# human-in-the-loop (the hard line: never autonomously exploit sqli/ssrf/idor/auth).
map_gate_class() {
  # Host-level nuclei-probeable classes -> a gate class (the evidence gate probes them,
  # SSRF/XXE via interactsh OOB). Param-level classes (xss/ssti/redirect/sqli) return ""
  # — they are confirmed by the catalog-driven confirmers (xss-confirm / param-confirm),
  # not the gate. idor/lfi/rce-exploit return "" too: operator-lead only (hard line).
  case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" in
    *graphql*|*gql*)                               echo "graphql" ;;
    *swagger*|*openapi*|*apidoc*|*api-doc*)         echo "swagger" ;;
    *ssrf*)                                         echo "ssrf" ;;
    *xxe*|*xml*ent*)                               echo "xxe" ;;
    *version*|*cve*|*deserial*)                     echo "version" ;;
    *panel*|*dashboard*|*admin*|*login*|*unauth*)  echo "unauth-surface" ;;
    *exposure*|*disclos*|*leak*|*backup*|*config*|*listing*|*info*|*api*) echo "content-leak" ;;
    *)                                             echo "" ;;   # xss/ssti/redirect/sqli -> catalog confirmers; idor/lfi/rce -> operator lead
  esac
}

# ---- pull a prioritised, quota-bounded batch of un-analysed in-scope assets ------
q="$(cat <<JSON
{
  "size": $ANALYZE_BATCH,
  "_source": ["host","url","tech","title","status_code","port","webserver","root_domain",
              "triage_program","triage_payout_tier","triage_score","triage_classes","triage_signals"],
  "query": { "bool": {
    "filter": [ {"term":{"triage_in_scope":true}}, {"term":{"triage_pays":true}} ],
    "must_not": [ {"term":{"triage_out_of_scope":true}}, {"term":{"triage_ignored":true}},
                  {"range":{"claude_analyzed_at":{"gte":"now-$ANALYZE_TTL"}}} ]
  }},
  "sort": [ {"triage_true_fresh":{"order":"desc","missing":"_last"}},
            {"triage_score":{"order":"desc","missing":"_last"}} ]
}
JSON
)"
resp="$(es "$ES_URL/$INDEX_NAME/_search" -d "$q" 2>/dev/null)" || { warn "ES query failed"; exit 0; }
assets="$(printf '%s' "$resp" | jq -c '[.hits.hits[]._source]' 2>/dev/null)"
n="$(printf '%s' "$assets" | jq 'length' 2>/dev/null || echo 0)"
[[ "${n:-0}" -gt 0 ]] || { log "no un-analysed in-scope assets due this cycle"; exit 0; }
log "🧠 ─── CLAUDE ANALYZE ─── $n in-scope asset(s) · model=$CLAUDE_ANALYZE_MODEL (Max, no API) · chunk=$ANALYZE_CHUNK ───"

analyzed=0; worth=0; gated=0; leads=0
now_iso="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# iterate in chunks of ANALYZE_CHUNK
chunks="$(printf '%s' "$assets" | jq -c --argjson n "$ANALYZE_CHUNK" '[range(0; length; $n) as $i | .[$i:$i+$n]]' 2>/dev/null)"
ci="$(printf '%s' "$chunks" | jq 'length' 2>/dev/null || echo 0)"
for ((k=0; k<ci; k++)); do
  [[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down mid-run — stopping"; break; }
  chunk="$(printf '%s' "$chunks" | jq -c ".[$k]")"
  m="$(printf '%s' "$chunk" | jq 'length')"

  # build the asset list + per-asset KB context for the prompt
  asset_lines=""; kb_lines=""
  for ((j=0; j<m; j++)); do
    a="$(printf '%s' "$chunk" | jq -c ".[$j]")"
    host="$(printf '%s' "$a" | jq -r '.host // ""')"
    tech="$(printf '%s' "$a" | jq -r '(.tech // []) | join(",")')"
    title="$(printf '%s' "$a" | jq -r '.title // "" | .[0:80]')"
    sc="$(printf '%s' "$a" | jq -r '.status_code // 0')"
    port="$(printf '%s' "$a" | jq -r '.port // 0')"
    prog="$(printf '%s' "$a" | jq -r '.triage_program // "?"')"
    sigs="$(printf '%s' "$a" | jq -r '(.triage_signals // []) | join(",") | .[0:120]')"
    asset_lines+="- host=$host | tech=[$tech] | status=$sc | port=$port | title=\"$title\" | signals=[$sigs] | program=$prog"$'\n'
    # KB: prior outcomes on similar stacks (no API — keyword retrieval, Claude reasons)
    kb="$(V3_DB="$V3_DB" python3 "$STATE_PY" kb-lookup "$tech" "" "$host" "$KB_CONTEXT" 2>/dev/null \
          | jq -r '.[]? | "    * [\(.verdict)] \(.host) (\(.tech // "?")) \(.vuln_class // "?"): \(.reason // "")"' 2>/dev/null)"
    [[ -n "$kb" ]] && kb_lines+="  $host:"$'\n'"$kb"$'\n'
  done

  prompt="$(cat <<EOF
You are a bug-bounty RECON ANALYST. For EACH asset below, decide whether it is worth
deeper security verification, your interest 0.0-1.0, the single most likely vulnerability
class, and a one-line reason. Reason ONLY over the data given; issue no requests.

Be SELECTIVE — most assets are NOT worth testing. Set worth=false / low interest for:
CDN/WAF parking pages, marketing/static sites, plain login walls with nothing behind,
generic 403/404. FAVOUR (worth=true, higher interest): admin/internal/api/dev/staging
surfaces, exposed dashboards/panels (Jenkins, GitLab, Grafana, Kibana, actuator,
phpMyAdmin...), version-pinned software with known CVEs, anything that smells like an
unauthenticated sensitive surface.

vuln_class is your best single guess: rce, xss, sqli, ssrf, idor, info-disclosure,
exposed-panel, auth-bypass, takeover, lfi, ssti, or none.

PAST OUTCOMES on similar stacks (use these to avoid repeating mistakes — if a similar
stack was judged fp before, LOWER interest; if real before, RAISE it):
${kb_lines:-  (none yet)}

ASSETS:
$asset_lines

Output ONLY a JSON array, one object per asset IN THE SAME ORDER, no prose/markdown:
[{"host":"...","worth":true,"interest":0.0,"vuln_class":"...","reason":"one sentence"}]
EOF
)"

  out="$(timeout "$CLAUDE_TIMEOUT" "$CLAUDE_BIN" -p "$prompt" --model "$CLAUDE_ANALYZE_MODEL" --output-format json </dev/null 2>/dev/null \
         | jq -r '.result // empty' 2>/dev/null)"
  # robust: parse the first JSON array out of Claude's text (handles fences / stray prose / newlines)
  arr="$(printf '%s' "$out" | python3 -c 'import sys,json,re
t=sys.stdin.read().strip()
t=re.sub(r"^```[a-zA-Z]*","",t).strip().strip("`").strip()
v=None
try: v=json.loads(t)
except Exception:
    m=re.search(r"\[.*\]", t, re.S)
    if m:
        try: v=json.loads(m.group(0))
        except Exception: v=None
print(json.dumps(v) if isinstance(v,list) else "")' 2>/dev/null)"
  vc="$(printf '%s' "$arr" | jq 'length' 2>/dev/null || echo 0)"
  [[ "${vc:-0}" -gt 0 ]] || { warn "chunk $k: no parseable verdicts — skipping"; continue; }

  # build a single _bulk body for the chunk
  bulk=""
  for ((j=0; j<vc; j++)); do
    v="$(printf '%s' "$arr" | jq -c ".[$j]")"
    host="$(printf '%s' "$v" | jq -r '.host // ""')"; [[ -z "$host" ]] && continue
    wv="$(printf '%s' "$v" | jq -r 'if (.worth==true) then "true" else "false" end')"
    iv="$(printf '%s' "$v" | jq -r '(.interest // 0) | tonumber? // 0')"
    cls="$(printf '%s' "$v" | jq -r '.vuln_class // "none"')"
    why="$(printf '%s' "$v" | jq -r '.reason // ""')"
    doc="$(jq -nc --arg w "$wv" --argjson i "${iv:-0}" --arg c "$cls" --arg a "$why" \
            --arg t "$now_iso" --arg m "$CLAUDE_ANALYZE_MODEL" \
            '{claude_worth: ($w=="true"), claude_interest: $i, claude_suggested_class: $c,
              claude_analysis: $a, claude_analyzed_at: $t, claude_analyze_model: $m}')"
    # feed the verify layer: worth + auto-probeable class -> evidence-gate candidate
    if [[ "$wv" == "true" ]]; then
      worth=$((worth+1))
      gc="$(map_gate_class "$cls")"
      if [[ -n "$gc" ]]; then
        doc="$(printf '%s' "$doc" | jq -c --arg gc "$gc" \
                '. + {triage_gate_state:"candidate", triage_gate_class:$gc, triage_gate_attempts:0}')"
        gated=$((gated+1)); route="⚙️ →gate:$gc"
      else
        leads=$((leads+1)); route="📋 →lead(human)"   # sqli/ssrf/idor/logic -> operator lead only
      fi
      log "   🎯 worth $host · int=$iv · $cls · $route"
      log "        ↳ 💬 $why"
    fi
    bulk+="$(jq -nc --arg id "$host" --arg idx "$INDEX_NAME" '{update:{_id:$id,_index:$idx}}')"$'\n'
    bulk+="$(jq -nc --argjson d "$doc" '{doc:$d}')"$'\n'
    analyzed=$((analyzed+1))
  done
  if [[ -n "$bulk" ]]; then
    es "$ES_URL/_bulk" --data-binary "$bulk" >/dev/null 2>&1 || warn "chunk $k: ES bulk writeback failed"
  fi
  log "   · chunk $((k+1))/$ci done ($m assets) · running: 🎯$worth worth ⚙️$gated gate 📋$leads lead"
done

log "🧠 analyze done · 🎯 $worth worth · ⚙️ $gated gate-candidates · 📋 $leads operator-leads  (of $analyzed analysed)"

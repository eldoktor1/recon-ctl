#!/usr/bin/env bash
# =============================================================================
# recon_ai_vision.sh — Claude VISION recon-triage over screenshots (token-frugal)
#
# The text ANALYZE tier (recon_ai_analyze.sh) reasons over metadata and is BLIND
# to what a page actually looks like: a title "Dashboard" might be a login wall,
# an unauthenticated Grafana, a fresh install wizard, or a stack-trace page.
# This tier looks at the captured SCREENSHOT and classifies what is ACTUALLY on
# screen — surfacing the exposed-panel / misconfig / info-disclosure money that
# metadata misses. Commodity tools screenshot; almost nobody runs LLM vision
# reasoning over the result. That is the unique edge.
#
# TOKEN-FRUGAL BY DESIGN (operator: be concise of tokens):
#   * HAIKU only (vision-capable, cheap) — no big-model escalation here.
#   * Feeds the 200x150 THUMBNAIL (a few hundred image tokens), never the
#     full-size JPEG.
#   * Short prompt + compact schema + one screenshot per call.
#   * TTL so a host is visioned once, not every run.
#
# Multimodal mechanism (same proven, path-confined pattern as recon_ai_review):
#   the thumb is written to a throwaway dir as ./screenshot.jpg and Claude is
#   Read-scoped to ONLY that dir (--tools Read --add-dir --permission-mode
#   dontAsk). It views the image, returns a schema-validated verdict; it has no
#   shell and cannot read outside the dir.
#
# Writes back to ES: claude_vision_class, claude_vision_worth,
#   claude_vision_interest (INTEGER 0-100; the field dynamic-mapped to long, so we
#   scale the model's 0.0-1.0 x100), claude_vision_reason, claude_vision_at,
#   claude_vision_model. worth=true + an auto-probeable class also marks the
#   asset an EVIDENCE-GATE candidate (feeds the verify layer, like ANALYZE).
#
# Runs as d0k (Claude Max OAuth, no API key). Not target-facing, but honours
# vpn_down to stay quiet during incidents. Standalone (manual) for now; wire
# into the daemon supervise_loop once validated.
# =============================================================================
set -uo pipefail
IFS=$'\n\t'

log()  { printf '[%s AI-VISION] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s AI-VISION WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"
INDEX_NAME="${INDEX_NAME:-recon_alive}"
NETRC="${NETRC:-$HOME/.recon_es_netrc}"
CLAUDE_BIN="${CLAUDE_BIN:-$HOME/.local/bin/claude}"; [[ -x "$CLAUDE_BIN" ]] || CLAUDE_BIN="$(command -v claude 2>/dev/null || echo '')"
CLAUDE_VISION_MODEL="${CLAUDE_VISION_MODEL:-haiku}"   # vision bulk = cheap, frugal
CLAUDE_TIMEOUT="${CLAUDE_TIMEOUT:-90}"
VISION_BATCH="${VISION_BATCH:-30}"                    # screenshots per run
VISION_TTL="${VISION_TTL:-21d}"                       # re-vision cadence (ES date math)

# Compact schema — one verdict per screenshot.
VISION_SCHEMA='{"type":"object","additionalProperties":false,"properties":{"class":{"type":"string","enum":["unauth-panel","install-setup","error-disclosure","login-wall","app-content","parked-marketing","blank-error","other"]},"worth":{"type":"boolean"},"interest":{"type":"number","minimum":0,"maximum":1},"reason":{"type":"string"}},"required":["class","worth","interest","reason"]}'

es() { curl -fsS -m 30 --netrc-file "$NETRC" -H 'Content-Type: application/json' "$@"; }

mkdir -p "$STATE_DIR"
exec 9>"$STATE_DIR/ai_vision.lock"; flock -n 9 || { warn "ai-vision already running"; exit 0; }
[[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down — skipping"; exit 0; }
[[ -n "$CLAUDE_BIN" && -x "$CLAUDE_BIN" ]] || { warn "claude CLI not found — skipping"; exit 0; }
command -v jq >/dev/null 2>&1 || { warn "jq missing"; exit 0; }
command -v base64 >/dev/null 2>&1 || { warn "base64 missing"; exit 0; }
[[ -f "$NETRC" ]] || { warn "ES netrc missing ($NETRC)"; exit 0; }

# one-time headless sanity — bail quietly if auth/headless is broken
timeout 60 "$CLAUDE_BIN" -p "Reply with exactly: OK" 2>/dev/null | grep -q "OK" \
  || { warn "claude headless not responding (auth?) — skipping"; exit 0; }

# Map a vision class -> evidence-gate class for auto-probeable surface (the gate
# probes these read-only). Non-actionable classes return "" (no gate; the
# vision verdict is recorded but nothing auto-runs). Hard-line classes are never
# auto-probed — vision only surfaces, never exploits.
map_vision_gate_class() {
  case "${1:-}" in
    unauth-panel)      echo "unauth-surface" ;;
    install-setup)     echo "unauth-surface" ;;
    error-disclosure)  echo "content-leak" ;;
    *)                 echo "" ;;
  esac
}

# ── pull a batch of captured, un-visioned, in-scope screenshots ───────────────
# screenshot_status=ok only (a real capture). Excludes out-of-scope/ignored
# (operator bench, date-range authoritative) and anything visioned within TTL.
q="$(cat <<JSON
{
  "size": $VISION_BATCH,
  "_source": ["host","tech","title","status_code","triage_program","triage_score",
              "screenshot_path","screenshot_thumb_b64","screenshot_title"],
  "query": { "bool": {
    "filter": [ {"term":{"triage_in_scope":true}}, {"term":{"triage_pays":true}},
                {"term":{"screenshot_status":"ok"}} ],
    "must_not": [ {"term":{"triage_out_of_scope":true}}, {"term":{"triage_ignored":true}},
                  {"range":{"ignore_expires_at":{"gt":"now"}}},
                  {"range":{"claude_vision_at":{"gte":"now-$VISION_TTL"}}} ]
  }},
  "sort": [ {"triage_score":{"order":"desc","missing":"_last"}} ]
}
JSON
)"
resp="$(es "$ES_URL/$INDEX_NAME/_search" -d "$q" 2>/dev/null)" || { warn "ES query failed"; exit 0; }
[[ -z "$resp" || "$(printf '%s' "$resp" | jq -r '.error // empty')" != "" ]] && { warn "ES error: $(printf '%s' "$resp" | jq -rc '.error.type // "unknown"')"; exit 0; }
n="$(printf '%s' "$resp" | jq -r '.hits.hits | length' 2>/dev/null || echo 0)"
[[ "${n:-0}" -gt 0 ]] || { log "no un-visioned in-scope screenshots due this run"; exit 0; }
log "👁  ─── CLAUDE VISION ─── $n screenshot(s) · model=$CLAUDE_VISION_MODEL (Max, no API) · thumb-only ───"

now_iso="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
visioned=0; worth=0; gated=0; leads=0

for ((i=0; i<n; i++)); do
  [[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down mid-run — stopping"; break; }
  a="$(printf '%s' "$resp" | jq -c ".hits.hits[$i]._source")"
  host="$(printf '%s' "$a" | jq -r '.host // ""')"; [[ -z "$host" ]] && continue
  tech="$(printf '%s' "$a" | jq -r '(.tech // []) | join(",") | .[0:120]')"
  title="$(printf '%s' "$a" | jq -r '(.screenshot_title // .title // "") | .[0:80]')"
  sc="$(printf '%s' "$a" | jq -r '.status_code // 0')"
  prog="$(printf '%s' "$a" | jq -r '.triage_program // "?"')"
  thumb="$(printf '%s' "$a" | jq -r '.screenshot_thumb_b64 // ""')"
  spath="$(printf '%s' "$a" | jq -r '.screenshot_path // ""')"

  ev="$(mktemp -d "${TMPDIR:-/tmp}/aivision.XXXXXX")" || { warn "$host: mktemp failed"; continue; }
  # Prefer the tiny thumb (frugal); fall back to the full-size disk JPEG.
  if [[ -n "$thumb" && "$thumb" != "null" ]]; then
    printf '%s' "$thumb" | base64 -d > "$ev/screenshot.jpg" 2>/dev/null || : > "$ev/screenshot.jpg"
  fi
  if [[ ! -s "$ev/screenshot.jpg" && -n "$spath" && -f "$spath" ]]; then
    cp -f "$spath" "$ev/screenshot.jpg" 2>/dev/null || true
  fi
  if [[ ! -s "$ev/screenshot.jpg" ]]; then
    warn "$host: no usable screenshot image — skipping"; rm -rf "$ev"; continue
  fi

  prompt="$(cat <<EOF
You are a bug-bounty RECON analyst. READ and VIEW the screenshot ./screenshot.jpg and
classify what is ACTUALLY on screen (the pixels decide, not the metadata).
Asset: host=$host | tech=[$tech] | title="$title" | status=$sc | program=$prog

Pick exactly ONE class:
- unauth-panel: an exposed admin/dashboard/console/metrics/API UI usable WITHOUT login
  (Jenkins, Grafana, Kibana, actuator, phpMyAdmin, Prometheus, GitLab, Airflow, ...). HIGH value.
- install-setup: a fresh install / setup wizard / default "it works" landing. HIGH value.
- error-disclosure: a stack trace / debug page / verbose error / directory listing. Value.
- login-wall: a login/SSO page with nothing exposed behind it. Low.
- app-content: a normal app or content page (nothing obviously sensitive).
- parked-marketing: marketing / parking / coming-soon page.
- blank-error: blank, 404, access-denied, or a WAF/CDN block page.
- other: none of the above.

worth=true ONLY for genuinely interesting UNAUTHENTICATED surface (unauth-panel /
install-setup / error-disclosure). interest 0.0-1.0. reason: ONE sentence on what you SEE.
Output ONLY the JSON object, no prose.
EOF
)"

  out="$( cd "$ev" && timeout "$CLAUDE_TIMEOUT" "$CLAUDE_BIN" -p "$prompt" \
          --model "$CLAUDE_VISION_MODEL" --tools Read --add-dir "$ev" \
          --permission-mode dontAsk --no-session-persistence \
          --json-schema "$VISION_SCHEMA" --output-format json </dev/null 2>/dev/null)"
  v="$(printf '%s' "$out" | jq -c '.structured_output // empty' 2>/dev/null)"
  rm -rf "$ev"
  if [[ -z "$v" || "$v" == "null" ]]; then
    warn "$host: no parseable vision verdict — skipping"; continue
  fi

  cls="$(printf '%s' "$v" | jq -r '.class // "other"')"
  wv="$(printf '%s' "$v" | jq -r 'if (.worth==true) then "true" else "false" end')"
  iv="$(printf '%s' "$v" | jq -r '(.interest // 0) | tonumber? // 0')"
  why="$(printf '%s' "$v" | jq -r '.reason // ""')"
  # Store interest as an INTEGER 0-100 (the model emits 0.0-1.0). claude_vision_interest
  # dynamic-mapped to `long`; scaling x100 keeps full granularity without a 1.5M reindex.
  ivp="$(awk -v x="${iv:-0}" 'BEGIN{v=x*100; if(v<0)v=0; if(v>100)v=100; printf "%d", v+0.5}')"

  doc="$(jq -nc --arg c "$cls" --arg w "$wv" --argjson i "${ivp:-0}" --arg a "$why" \
          --arg t "$now_iso" --arg m "$CLAUDE_VISION_MODEL" \
          '{claude_vision_class:$c, claude_vision_worth:($w=="true"),
            claude_vision_interest:$i, claude_vision_reason:$a,
            claude_vision_at:$t, claude_vision_model:$m}')"

  if [[ "$wv" == "true" ]]; then
    worth=$((worth+1))
    gc="$(map_vision_gate_class "$cls")"
    if [[ -n "$gc" ]]; then
      doc="$(printf '%s' "$doc" | jq -c --arg gc "$gc" \
              '. + {triage_gate_state:"candidate", triage_gate_class:$gc, triage_gate_attempts:0}')"
      gated=$((gated+1)); route="⚙️ →gate:$gc"
    else
      leads=$((leads+1)); route="📋 →lead"
    fi
    log "   🎯 $host · $cls · int=$ivp/100 · $route"
    log "        ↳ 👁 $why"
  else
    log "   · $host · $cls (skip) · $why"
  fi

  es "$ES_URL/$INDEX_NAME/_update/$host" -X POST -d "$(jq -nc --argjson d "$doc" '{doc:$d}')" >/dev/null 2>&1 \
    || warn "$host: ES writeback failed"
  visioned=$((visioned+1))
done

es "$ES_URL/$INDEX_NAME/_refresh" >/dev/null 2>&1 || true
log "👁  vision done · 🎯 $worth worth · ⚙️ $gated gate-candidates · 📋 $leads leads  (of $visioned visioned)"

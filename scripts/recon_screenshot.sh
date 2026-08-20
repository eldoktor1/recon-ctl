#!/usr/bin/env bash
# =============================================================================
# recon_screenshot.sh — orchestrator for the Playwright screenshot module
#
# Picks status_code=200, no-CDN, in-scope, paying hosts that have not been
# screenshotted within the cooldown window, runs the Python worker against
# each in series, writes screenshot_* fields back to ES, and rebuilds an HTML
# gallery (`~/recon/screenshots/index.html`) that opens with explorer.exe.
#
# WHY THIS LIVES AS A SHELL ORCHESTRATOR
#   The Python worker has a single responsibility: capture one host, emit one
#   JSON line. All ES + scheduling + cooldown logic stays here so it shares
#   the established pipeline conventions (netrc auth, killswitch, VPN gate via
#   the daemon's supervise_loop, Discord helper, IFS rules).
#
# WHY NOT run_scanner
#   The handoff lumped screenshot in with non-target-facing modules. Screen-
#   shots are absolutely target-facing — Chromium issues TCP+TLS to every
#   host. We still run as d0k because Playwright caches and browser deps live
#   in $HOME and bouncing through sudo for every cycle is brittle. The VPN
#   guard pauses every supervise_loop (including this one) on vpn_down, so
#   nothing egresses with the real IP even briefly.
#
# CDN HOSTS ARE EXCLUDED
#   A CDN-fronted 200 is meaningless visually (it would 403 anything not
#   carrying a real session) and burns budget. Filter on cdn_name absent.
#
# COOLDOWN
#   24h by default — visual surface rarely changes faster, and we want
#   churn-budget to go toward new hosts.
# =============================================================================
set -uo pipefail
IFS=$'\n\t'

log()  { printf '[%s SCREENSHOT] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s SCREENSHOT WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/recon_net.sh"
setup_es_netrc
ES_AUTH=(--netrc-file "$HOME/.recon_es_netrc")

BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
SCREENSHOT_DIR="${SCREENSHOT_DIR:-$BASE_DIR/screenshots}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"
INDEX_NAME="${INDEX_NAME:-recon_alive}"

SHOT_VENV_PY="${SHOT_VENV_PY:-$HOME/recon/venv/screenshot/bin/python}"
SHOT_WORKER="${SHOT_WORKER:-$REPO_DIR/tools/screenshot_worker.py}"

SHOT_BATCH="${SHOT_BATCH:-25}"             # hosts/cycle in normal daemon mode
SHOT_COOLDOWN_HOURS="${SHOT_COOLDOWN_HOURS:-24}"
SHOT_MIN_SCORE="${SHOT_MIN_SCORE:-0}"      # 0 = no score gate; raise for priority-only mode
SHOT_NAV_TIMEOUT_MS="${SHOT_NAV_TIMEOUT_MS:-20000}"
SHOT_SETTLE_MS="${SHOT_SETTLE_MS:-2000}"            # post-load idle before capture
SHOT_CHALLENGE_WAIT_MS="${SHOT_CHALLENGE_WAIT_MS:-12000}"  # patience for a JS bot-challenge
SHOT_PER_HOST_BUDGET="${SHOT_PER_HOST_BUDGET:-75}"  # wall-clock s (headed + challenge-wait + 1 retry)
SHOT_BACKFILL_LIMIT="${SHOT_BACKFILL_LIMIT:-200}"   # `backfill` mode batch size
SHOT_GALLERY_CAP="${SHOT_GALLERY_CAP:-5000}"        # max thumbs rendered into the HTML gallery

# ── Anti-bot launch posture ──────────────────────────────────────────────────
# Run the browser HEADED on a virtual display — headless detection is the single
# strongest bot signal, and headed-under-Xvfb defeats a whole class of checks
# that JS-property stealth cannot reach. When Xvfb is absent we fall through to
# the worker's headless path (it self-detects no DISPLAY). When real Chrome is
# installed we use its channel (the bundled-Chromium fingerprint is what
# Akamai/DataDome flag); otherwise the worker falls back to bundled Chromium.
SHOT_XVFB_PREFIX=()
if command -v xvfb-run >/dev/null 2>&1; then
  SHOT_XVFB_PREFIX=(xvfb-run -a --server-args="-screen 0 1366x768x24 -nolisten tcp")
  export SHOT_HEADED=1
else
  export SHOT_HEADED=0
  warn "xvfb-run not found — screenshots run HEADLESS (more bot-detectable); apt install xvfb to fix"
fi
if [[ -z "${SHOT_CHROME_CHANNEL:-}" ]] && command -v google-chrome >/dev/null 2>&1; then
  export SHOT_CHROME_CHANNEL=chrome
fi

KILL_FILE="$STATE_DIR/kill/v2_screenshot"
LOCK_FILE="$STATE_DIR/screenshot.lock"
mkdir -p "$STATE_DIR" "$SCREENSHOT_DIR" "$STATE_DIR/kill"

[[ -f "$KILL_FILE" ]] && { warn "killswitch active (v2_screenshot)"; exit 0; }
# Fail-closed on VPN for ALL invocations (the daemon gates its loop, but manual
# runs — e.g. `reprocess` — are equally target-facing and must respect it too).
[[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down — skipping (fail-closed, Mullvad sole egress)"; exit 0; }
[[ -x "$SHOT_VENV_PY" ]] || { warn "venv python missing at $SHOT_VENV_PY — run 'recon-screenshot-install'"; exit 0; }
[[ -f "$SHOT_WORKER"  ]] || { warn "worker script missing at $SHOT_WORKER"; exit 1; }

exec 9>"$LOCK_FILE"
flock -n 9 || { warn "screenshot already running"; exit 0; }

MODE="${1:-cycle}"

es_curl() { curl -sS -m30 "${ES_AUTH[@]}" "$@"; }

cooldown_cutoff="$(date -u -d "-${SHOT_COOLDOWN_HOURS} hours" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || \
  python3 -c "
from datetime import datetime, timedelta
print((datetime.utcnow()-timedelta(hours=${SHOT_COOLDOWN_HOURS})).strftime('%Y-%m-%dT%H:%M:%SZ'))
")"

# ── Render the HTML gallery ────────────────────────────────────────────────
# Pulls every host with a screenshot_thumb_b64 + screenshot_status=ok and
# writes a single static index.html that previews each thumb (inline data
# URLs — no extra files to serve, opens cleanly in Windows Explorer).
# Capped at SHOT_GALLERY_CAP (default 5000) to keep render bounded; "ok only" by
# default. Thumbs are inline base64, so very large caps make a heavy HTML file.
gallery_render() {
  local cap="${1:-${SHOT_GALLERY_CAP:-5000}}"
  local out="$SCREENSHOT_DIR/index.html"
  local resp
  resp="$(es_curl -H 'Content-Type: application/json' \
    -X POST "$ES_URL/$INDEX_NAME/_search" \
    -d "$(jq -nc --argjson size "$cap" '{
      size: $size,
      _source: ["host","url","triage_priority","triage_score","triage_program",
                "triage_payout_tier","screenshot_at","screenshot_status",
                "screenshot_title","screenshot_thumb_b64","bypass_confirmed"],
      query: {bool:{filter:[
        {term:{"screenshot_status":"ok"}}
      ]}},
      sort: [
        {triage_score:{order:"desc",missing:"_last"}},
        {screenshot_at:{order:"desc"}}
      ]
    }')" 2>/dev/null)"
  local n; n="$(jq -r '.hits.hits | length' <<< "$resp" 2>/dev/null)"
  [[ -z "$n" || "$n" == "null" ]] && n=0
  log "gallery: rendering $n thumb(s) → $out"

  # Build the page in a temp file then atomic-rename (Windows Explorer holds
  # file handles when open; this avoids a half-written page being read).
  local tmp; tmp="$(mktemp "$out.tmp.XXXXXX")"
  {
    cat <<'HTMLHEAD'
<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<title>recon screenshots</title>
<style>
  body{background:#111;color:#ccc;font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;padding:1rem}
  h1{font-weight:400;font-size:1.1rem;color:#888;margin:0 0 1rem 0}
  .filter{margin:0 0 1rem 0;padding:.4rem .6rem;background:#222;color:#eee;border:1px solid #333;border-radius:4px;font:14px monospace;width:300px}
  .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:.6rem}
  .card{background:#1c1c1c;border-radius:4px;padding:.4rem;overflow:hidden;border:1px solid #2a2a2a}
  .card img{display:block;width:200px;height:150px;border-radius:3px;background:#000}
  .meta{font-size:11px;color:#aaa;padding:.35rem 0 0 0;line-height:1.3;word-break:break-all}
  .host{color:#fff;font-weight:600;font-size:12px}
  .p0{border-left:3px solid #ff4d4d}
  .p1{border-left:3px solid #ffae33}
  .by{border-left:3px solid #ff66cc}
  a{color:#5cf;text-decoration:none}
  a:hover{text-decoration:underline}
  .tag{display:inline-block;font-size:10px;color:#888;background:#222;padding:1px 4px;border-radius:2px;margin-right:3px}
</style></head><body>
HTMLHEAD
    printf '<h1>recon screenshots — %s entries, generated %s UTC</h1>\n' \
      "$n" "$(date -u '+%Y-%m-%d %H:%M:%S')"
    cat <<'HTMLFILT'
<input class="filter" id="f" placeholder="filter by host / program / title…">
<div class="grid" id="g">
HTMLFILT
    if [[ "$n" -gt 0 ]]; then
      jq -r '.hits.hits[]._source as $s |
        ($s.triage_priority // "?") as $pri |
        (if $s.bypass_confirmed then "by"
         elif $pri=="P0" then "p0"
         elif $pri=="P1" then "p1"
         else "" end) as $klass |
        ($s.url // ("https://" + $s.host)) as $href |
        ($s.host // "?")         as $host |
        ($s.triage_program // "-") as $prog |
        ($s.triage_payout_tier // "-") as $tier |
        ($s.screenshot_title // "")  as $title |
        ($s.triage_score // 0 | tostring) as $score |
        ($s.screenshot_thumb_b64) as $b64 |
        "<div class=\"card \($klass)\">"
        + "<a href=\"\($href)\" target=\"_blank\">"
        + "<img src=\"data:image/jpeg;base64,\($b64)\" alt=\"\($host)\" loading=\"lazy\"></a>"
        + "<div class=\"meta\">"
        + "<div class=\"host\"><a href=\"\($href)\" target=\"_blank\">\($host)</a></div>"
        + "<span class=\"tag\">\($pri)</span>"
        + "<span class=\"tag\">scr \($score)</span>"
        + "<span class=\"tag\">\($tier)</span>"
        + "<span class=\"tag\">\($prog)</span>"
        + (if $title != "" then "<div>\($title | gsub("<";"&lt;") | gsub(">";"&gt;"))</div>" else "" end)
        + "</div></div>"
      ' <<< "$resp" 2>/dev/null
    fi
    cat <<'HTMLFOOT'
</div>
<script>
(function(){
  var input=document.getElementById('f'), grid=document.getElementById('g');
  if(!input||!grid)return;
  input.addEventListener('input',function(){
    var q=input.value.toLowerCase().trim();
    Array.prototype.forEach.call(grid.children,function(card){
      card.style.display=q===''||card.innerText.toLowerCase().indexOf(q)>=0?'':'none';
    });
  });
})();
</script>
</body></html>
HTMLFOOT
  } > "$tmp"
  mv -f "$tmp" "$out"
  log "gallery: written ($(wc -c < "$out" | tr -d ' ') bytes)"
}

# ── Pick targets ───────────────────────────────────────────────────────────
# Three query shapes:
#   cycle:     cooldown-aware, sorted by triage_score desc (daemon mode)
#   backfill:  hosts that have NEVER been screenshotted (higher overall cap)
#   reprocess: hosts previously blocked/timeout/blank — re-shoot with the current
#              worker IGNORING cooldown (use after a worker/anti-bot improvement)
build_query() {
  local mode="$1" cap="$2"
  if [[ "$mode" == "reprocess" ]]; then
    jq -nc \
      --argjson size "$cap" \
      --argjson min_score "$SHOT_MIN_SCORE" '{
        size: $size,
        _source: ["host","url","status_code","triage_priority","triage_score",
                  "triage_program","triage_payout_tier","cdn_name"],
        query: {bool: {
          filter: [
            {terms: {screenshot_status: ["blocked","timeout","blank"]}},
            {term: {triage_in_scope: true}},
            {term: {triage_pays: true}},{bool:{must_not:{term:{triage_scan_deny:true}}}},
            {range: {triage_score: {gte: $min_score}}}
          ],
          must_not: [
            {exists: {field: "cdn_name"}}
          ]
        }},
        sort: [{triage_score: {order: "desc"}}]
      }'
  elif [[ "$mode" == "backfill" ]]; then
    jq -nc \
      --argjson size "$cap" \
      --argjson min_score "$SHOT_MIN_SCORE" '{
        size: $size,
        _source: ["host","url","status_code","triage_priority","triage_score",
                  "triage_program","triage_payout_tier","cdn_name"],
        query: {bool: {
          filter: [
            {term: {status_code: 200}},
            {term: {triage_in_scope: true}},
            {term: {triage_pays: true}},{bool:{must_not:{term:{triage_scan_deny:true}}}},
            {range: {triage_score: {gte: $min_score}}}
          ],
          must_not: [
            {exists: {field: "cdn_name"}},
            {exists: {field: "screenshot_at"}}
          ]
        }},
        sort: [{triage_score: {order: "desc"}}]
      }'
  else
    jq -nc \
      --argjson size "$cap" \
      --arg cutoff "$cooldown_cutoff" \
      --argjson min_score "$SHOT_MIN_SCORE" '{
        size: $size,
        _source: ["host","url","status_code","triage_priority","triage_score",
                  "triage_program","triage_payout_tier","cdn_name"],
        query: {bool: {
          filter: [
            {term: {status_code: 200}},
            {term: {triage_in_scope: true}},
            {term: {triage_pays: true}},{bool:{must_not:{term:{triage_scan_deny:true}}}},
            {range: {triage_score: {gte: $min_score}}}
          ],
          must_not: [
            {exists: {field: "cdn_name"}},
            {range: {screenshot_at: {gte: $cutoff}}}
          ]
        }},
        sort: [{triage_score: {order: "desc"}}]
      }'
  fi
}

# ── ES update from worker JSON ─────────────────────────────────────────────
# Builds a doc upsert from the worker's JSON line and writes it to ES.
es_update_from_json() {
  local host="$1" json="$2"
  # Extract fields safely (worker may emit screenshot_thumb_b64="" on failure
  # — we still want screenshot_at + status recorded so cooldown engages).
  local update_body
  update_body="$(jq -nc --argjson j "$json" '{
    doc: {
      screenshot_at:        ($j.screenshot_at // null),
      screenshot_status:    ($j.screenshot_status // "failed"),
      screenshot_path:      ($j.screenshot_path // ""),
      screenshot_title:     ($j.screenshot_title // ""),
      screenshot_w:         ($j.screenshot_w // 0),
      screenshot_h:         ($j.screenshot_h // 0),
      screenshot_thumb_b64: ($j.screenshot_thumb_b64 // null),
      screenshot_thumb_img: ($j.screenshot_thumb_img // null),
      screenshot_engine:    ($j.screenshot_engine // ""),
      screenshot_error:     ($j.error // "")
    }
  }')"
  es_curl -H 'Content-Type: application/json' \
    -X POST "$ES_URL/$INDEX_NAME/_update/$host" \
    -d "$update_body" > /dev/null 2>&1 || warn "ES update failed for $host"
}

# ── Run a single host ──────────────────────────────────────────────────────
shoot_one() {
  local host="$1"
  local started; started="$(date +%s)"
  # Wrap with `timeout` so a hung Chromium can never stall the daemon loop.
  local out
  out="$(timeout "$SHOT_PER_HOST_BUDGET" \
    "${SHOT_XVFB_PREFIX[@]}" "$SHOT_VENV_PY" "$SHOT_WORKER" "$host" \
      --out-dir "$SCREENSHOT_DIR" \
      --nav-timeout "$SHOT_NAV_TIMEOUT_MS" \
      --settle "$SHOT_SETTLE_MS" \
      --challenge-wait "$SHOT_CHALLENGE_WAIT_MS" 2>>"$STATE_DIR/screenshot.err" || true)"
  local elapsed=$(( $(date +%s) - started ))

  if [[ -z "$out" ]]; then
    warn "  $host: worker produced no output (timeout/crash, ${elapsed}s)"
    # Still mark screenshot_at so cooldown protects the next cycle.
    es_update_from_json "$host" "$(jq -nc \
      --arg h "$host" --arg now "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
      '{host:$h, screenshot_at:$now, screenshot_status:"failed", error:"timeout"}')"
    return
  fi
  # The worker may print stderr too; take the LAST JSON line only.
  local jsonline; jsonline="$(printf '%s\n' "$out" | tail -1)"
  if ! jq -e . >/dev/null 2>&1 <<< "$jsonline"; then
    warn "  $host: worker output not valid JSON, ignoring (${elapsed}s)"
    return
  fi
  local status; status="$(jq -r '.screenshot_status // "?"' <<< "$jsonline")"
  local title;  title="$(jq -r '.screenshot_title // ""'   <<< "$jsonline")"
  log "  $host: status=$status (${elapsed}s) title=${title:0:60}"
  es_update_from_json "$host" "$jsonline"
}

# ── Main mode dispatch ─────────────────────────────────────────────────────
case "$MODE" in
  cycle)
    cap="$SHOT_BATCH"
    log "cycle: cap=$cap cooldown=${SHOT_COOLDOWN_HOURS}h cutoff=$cooldown_cutoff"
    ;;
  backfill)
    cap="${2:-$SHOT_BACKFILL_LIMIT}"
    log "backfill: cap=$cap (one-shot, no cooldown — hosts with NO screenshot_at yet)"
    ;;
  reprocess)
    cap="${2:-$SHOT_BACKFILL_LIMIT}"
    log "reprocess: cap=$cap (re-shoot prior blocked/timeout/blank with current worker, ignoring cooldown)"
    ;;
  gallery)
    gallery_render "${2:-${SHOT_GALLERY_CAP:-5000}}"
    exit 0
    ;;
  test)
    host="${2:?usage: recon_screenshot.sh test <host>}"
    log "test: single host = $host"
    shoot_one "$host"
    gallery_render "${SHOT_GALLERY_CAP:-5000}"
    exit 0
    ;;
  *)
    cat >&2 <<USAGE
Usage: recon_screenshot.sh [cycle|backfill [N]|reprocess [N]|gallery [N]|test <host>]

  cycle              cooldown-aware daemon batch (default; SHOT_BATCH=$SHOT_BATCH)
  backfill [N]       hosts with NO screenshot_at yet, larger batch (default $SHOT_BACKFILL_LIMIT)
  reprocess [N]      re-shoot prior blocked/timeout/blank hosts with the current
                     worker, ignoring cooldown (default $SHOT_BACKFILL_LIMIT)
  gallery [N]        rebuild HTML gallery only (default 1000 entries)
  test <host>        screenshot one host now, then rebuild gallery
USAGE
    exit 2
    ;;
esac

resp="$(es_curl -H 'Content-Type: application/json' \
  -X POST "$ES_URL/$INDEX_NAME/_search" \
  -d "$(build_query "$MODE" "$cap")" 2>/dev/null)"

total="$(printf '%s' "$resp" | jq -r '.hits.total.value // 0')"
got="$(printf '%s' "$resp" | jq -r '.hits.hits | length')"
log "candidates matched: total_in_es=$total, returning=$got"
[[ "$got" -eq 0 ]] && { log "nothing to capture this cycle"; gallery_render "${SHOT_GALLERY_CAP:-5000}"; exit 0; }

ok_n=0; blk_n=0; fail_n=0
while IFS= read -r host; do
  [[ -z "$host" ]] && continue
  shoot_one "$host"
  # Tally — re-read latest ES doc would be slower; parse from the err file is messy.
  # Use a per-call status capture: shoot_one already logged. We do a tiny ES read.
  st="$(es_curl "$ES_URL/$INDEX_NAME/_doc/$host?_source=screenshot_status" 2>/dev/null \
        | jq -r '._source.screenshot_status // "?"')"
  case "$st" in
    ok)      ok_n=$(( ok_n + 1 )) ;;
    blocked) blk_n=$(( blk_n + 1 )) ;;
    *)       fail_n=$(( fail_n + 1 )) ;;
  esac
  sleep 0.4
done < <(printf '%s' "$resp" | jq -r '.hits.hits[]._source.host')

es_curl -X POST "$ES_URL/$INDEX_NAME/_refresh" > /dev/null 2>&1 || true

log "=== cycle done: ok=$ok_n blocked=$blk_n failed=$fail_n ==="

gallery_render "${SHOT_GALLERY_CAP:-5000}"

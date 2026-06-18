#!/usr/bin/env bash
# =============================================================================
# recon_domxss_confirm.sh — U6 DOM-XSS lane: dalfox headless EXECUTION confirm.
#
# Research (2026-06-17): XSS has moved reflected -> DOM (location.hash/postMessage/
# prototype-pollution -> sink). The reflected confirmers (xss-confirm/param-confirm) are
# BLIND to it. Best autonomous tool = dalfox `--deep-domxss --force-headless-verification`
# (installed; AST + real headless Chromium — a [POC] line = the payload EXECUTED, not merely
# reflected). DOMDig is the deep-SPA v2/on-demand. See docs/knowledge/class-unauth-hunting.md U6.
#
# Reads XSS candidate URLs from the recon_params catalog (in-scope+paying), runs dalfox DOM
# headless per URL, and on a verified [POC] records: state.py record-confirmed
# (signal_class=dom-xss) -> ai-pending -> 2IC verify -> SUBMIT. Reflection != XSS (dalfox's
# own headless check is the gate). GET-only, rate-limited, Mullvad + live-scope gated, bounded
# (headless is heavy). Target-facing -> run via run_scanner (reconrun) from the daemon.
# =============================================================================
set -uo pipefail
IFS=$'\n\t'
log()  { printf '[%s DOMXSS] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s DOMXSS WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/recon_net.sh" 2>/dev/null || true
BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
V3_DB="${V3_DB:-$BASE_DIR/v3/findings.db}"
STATE_PY="${STATE_PY:-$REPO_DIR/engine/state.py}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"
INDEX_NAME="${INDEX_NAME:-recon_alive}"
PARAMS_INDEX="${PARAMS_INDEX:-recon_params}"
NETRC="${NETRC:-$HOME/.recon_es_netrc}"
DALFOX="${DALFOX:-$(command -v dalfox 2>/dev/null || echo "$HOME/go/bin/dalfox")}"
SEEN="${DOMXSS_SEEN:-$STATE_DIR/domxss_confirm_seen.txt}"
DOMXSS_BATCH="${DOMXSS_BATCH:-6}"          # URLs per cycle (headless is heavy — keep small)
DOMXSS_DELAY="${DOMXSS_DELAY:-400}"        # ms between dalfox requests (polite)
DOMXSS_TIMEOUT="${DOMXSS_TIMEOUT:-120}"    # hard wall-clock cap per URL
DOMXSS_SKIP_PROGRAMS="${DOMXSS_SKIP_PROGRAMS:-synergie}"  # "no automated scanners" programs

es() { curl -fsS -m 20 --netrc-file "$NETRC" -H 'Content-Type: application/json' "$@"; }
in_scope_now() {
  local _sc="$SCRIPT_DIR/recon_scope_check.sh"
  if [[ -f "$_sc" ]]; then
    [[ "$(bash "$_sc" "$1" 2>/dev/null | jq -r '((.in_scope//false)==true) and ((.pays//false)==true) and ((.out_of_scope//false)!=true)' 2>/dev/null)" == "true" ]]
  else
    [[ "$(es "$ES_URL/$INDEX_NAME/_source/$1" 2>/dev/null | jq -r '((.triage_in_scope//false)==true) and ((.triage_pays//false)==true) and ((.triage_out_of_scope//false)!=true)' 2>/dev/null)" == "true" ]]
  fi
}

mkdir -p "$STATE_DIR" "$(dirname "$V3_DB")" 2>/dev/null || true
exec 9>"$STATE_DIR/domxss_confirm.lock"; flock -n 9 || { warn "already running"; exit 0; }
[[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down — refusing to probe (fail-closed)"; exit 0; }
command -v jq >/dev/null 2>&1 || { warn "jq missing"; exit 0; }
command -v python3 >/dev/null 2>&1 || { warn "python3 missing"; exit 0; }
[[ -x "$DALFOX" ]] || { warn "dalfox not found ($DALFOX)"; exit 0; }
es "$ES_URL/$PARAMS_INDEX/_count" >/dev/null 2>&1 || { log "no params catalog ($PARAMS_INDEX) yet"; exit 0; }
touch "$SEEN"

# XSS candidates: in-scope+paying, freshest first
q="$(jq -nc --argjson n "$DOMXSS_BATCH" \
      '{size:($n*4), _source:["url","host","program"],
        query:{bool:{filter:[{term:{vuln_classes:"xss"}}],must_not:[{term:{payout_tier:"none"}}]}},
        sort:[{true_fresh:{order:"desc",missing:"_last"}},{cataloged_at:{order:"desc"}}]}')"
resp="$(es "$ES_URL/$PARAMS_INDEX/_search" -d "$q" 2>/dev/null)" || { warn "ES query failed"; exit 0; }
mapfile -t urls < <(printf '%s' "$resp" | jq -r '.hits.hits[]._source.url // empty' 2>/dev/null \
                    | awk 'NF && !seen[$0]++' | grep -vxF -f "$SEEN" 2>/dev/null | head -n "$DOMXSS_BATCH")
[[ "${#urls[@]}" -gt 0 ]] || { log "no fresh XSS candidates"; exit 0; }

log "🧪 DOM-XSS confirm · ${#urls[@]} candidate URL(s) · dalfox --deep-domxss --force-headless-verification"
confirmed=0; tested=0
for url in "${urls[@]}"; do
  [[ -z "$url" ]] && continue
  [[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down mid-run — stopping"; break; }
  host="$(printf '%s' "$url" | sed -E 's#^[a-z]+://([^/:]+).*#\1#')"
  in_scope_now "$host" || { printf '%s\n' "$url" >> "$SEEN"; continue; }
  prog="$(es "$ES_URL/$INDEX_NAME/_source/$host" 2>/dev/null | jq -r '.triage_program // ""' 2>/dev/null)"
  if printf '%s' "$prog" | grep -qiE "$DOMXSS_SKIP_PROGRAMS"; then printf '%s\n' "$url" >> "$SEEN"; continue; fi
  # dalfox DOM + headless EXECUTION verify. --skip-bav = no basic-other-vuln noise; GET; polite.
  out="$(timeout "$DOMXSS_TIMEOUT" "$DALFOX" url "$url" --deep-domxss --force-headless-verification \
        --skip-bav -w 1 --delay "$DOMXSS_DELAY" --timeout 30 --format plain --silence 2>/dev/null)"
  printf '%s\n' "$url" >> "$SEEN"; tested=$((tested+1))
  printf '%s' "$out" | grep -qE '\[POC\]' || continue
  poc="$(printf '%s' "$out" | grep -E '\[POC\]' | head -1 | cut -c1-300)"
  ev="$(jq -nc --arg p "$poc" --arg u "$url" \
        '{probe:"dalfox-domxss", poc:$p, evidence:("dalfox headless VERIFIED DOM/XSS EXECUTION: "+$p), matched_at:$u}' 2>/dev/null)"
  V3_DB="$V3_DB" python3 "$STATE_PY" record-confirmed "$host" "$url" "$prog" "dom-xss" "xss" "15" "0.9" "$ev" >/dev/null 2>&1 \
    && { confirmed=$((confirmed+1)); log "   💥 DOM-XSS VERIFIED (dalfox headless) · $host"; }
  es -X POST "$ES_URL/$INDEX_NAME/_update/$host" -d "$(jq -nc --argjson e "${ev:-{}}" \
      '{doc:{triage_gate_state:"confirmed", triage_gate_class:"dom-xss", triage_gate_evidence:$e}}')" >/dev/null 2>&1 || true
done

tail -n 8000 "$SEEN" > "$SEEN.tmp" 2>/dev/null && mv "$SEEN.tmp" "$SEEN" 2>/dev/null || true
log "🧪 DOM-XSS confirm done · 💥 $confirmed verified / $tested tested"
exit 0

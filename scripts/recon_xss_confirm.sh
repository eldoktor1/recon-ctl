#!/usr/bin/env bash
# =============================================================================
# recon_xss_confirm.sh — turn reflected-XSS LEADs into CONFIRMED findings.
#
# recon_params `verify xss` proves a canary REFLECTS (a LEAD). This step loads each
# reflected URL in headless Chromium (tools/xss_confirm_worker.py) and confirms the
# injected JS actually EXECUTES — the article's "detection != exploitation" gate for
# the XSS class. Executes => record CONFIRMED in SQLite (-> Claude verify -> #review);
# else the lead is left as reflected-not-exploitable.
#
# TARGET-FACING (Chromium hits the host): runs as d0k (Playwright cache in $HOME) and
# is VPN-gated fail-closed — refuses to probe while vpn_down. Unauthenticated +
# non-destructive (marker alert only). Bounded per cycle; per-URL cooldown via seen-file.
# =============================================================================
set -uo pipefail
IFS=$'\n\t'

log()  { printf '[%s XSS-CONFIRM] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s XSS-CONFIRM WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/recon_net.sh" 2>/dev/null || true
BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
V3_DB="${V3_DB:-$BASE_DIR/v3/findings.db}"
STATE_PY="${STATE_PY:-$REPO_DIR/engine/state.py}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"
INDEX_NAME="${INDEX_NAME:-recon_alive}"
NETRC="${NETRC:-$HOME/.recon_es_netrc}"
SHOT_VENV_PY="${SHOT_VENV_PY:-$HOME/recon/venv/screenshot/bin/python}"
WORKER="${XSS_WORKER:-$REPO_DIR/tools/xss_confirm_worker.py}"
LEADS="${XSS_LEADS:-$BASE_DIR/params/verify_xss.jsonl}"
SEEN="${XSS_SEEN:-$STATE_DIR/xss_confirm_seen.txt}"
XSS_BATCH="${XSS_BATCH:-15}"
es() { curl -fsS -m 20 --netrc-file "$NETRC" -H 'Content-Type: application/json' "$@"; }
# Live scope guard (authoritative at probe time): a host is "game" only if it is
# CURRENTLY in-scope + paying + not out-of-scope — never trust stale catalog scope.
in_scope_now() {
  [[ "$(es "$ES_URL/$INDEX_NAME/_source/$1" 2>/dev/null | jq -r \
     '((.triage_in_scope//false)==true) and ((.triage_pays//false)==true) and ((.triage_out_of_scope//false)!=true)' 2>/dev/null)" == "true" ]]
}

mkdir -p "$STATE_DIR"
exec 9>"$STATE_DIR/xss_confirm.lock"; flock -n 9 || { warn "already running"; exit 0; }
# TARGET-FACING: fail closed if egress is not confirmed on the VPN.
[[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down — refusing to probe targets"; exit 0; }
[[ -x "$SHOT_VENV_PY" ]] || { warn "playwright venv missing ($SHOT_VENV_PY) — run: recon-ctl screenshot install"; exit 0; }
[[ -f "$WORKER" ]] || { warn "worker missing ($WORKER)"; exit 0; }
[[ -s "$LEADS" ]] || { log "no reflected-xss leads to confirm ($LEADS)"; exit 0; }
command -v jq >/dev/null 2>&1 || { warn "jq missing"; exit 0; }
touch "$SEEN"

# unique, not-yet-tested reflected URLs (newest first), bounded
mapfile -t urls < <(tac "$LEADS" 2>/dev/null | jq -r '.url // empty' 2>/dev/null \
                    | awk 'NF && !seen[$0]++' | grep -vxF -f "$SEEN" 2>/dev/null | head -n "$XSS_BATCH")
[[ "${#urls[@]}" -gt 0 ]] || { log "no fresh reflected-xss leads (all tested)"; exit 0; }
log "🧪 ─── XSS CONFIRM ─── ${#urls[@]} reflected lead(s) · headless Chromium marker-exec ───"

confirmed=0; tested=0
for url in "${urls[@]}"; do
  [[ -z "$url" ]] && continue
  [[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down mid-run — stopping"; break; }
  host="$(printf '%s' "$url" | sed -E 's#^[a-z]+://([^/:]+).*#\1#')"
  in_scope_now "$host" || { printf '%s\n' "$url" >> "$SEEN"; continue; }   # live scope guard
  out="$(timeout 90 "$SHOT_VENV_PY" "$WORKER" "$url" 2>/dev/null)"
  printf '%s\n' "$url" >> "$SEEN"     # cooldown: don't retest this URL next cycle
  tested=$((tested+1))
  [[ -z "$out" ]] && continue
  executed="$(printf '%s' "$out" | jq -r '.executed // false' 2>/dev/null)"
  [[ "$executed" == "true" ]] || continue
  prog="$(es "$ES_URL/$INDEX_NAME/_source/$host" 2>/dev/null | jq -r '.triage_program // ""' 2>/dev/null)"
  ev="$(printf '%s' "$out" | jq -c '{probe:"browser-xss", context:.context, param:.param, payload:.payload, poc_url:.poc_url, matched_at:.url}' 2>/dev/null)"
  # CONFIRMED execution -> SQLite state machine (-> Claude verify -> #review). conf 0.9.
  V3_DB="$V3_DB" python3 "$STATE_PY" record-confirmed "$host" "$url" "$prog" "xss" "xss" "15" "0.9" "$ev" >/dev/null 2>&1 || true
  # reflect in ES too so triage/dashboards see the confirmation
  es -X POST "$ES_URL/$INDEX_NAME/_update/$host" -d "$(jq -nc --argjson e "${ev:-{}}" \
      '{doc:{triage_gate_state:"confirmed", triage_gate_class:"xss", triage_gate_evidence:$e}}')" >/dev/null 2>&1 || true
  confirmed=$((confirmed+1))
  log "   💥 XSS CONFIRMED (executes) · $host · param=$(printf '%s' "$out" | jq -r '.param // "?"') → SQLite → verify"
done

# keep the seen-file bounded
tail -n 5000 "$SEEN" > "$SEEN.tmp" 2>/dev/null && mv "$SEEN.tmp" "$SEEN" 2>/dev/null || true
log "🧪 xss-confirm done · 💥 $confirmed confirmed / $tested tested"

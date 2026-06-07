#!/usr/bin/env bash
# =============================================================================
# recon_param_confirm.sh — SAFE differential confirmation for SSTI / open-redirect
# / SQLi across the sus-params catalog. Widens the reliable net beyond XSS while
# holding the line: precise NON-DESTRUCTIVE, UNAUTHENTICATED differential probes
# (template math eval / redirect-to-canary / error-based diff) — never data harvest
# or RCE. Confirmed -> SQLite -> Claude verify (FP filter) -> #review.
#
# TARGET-FACING (HTTP to the host): VPN-gated fail-closed. Reads candidate param-URLs
# from the recon_params catalog (already in-scope-only) by vuln_class. Bounded per
# class; per-URL cooldown via seen-file. Runs as d0k.
# =============================================================================
set -uo pipefail
IFS=$'\n\t'

log()  { printf '[%s PARAM-CONFIRM] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s PARAM-CONFIRM WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/recon_net.sh" 2>/dev/null || true
BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
V3_DB="${V3_DB:-$BASE_DIR/v3/findings.db}"
STATE_PY="${STATE_PY:-$REPO_DIR/v3/state.py}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"
INDEX_NAME="${INDEX_NAME:-recon_alive}"
PARAMS_INDEX="${PARAMS_INDEX:-recon_params}"
NETRC="${NETRC:-$HOME/.recon_es_netrc}"
WORKER="${PARAM_WORKER:-$REPO_DIR/tools/param_confirm_worker.py}"
SEEN="${PARAM_SEEN:-$STATE_DIR/param_confirm_seen.txt}"
PC_CLASSES="${PC_CLASSES:-ssti redirect sqli}"
PC_BATCH="${PC_BATCH:-10}"                 # URLs per class per cycle (quota/load bound)
es() { curl -fsS -m 20 --netrc-file "$NETRC" -H 'Content-Type: application/json' "$@"; }
# Live scope guard (authoritative at probe time): only probe a host that is CURRENTLY
# in-scope + paying + not out-of-scope — never trust stale catalog scope.
in_scope_now() {
  [[ "$(es "$ES_URL/$INDEX_NAME/_source/$1" 2>/dev/null | jq -r \
     '((.triage_in_scope//false)==true) and ((.triage_pays//false)==true) and ((.triage_out_of_scope//false)!=true)' 2>/dev/null)" == "true" ]]
}

mkdir -p "$STATE_DIR"
exec 9>"$STATE_DIR/param_confirm.lock"; flock -n 9 || { warn "already running"; exit 0; }
[[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down — refusing to probe targets"; exit 0; }
[[ -f "$WORKER" ]] || { warn "worker missing ($WORKER)"; exit 0; }
command -v jq >/dev/null 2>&1 || { warn "jq missing"; exit 0; }
command -v python3 >/dev/null 2>&1 || { warn "python3 missing"; exit 0; }
es "$ES_URL/$PARAMS_INDEX/_count" >/dev/null 2>&1 || { log "no params catalog ($PARAMS_INDEX) yet"; exit 0; }
touch "$SEEN"

confirmed_total=0; tested_total=0
for cls in $PC_CLASSES; do
  [[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down mid-run — stopping"; break; }
  # in-scope paying candidates for this class, freshest first
  q="$(jq -nc --arg c "$cls" --argjson n "$PC_BATCH" \
        '{size:($n*3), _source:["url","host","program"],
          query:{bool:{filter:[{term:{vuln_classes:$c}}],
                       must_not:[{term:{payout_tier:"none"}}]}},
          sort:[{true_fresh:{order:"desc",missing:"_last"}},{cataloged_at:{order:"desc"}}]}')"
  resp="$(es "$ES_URL/$PARAMS_INDEX/_search" -d "$q" 2>/dev/null)" || continue
  mapfile -t urls < <(printf '%s' "$resp" | jq -r '.hits.hits[]._source.url // empty' 2>/dev/null \
                      | awk 'NF && !seen[$0]++' | grep -vxF -f "$SEEN" 2>/dev/null | head -n "$PC_BATCH")
  [[ "${#urls[@]}" -gt 0 ]] || { log "$cls: no fresh candidates"; continue; }
  log "$cls: confirming ${#urls[@]} candidate param-URL(s)"
  for url in "${urls[@]}"; do
    [[ -z "$url" ]] && continue
    [[ -f "$STATE_DIR/vpn_down" ]] && break
    host="$(printf '%s' "$url" | sed -E 's#^[a-z]+://([^/:]+).*#\1#')"
    in_scope_now "$host" || { printf '%s\n' "$url" >> "$SEEN"; continue; }   # live scope guard
    out="$(timeout 60 python3 "$WORKER" "$url" "$cls" 2>/dev/null)"
    printf '%s\n' "$url" >> "$SEEN"
    tested_total=$((tested_total+1))
    [[ -z "$out" ]] && continue
    [[ "$(printf '%s' "$out" | jq -r '.confirmed // false' 2>/dev/null)" == "true" ]] || continue
    prog="$(es "$ES_URL/$INDEX_NAME/_source/$host" 2>/dev/null | jq -r '.triage_program // ""' 2>/dev/null)"
    ev="$(printf '%s' "$out" | jq -c '{probe:("param-"+.class), context:.context, param:.param, payload:.payload, evidence:.evidence, matched_at:.url}' 2>/dev/null)"
    V3_DB="$V3_DB" python3 "$STATE_PY" record-confirmed "$host" "$url" "$prog" "$cls" "$cls" "15" "0.85" "$ev" >/dev/null 2>&1 || true
    es -X POST "$ES_URL/$INDEX_NAME/_update/$host" -d "$(jq -nc --arg c "$cls" --argjson e "${ev:-{}}" \
        '{doc:{triage_gate_state:"confirmed", triage_gate_class:$c, triage_gate_evidence:$e}}')" >/dev/null 2>&1 || true
    confirmed_total=$((confirmed_total+1))
    log "  CONFIRMED $cls: $host  ($(printf '%s' "$out" | jq -r '.param // "?"'))"
  done
done

tail -n 8000 "$SEEN" > "$SEEN.tmp" 2>/dev/null && mv "$SEEN.tmp" "$SEEN" 2>/dev/null || true
log "param-confirm done — tested=$tested_total confirmed=$confirmed_total"

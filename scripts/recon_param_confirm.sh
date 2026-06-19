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
STATE_PY="${STATE_PY:-$REPO_DIR/engine/state.py}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"
INDEX_NAME="${INDEX_NAME:-recon_alive}"
PARAMS_INDEX="${PARAMS_INDEX:-recon_params}"
NETRC="${NETRC:-$HOME/.recon_es_netrc}"
WORKER="${PARAM_WORKER:-$REPO_DIR/tools/param_confirm_worker.py}"
SEEN="${PARAM_SEEN:-$STATE_DIR/param_confirm_seen.txt}"
PC_CLASSES="${PC_CLASSES:-ssti redirect sqli nosqli}"
PC_BATCH="${PC_BATCH:-10}"                 # URLs per class per cycle (quota/load bound)
# sqlmap SQLi VERIFY (operator-authorized 2026-06-17, in-scope+paying only). PoC depth only
# (--banner/--current-db), NEVER mass --dump of third-party data, NO stacked (technique excludes S),
# rate-limited (--delay 1 --threads 1) so it never bans the Mullvad exit, bounded per cycle (anti-burn),
# skip "no automated scanners" programs. See CLAUDE.md SQLi hard line + project_xss_sqli_rs0n_lane.
SQLMAP_BIN="${SQLMAP_BIN:-$(command -v sqlmap 2>/dev/null || echo '')}"
SQLMAP_BATCH="${SQLMAP_BATCH:-3}"          # sqlmap runs per cycle (gentle; unseen overflow retried next cycle)
SQLMAP_TIMEOUT="${SQLMAP_TIMEOUT:-240}"    # hard wall-clock cap per URL
SQLMAP_SKIP_PROGRAMS="${SQLMAP_SKIP_PROGRAMS:-synergie}"   # programs whose rules forbid automated scanners
es() { curl -fsS -m 20 --netrc-file "$NETRC" -H 'Content-Type: application/json' "$@"; }
# Live scope guard (authoritative at probe time): only probe a host that is CURRENTLY
# in-scope + paying + not out-of-scope — never trust stale catalog scope.
in_scope_now() {
  # AUTHORITATIVE scope DB (recon_scope_check.sh) — not stale ES triage_* (matches recon_safe_probe.sh).
  local _sc="$SCRIPT_DIR/recon_scope_check.sh"
  if [[ -f "$_sc" ]]; then
    [[ "$(bash "$_sc" "$1" 2>/dev/null | jq -r \
       '((.in_scope//false)==true) and ((.pays//false)==true) and ((.out_of_scope//false)!=true)' 2>/dev/null)" == "true" ]]
  else
    [[ "$(es "$ES_URL/$INDEX_NAME/_source/$1" 2>/dev/null | jq -r \
       '((.triage_in_scope//false)==true) and ((.triage_pays//false)==true) and ((.triage_out_of_scope//false)!=true)' 2>/dev/null)" == "true" ]]
  fi
}

# sqlmap SQLi verify: gentle, PoC-depth, read-only. Prints JSON {dbms,evidence} on confirm, else empty.
# technique=BEUT (Boolean/Error/Union/Time) — EXCLUDES Stacked (S) so no write/destructive queries.
# --banner/--current-db = PoC (version + db NAME), never a data dump. Output dir is a throwaway /tmp.
sqlmap_verify() {
  local url="$1" od out dbms
  [[ -n "$SQLMAP_BIN" ]] || return 0
  od="$(mktemp -d "${TMPDIR:-/tmp}/sqlmapv.XXXXXX")"
  out="$(timeout "$SQLMAP_TIMEOUT" "$SQLMAP_BIN" -u "$url" --batch --random-agent \
        --level 1 --risk 1 --technique=BEUT --threads 1 --delay 1 --time-sec 5 \
        --timeout 15 --retries 1 --crawl 0 --flush-session --banner --current-db \
        --disable-coloring --answers="quit=N,crack=N,dict=N,continue=Y" -v1 \
        --output-dir="$od" 2>/dev/null)"
  rm -rf "$od" 2>/dev/null
  printf '%s' "$out" | grep -qiE "the following injection point|sqlmap identified|is vulnerable|back-end DBMS:" || return 0
  dbms="$(printf '%s' "$out" | grep -ioE "back-end DBMS:.*" | head -1 | sed 's/[[:space:]]*$//')"
  [[ -n "$dbms" ]] || dbms="injection point confirmed (DBMS unidentified)"
  jq -nc --arg d "$dbms" '{confirmed:true, dbms:$d, evidence:("sqlmap VERIFIED SQL injection — "+$d+" (PoC: --banner/--current-db; NO data dumped)")}'
}

mkdir -p "$STATE_DIR"
exec 9>"$STATE_DIR/param_confirm.lock"; flock -n 9 || { warn "already running"; exit 0; }
[[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down — refusing to probe targets"; exit 0; }
[[ -f "$WORKER" ]] || { warn "worker missing ($WORKER)"; exit 0; }
command -v jq >/dev/null 2>&1 || { warn "jq missing"; exit 0; }
command -v python3 >/dev/null 2>&1 || { warn "python3 missing"; exit 0; }
es "$ES_URL/$PARAMS_INDEX/_count" >/dev/null 2>&1 || { log "no params catalog ($PARAMS_INDEX) yet"; exit 0; }
touch "$SEEN"

confirmed_total=0; tested_total=0; sqlmap_done=0
IFS=' ' read -ra _PC_ARR <<< "$PC_CLASSES"   # split on space (global IFS=$'\n\t' would NOT)
for cls in "${_PC_ARR[@]}"; do
  [[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down mid-run — stopping"; break; }
  # per-class seen ledger so classes don't starve each other's candidate pool — nosqli rides the
  # SAME sqli param surface (no gf "nosqli" class) and must not consume sqli's sqlmap candidates.
  SEEN="$STATE_DIR/param_confirm_seen_${cls}.txt"; touch "$SEEN"
  qcls="$cls"; [[ "$cls" == "nosqli" ]] && qcls="sqli"
  # in-scope paying candidates for this class. RANDOM-SAMPLE the catalog (true_fresh boosted),
  # not a frozen freshest-N sort: the old sort always returned the SAME top-N, which the seen-
  # ledger then filtered to empty within a few cycles ("no fresh candidates" forever despite a
  # 25k catalog — the yield.params silent-zero). A per-cycle random_score slides the window
  # across the whole catalog so the lane keeps surfacing un-probed URLs. Pull a wide window
  # (n*10) so the client-side seen-filter still leaves a full batch.
  seed=$(( (RANDOM << 15) | RANDOM ))
  q="$(jq -nc --arg c "$qcls" --argjson n "$PC_BATCH" --argjson seed "$seed" \
        '{size:($n*10), _source:["url","host","program"],
          query:{function_score:{
            query:{bool:{filter:[{term:{vuln_classes:$c}}],
                         must_not:[{term:{payout_tier:"none"}}]}},
            functions:[{random_score:{seed:$seed,field:"_seq_no"}},
                       {filter:{term:{true_fresh:true}},weight:2}],
            score_mode:"sum", boost_mode:"replace"}}}')"
  resp="$(es "$ES_URL/$PARAMS_INDEX/_search" -d "$q" 2>/dev/null)" || continue
  mapfile -t urls < <(printf '%s' "$resp" | jq -r '.hits.hits[]._source.url // empty' 2>/dev/null \
                      | awk 'NF && !seen[$0]++' | grep -vxF -f "$SEEN" 2>/dev/null | head -n "$PC_BATCH")
  [[ "${#urls[@]}" -gt 0 ]] || { log "$cls: no fresh candidates"; continue; }
  log "🧪 ─── PARAM CONFIRM [$cls] ─── ${#urls[@]} candidate param-URL(s) · differential probe ───"
  for url in "${urls[@]}"; do
    [[ -z "$url" ]] && continue
    [[ -f "$STATE_DIR/vpn_down" ]] && break
    host="$(printf '%s' "$url" | sed -E 's#^[a-z]+://([^/:]+).*#\1#')"
    in_scope_now "$host" || { printf '%s\n' "$url" >> "$SEEN"; continue; }   # live scope guard
    # SQLi → sqlmap VERIFY (operator-authorized; gentle, bounded, PoC-depth, skip no-scanner programs).
    # Catches blind/time/union the cheap '-vs-'' worker misses. Falls through to the worker if sqlmap absent.
    if [[ "$cls" == "sqli" && -n "$SQLMAP_BIN" ]]; then
      [[ "$sqlmap_done" -ge "$SQLMAP_BATCH" ]] && break   # per-cycle cap; unseen overflow retried next cycle
      prog="$(es "$ES_URL/$INDEX_NAME/_source/$host" 2>/dev/null | jq -r '.triage_program // ""' 2>/dev/null)"
      if printf '%s' "$prog" | grep -qiE "$SQLMAP_SKIP_PROGRAMS"; then printf '%s\n' "$url" >> "$SEEN"; continue; fi
      res="$(sqlmap_verify "$url")"
      sqlmap_done=$((sqlmap_done+1)); tested_total=$((tested_total+1)); printf '%s\n' "$url" >> "$SEEN"
      [[ -n "$res" ]] || continue
      ev="$(printf '%s' "$res" | jq -c --arg u "$url" '{probe:"sqlmap", dbms:.dbms, evidence:.evidence, matched_at:$u}' 2>/dev/null)"
      V3_DB="$V3_DB" python3 "$STATE_PY" record-confirmed "$host" "$url" "$prog" "sqli" "sqli" "15" "0.92" "$ev" >/dev/null 2>&1 || true
      es -X POST "$ES_URL/$INDEX_NAME/_update/$host" -d "$(jq -nc --argjson e "${ev:-{}}" '{doc:{triage_gate_state:"confirmed", triage_gate_class:"sqli", triage_gate_evidence:$e}}')" >/dev/null 2>&1 || true
      confirmed_total=$((confirmed_total+1))
      log "   💥 sqli VERIFIED (sqlmap) · $host · $(printf '%s' "$res" | jq -r '.dbms // "?"')"
      continue
    fi
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
    log "   💥 ${cls} CONFIRMED · $host · param=$(printf '%s' "$out" | jq -r '.param // "?"') → SQLite → verify"
  done
done

for _sf in "$STATE_DIR"/param_confirm_seen_*.txt; do [[ -f "$_sf" ]] && { tail -n 8000 "$_sf" > "$_sf.tmp" 2>/dev/null && mv "$_sf.tmp" "$_sf" 2>/dev/null; }; done
# Activity heartbeat for the yield self-audit: write ONLY when we actually PROBED candidates
# (tested>0). A strict FP-averse confirm lane legitimately confirms 0 for long stretches — that
# is healthy, not a silent-zero. observability checks this file's freshness to tell a LIVE lane
# (probing, just nothing met the bar) from a genuinely starved/broken one (the pre-fix state).
[[ "$tested_total" -gt 0 ]] && printf '{"ts":"%s","tested":%s,"confirmed":%s}\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$tested_total" "$confirmed_total" \
  > "$STATE_DIR/param_confirm_status.json" 2>/dev/null || true
log "🧪 param-confirm done · 💥 $confirmed_total confirmed / $tested_total tested"

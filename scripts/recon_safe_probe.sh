#!/usr/bin/env bash
# =============================================================================
# recon_safe_probe.sh — the ONLY target-facing tool the Claude VERIFY agent may drive.
#
# Wraps safe_probe_worker.py with operator guards so it is safe regardless of caller
# intent (the caller is an LLM that could be prompt-injected by target content):
#   * vpn_down  -> refuse (fail-closed; Mullvad is sole egress via the OS killswitch)
#   * live scope gate -> only in-scope, paying, not-out-of-scope hosts (authoritative now)
#   * per-finding BUDGET -> caps probes per single verification (anti-runaway)
#   * ANTI-BURN rate limiting (so we never get banned / WAF-blocked — the article's rule):
#       - min gap between probes to the same host
#       - per-host rolling-window cap
#       - global rolling-window cap
#       - host COOLDOWN on a 429/403/503 (back off a target the moment it pushes back)
#       - global CIRCUIT-BREAKER: too many blocks in a short window -> pause ALL probing
#   * full AUDIT log (accountability)
# The worker enforces: unauth only, GET/HEAD/OPTIONS only, no redirect-follow, no
# internal/metadata targets, size-capped body. One url(+method) in, one JSON line out,
# always exit 0.
#
# Usage: recon_safe_probe.sh <url> [GET|HEAD|OPTIONS]
# Env (caller, per finding): SAFE_PROBE_LEDGER, SAFE_PROBE_BUDGET
# Env (rate-limit tunables): PROBE_MIN_GAP, PROBE_RL_PER_HOST, PROBE_RL_WINDOW,
#   PROBE_RL_GLOBAL, PROBE_HOST_COOLDOWN, PROBE_GLOBAL_BLOCK_TRIP, PROBE_GLOBAL_PAUSE
# =============================================================================
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"
INDEX_NAME="${INDEX_NAME:-recon_alive}"
NETRC="${NETRC:-$HOME/.recon_es_netrc}"
WORKER="${SAFE_PROBE_WORKER:-$REPO_DIR/tools/safe_probe_worker.py}"
AUDIT="${SAFE_PROBE_AUDIT:-$STATE_DIR/safe_probe_audit.log}"
LEDGER="${SAFE_PROBE_LEDGER:-}"            # per-finding counter file (set by caller)
BUDGET="${SAFE_PROBE_BUDGET:-8}"           # max probes against this ledger
# anti-burn defaults (polite: ~6 req / host / min, 30 global / min, 2s min gap, 15m cooldown)
PROBE_MIN_GAP="${PROBE_MIN_GAP:-2}"
PROBE_RL_PER_HOST="${PROBE_RL_PER_HOST:-6}"
PROBE_RL_WINDOW="${PROBE_RL_WINDOW:-60}"
PROBE_RL_GLOBAL="${PROBE_RL_GLOBAL:-30}"
PROBE_HOST_COOLDOWN="${PROBE_HOST_COOLDOWN:-900}"
PROBE_GLOBAL_BLOCK_TRIP="${PROBE_GLOBAL_BLOCK_TRIP:-5}"   # blocks within 5m -> trip
PROBE_GLOBAL_PAUSE="${PROBE_GLOBAL_PAUSE:-900}"           # global pause duration on trip
RL_DIR="$STATE_DIR/probe_rl"
GPAUSE="$STATE_DIR/probe_global_pause"
es() { curl -fsS -m 15 --netrc-file "$NETRC" -H 'Content-Type: application/json' "$@"; }
emit() { printf '%s\n' "$1"; exit 0; }     # tool semantics: always JSON on stdout, exit 0
jerr() { jq -nc "$@" 2>/dev/null || printf '{"ok":false,"error":"guard"}'; }

url="${1:-}"; method="${2:-GET}"
[[ -n "$url" ]] || emit '{"ok":false,"error":"usage: recon_safe_probe.sh <url> [GET|HEAD|OPTIONS]"}'
[[ -f "$STATE_DIR/vpn_down" ]] && emit '{"ok":false,"error":"vpn_down — probing disabled (fail-closed)"}'
[[ -f "$WORKER" ]] || emit '{"ok":false,"error":"probe worker missing"}'
command -v python3 >/dev/null 2>&1 || emit '{"ok":false,"error":"python3 missing"}'
mkdir -p "$RL_DIR" "$STATE_DIR" 2>/dev/null || true

# host + LIVE scope gate (authoritative at probe time — never trust a stale catalog)
host="$(printf '%s' "$url" | sed -E 's#^[a-zA-Z]+://([^/:]+).*#\1#')"
[[ -n "$host" && "$host" != "$url" ]] || emit '{"ok":false,"error":"could-not-parse-host"}'
# LIVE scope+pays gate — AUTHORITATIVE via recon_scope_check.sh (the scope DB), NOT stale
# ES triage_* fields. ES triage can lag/disagree with the program catalog (proven: jedi.ripe.net
# read in_scope+pays in ES but pays:false authoritatively, so the old gate wrongly allowed it).
# Fail-closed: if the authoritative resolver is present we REQUIRE its verdict; ES is only a
# fallback when the resolver is absent.
SCOPE_CHECK="${SCOPE_CHECK:-$SCRIPT_DIR/recon_scope_check.sh}"
if [[ -f "$SCOPE_CHECK" ]] && command -v jq >/dev/null 2>&1; then
  ins="$(bash "$SCOPE_CHECK" "$host" 2>/dev/null | jq -r \
     '((.in_scope//false)==true) and ((.pays//false)==true) and ((.out_of_scope//false)!=true)' 2>/dev/null)"
  [[ "$ins" == "true" ]] || emit "$(jerr --arg h "$host" '{ok:false,error:"out-of-scope-or-nonpaying",host:$h}')"
elif [[ -f "$NETRC" ]] && command -v jq >/dev/null 2>&1; then
  ins="$(es "$ES_URL/$INDEX_NAME/_source/$host" 2>/dev/null | jq -r \
     '((.triage_in_scope//false)==true) and ((.triage_pays//false)==true) and ((.triage_out_of_scope//false)!=true) and ((.triage_scan_deny//false)!=true)' 2>/dev/null)"
  [[ "$ins" == "true" ]] || emit "$(jerr --arg h "$host" '{ok:false,error:"out-of-scope-or-nonpaying-es-fallback",host:$h}')"
fi

# per-finding probe budget (anti-runaway for the agentic loop)
if [[ -n "$LEDGER" ]]; then
  n=0; [[ -f "$LEDGER" ]] && n="$(wc -l < "$LEDGER" 2>/dev/null | tr -d ' ')"
  [[ "${n:-0}" -ge "$BUDGET" ]] && emit "$(jerr --argjson b "$BUDGET" '{ok:false,error:"probe-budget-exhausted",budget:$b}')"
fi

# ---- ANTI-BURN rate limiting -------------------------------------------------
now="$(date +%s)"
hsafe="$(printf '%s' "$host" | tr -c 'A-Za-z0-9._-' '_')"
hlog="$RL_DIR/host_$hsafe"; glog="$RL_DIR/_global"; blog="$RL_DIR/_blocks"
cool="$RL_DIR/cooldown_$hsafe"
_within() { awk -v c="$1" -v w="$2" '($1+0)>=(c-w){print}' "$3" 2>/dev/null; }   # lines newer than c-w

# global circuit-breaker pause active?
if [[ -f "$GPAUSE" ]]; then
  exp="$(cat "$GPAUSE" 2>/dev/null || echo 0)"
  if [[ "$now" -lt "${exp:-0}" ]]; then emit "$(jerr --argjson s "$((exp-now))" '{ok:false,error:"global-probe-pause-active",retry_in_s:$s}')"; else rm -f "$GPAUSE"; fi
fi
# per-host cooldown (set after a prior block) active?
if [[ -f "$cool" ]]; then
  exp="$(cat "$cool" 2>/dev/null || echo 0)"
  if [[ "$now" -lt "${exp:-0}" ]]; then emit "$(jerr --arg h "$host" --argjson s "$((exp-now))" '{ok:false,error:"host-cooldown-after-block",host:$h,retry_in_s:$s}')"; else rm -f "$cool"; fi
fi
# per-host rolling window
recent_h="$(_within "$now" "$PROBE_RL_WINDOW" "$hlog")"
cnt_h="$(printf '%s' "$recent_h" | grep -c . 2>/dev/null)"
[[ "${cnt_h:-0}" -ge "$PROBE_RL_PER_HOST" ]] && emit "$(jerr --arg h "$host" --argjson l "$PROBE_RL_PER_HOST" --argjson w "$PROBE_RL_WINDOW" '{ok:false,error:"per-host-rate-limited",host:$h,limit:$l,window_s:$w}')"
# global rolling window
recent_g="$(_within "$now" "$PROBE_RL_WINDOW" "$glog")"
cnt_g="$(printf '%s' "$recent_g" | grep -c . 2>/dev/null)"
[[ "${cnt_g:-0}" -ge "$PROBE_RL_GLOBAL" ]] && emit "$(jerr --argjson l "$PROBE_RL_GLOBAL" --argjson w "$PROBE_RL_WINDOW" '{ok:false,error:"global-rate-limited",limit:$l,window_s:$w}')"
# enforce min gap to this host
last_h="$(printf '%s' "$recent_h" | tail -1)"
if [[ -n "$last_h" ]]; then gap=$((now - last_h)); [[ "$gap" -lt "$PROBE_MIN_GAP" ]] && { sleep "$((PROBE_MIN_GAP - gap))"; now="$(date +%s)"; }; fi
# polite jitter on top
sleep "$(awk 'BEGIN{srand(); print 0.2+rand()*0.8}')" 2>/dev/null || true; now="$(date +%s)"
# record this probe (pruned) in both ledgers + the per-finding budget
{ printf '%s\n' "$recent_h" | grep . ; echo "$now"; } > "$hlog.tmp" 2>/dev/null && mv "$hlog.tmp" "$hlog" 2>/dev/null || true
{ printf '%s\n' "$recent_g" | grep . ; echo "$now"; } > "$glog.tmp" 2>/dev/null && mv "$glog.tmp" "$glog" 2>/dev/null || true
[[ -n "$LEDGER" ]] && printf '%s %s\n' "$method" "$url" >> "$LEDGER" 2>/dev/null || true

# ---- run the safe worker -----------------------------------------------------
out="$(timeout 30 python3 "$WORKER" "$url" "$method" 2>/dev/null)"
[[ -n "$out" ]] || out='{"ok":false,"error":"probe-failed"}'
st="$(printf '%s' "$out" | jq -r '.status // "-"' 2>/dev/null || echo '-')"

# ---- burn detection: target pushed back -> back off ---------------------------
if [[ "$st" == "429" || "$st" == "403" || "$st" == "503" ]]; then
  echo "$((now + PROBE_HOST_COOLDOWN))" > "$cool" 2>/dev/null || true        # cool down THIS host
  echo "$now" >> "$blog" 2>/dev/null || true
  recent_b="$(_within "$now" 300 "$blog")"
  printf '%s\n' "$recent_b" | grep . > "$blog.tmp" 2>/dev/null && mv "$blog.tmp" "$blog" 2>/dev/null || true
  nb="$(printf '%s' "$recent_b" | grep -c . 2>/dev/null)"
  if [[ "${nb:-0}" -ge "$PROBE_GLOBAL_BLOCK_TRIP" ]]; then
    echo "$((now + PROBE_GLOBAL_PAUSE))" > "$GPAUSE" 2>/dev/null || true       # trip global circuit-breaker
  fi
  out="$(printf '%s' "$out" | jq -c --argjson cd "$PROBE_HOST_COOLDOWN" '. + {backoff:"host-cooldown-set",cooldown_s:$cd}' 2>/dev/null || printf '%s' "$out")"
fi

# audit — every probe recorded (timestamp, method, status, url)
printf '%s\t%s\t%s\t%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$method" "$st" "$url" >> "$AUDIT" 2>/dev/null || true
emit "$out"

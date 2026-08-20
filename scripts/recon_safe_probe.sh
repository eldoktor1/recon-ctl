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
#       - host COOLDOWN on a 429/403/503 (back off a target the moment it pushes back),
#         SIZED to the block: an EDGE/WAF path-rule 403 is not rate pushback, so it gets a
#         short cooldown and does NOT count toward the circuit-breaker (repeats escalate)
#       - global CIRCUIT-BREAKER: too many blocks in a short window -> pause ALL probing
#   * PATH DENYLIST for unattended lanes -> known burn-traps are never probed at all
#   * full AUDIT log (accountability)
# The worker enforces: unauth only, GET/HEAD/OPTIONS only, no redirect-follow, no
# internal/metadata targets, size-capped body. One url(+method) in, one JSON line out,
# always exit 0.
#
# Usage: recon_safe_probe.sh <url> [GET|HEAD|OPTIONS]
# Env (caller, per finding): SAFE_PROBE_LEDGER, SAFE_PROBE_BUDGET
# Env (rate-limit tunables): PROBE_MIN_GAP, PROBE_RL_PER_HOST, PROBE_RL_WINDOW,
#   PROBE_RL_GLOBAL, PROBE_HOST_COOLDOWN, PROBE_GLOBAL_BLOCK_TRIP, PROBE_GLOBAL_PAUSE
# Env (edge-block tunables): PROBE_EDGE_COOLDOWN, PROBE_EDGE_TRIP, PROBE_EDGE_WINDOW
# Env (denylist): SAFE_PROBE_UNATTENDED=0 to override (on-demand operator runs),
#   SAFE_PROBE_DENYLIST=<file> to extend the built-in burn-trap list
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
# edge/WAF blocks: a path-rule 403 is not the host asking us to slow down (see the block
# classifier in safe_probe_worker.py), so it buys a SHORT cooldown; only a run of them means
# the edge is really shutting us out, and that escalates to the full host cooldown.
PROBE_EDGE_COOLDOWN="${PROBE_EDGE_COOLDOWN:-60}"          # cooldown for a lone edge/WAF 403
PROBE_EDGE_TRIP="${PROBE_EDGE_TRIP:-3}"                   # edge 403s in-window -> escalate
PROBE_EDGE_WINDOW="${PROBE_EDGE_WINDOW:-300}"             # window for the escalation count
# UNATTENDED mode (default ON, fail-safe): enforce the burn-trap path denylist. An operator
# doing an on-demand run sets SAFE_PROBE_UNATTENDED=0 to probe a denylisted path deliberately.
SAFE_PROBE_UNATTENDED="${SAFE_PROBE_UNATTENDED:-1}"
RL_DIR="$STATE_DIR/probe_rl"
GPAUSE="$STATE_DIR/probe_global_pause"
es() { curl -fsS -m 15 --netrc-file "$NETRC" -H 'Content-Type: application/json' "$@"; }
emit() { printf '%s\n' "$1"; exit 0; }     # tool semantics: always JSON on stdout, exit 0
jerr() { jq -nc "$@" 2>/dev/null || printf '{"ok":false,"error":"guard"}'; }

# ---- BURN-TRAP PATH DENYLIST -------------------------------------------------------
# Paths that reliably answer from the EDGE with a block instead of from the application:
# probing one buys no evidence and costs a host cooldown, so an unattended lane must never
# spend a probe on it. Built-ins are the ones we have actually been burned by; the operator
# extends the list in $STATE_DIR/probe_denylist.txt (one shell glob per line, '#' comments).
# Matched case-insensitively against the URL PATH only (query stripped); a trailing '/*' also
# matches the bare directory itself.
#   /_common/file/*  Sitevision. GET /_common/file/pdf returns a large branded corporate-WAF
#                    403 (not the app). One hit cooled heureka.sbb.ch for 898s on 2026-08-20
#                    and the ai-hunter then emitted 6 ranked hypotheses off zero response
#                    data, 5 of them false. See docs/knowledge/tech-sitevision.md.
DENY_BUILTIN='/_common/file/*'
DENYLIST_FILE="${SAFE_PROBE_DENYLIST:-$STATE_DIR/probe_denylist.txt}"
_denied_by() {   # _denied_by <lowercased-path> -> prints the matching pattern, rc 0 on match
  local p="$1" pat
  while IFS= read -r pat; do
    pat="${pat%%#*}"; pat="${pat//[[:space:]]/}"; pat="$(printf '%s' "$pat" | tr 'A-Z' 'a-z')"
    [[ -z "$pat" ]] && continue
    # shellcheck disable=SC2254  # a denylist entry IS a glob — deliberately unquoted
    case "$p" in $pat) printf '%s\n' "$pat"; return 0 ;; esac
    if [[ "$pat" == */\* ]]; then
      case "$p" in "${pat%/\*}") printf '%s\n' "$pat"; return 0 ;; esac
    fi
  done < <(printf '%s\n' "$DENY_BUILTIN"; [[ -f "$DENYLIST_FILE" ]] && cat "$DENYLIST_FILE")
  return 1
}

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

# BURN-TRAP DENYLIST gate — ahead of the budget and the rate-limit ledgers, so a denied probe
# costs nothing at all. Audited: a silent skip is indistinguishable from a probe that ran.
if [[ "$SAFE_PROBE_UNATTENDED" != "0" ]]; then
  upath="$(printf '%s' "$url" | sed -E 's#^[a-zA-Z]+://[^/]*##; s#[?\#].*$##' | tr 'A-Z' 'a-z')"
  [[ -n "$upath" ]] || upath="/"
  if hitpat="$(_denied_by "$upath")"; then
    printf '%s\t%s\t%s\t%s\t%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$method" "DENY" "$url" "denylist=$hitpat" >> "$AUDIT" 2>/dev/null || true
    emit "$(jerr --arg h "$host" --arg p "$upath" --arg pat "$hitpat" '{ok:false,error:"path-denylisted",host:$h,path:$p,pattern:$pat,reason:"known edge/WAF burn-trap — probing it yields no evidence and costs a host cooldown",override:"SAFE_PROBE_UNATTENDED=0 for a deliberate on-demand run"}')"
  fi
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
cool="$RL_DIR/cooldown_$hsafe"; elog="$RL_DIR/edgeblocks_$hsafe"
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
# Sized to WHO blocked us (safe_probe_worker.py classifies it). An EDGE/WAF path-rule 403 means
# the application never saw the request and nothing asked us to slow down, so locking the host
# for 15m throws away a whole hunt for no safety gain. Everything else — app 403, any 429/503,
# an edge block carrying rate-limit language, or an UNKNOWN classification — keeps the full
# cooldown and still counts toward the global circuit-breaker (fail-safe: unknown == full).
bsrc="unknown"; brate="false"
if [[ "$st" == "429" || "$st" == "403" || "$st" == "503" ]]; then
  bsrc="$(printf '%s' "$out" | jq -r '.block_source // "unknown"' 2>/dev/null || echo unknown)"
  brate="$(printf '%s' "$out" | jq -r '.block_rate_limited // false' 2>/dev/null || echo false)"
fi
if [[ "$st" == "403" && "$bsrc" == "edge" && "$brate" != "true" ]]; then
  echo "$now" >> "$elog" 2>/dev/null || true
  recent_e="$(_within "$now" "$PROBE_EDGE_WINDOW" "$elog")"
  printf '%s\n' "$recent_e" | grep . > "$elog.tmp" 2>/dev/null && mv "$elog.tmp" "$elog" 2>/dev/null || true
  ne="$(printf '%s' "$recent_e" | grep -c . 2>/dev/null)"
  if [[ "${ne:-0}" -ge "$PROBE_EDGE_TRIP" ]]; then
    # a RUN of edge blocks is no longer a path rule — the edge is shutting us out of the host
    echo "$((now + PROBE_HOST_COOLDOWN))" > "$cool" 2>/dev/null || true
    echo "$now" >> "$blog" 2>/dev/null || true
    cdset="$PROBE_HOST_COOLDOWN"; bmode="edge-block-escalated-to-host-cooldown"
  else
    echo "$((now + PROBE_EDGE_COOLDOWN))" > "$cool" 2>/dev/null || true
    cdset="$PROBE_EDGE_COOLDOWN"; bmode="edge-block-short-cooldown"
  fi
  out="$(printf '%s' "$out" | jq -c --argjson cd "$cdset" --arg m "$bmode" --argjson n "${ne:-0}" '. + {backoff:$m,cooldown_s:$cd,edge_blocks_in_window:$n}' 2>/dev/null || printf '%s' "$out")"
elif [[ "$st" == "429" || "$st" == "403" || "$st" == "503" ]]; then
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

# audit — every probe recorded (timestamp, method, status, url, block/backoff detail)
printf '%s\t%s\t%s\t%s\t%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$method" "$st" "$url" "$(printf '%s' "$out" | jq -r '[(.block_source//empty),(.backoff//empty)]|map(select(.!=""))|join(" ")' 2>/dev/null)" >> "$AUDIT" 2>/dev/null || true
emit "$out"

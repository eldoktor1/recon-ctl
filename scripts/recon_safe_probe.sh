#!/usr/bin/env bash
# =============================================================================
# recon_safe_probe.sh — the ONLY target-facing tool the Claude VERIFY agent may call.
#
# Wraps safe_probe_worker.py with the operator guards so it is safe regardless of the
# caller's intent (the caller is an LLM that could be prompt-injected by target content):
#   * vpn_down  -> refuse (fail-closed; Mullvad is sole egress, enforced by the OS killswitch)
#   * live scope gate -> only an in-scope, paying, not-out-of-scope host (authoritative at
#     probe time, never stale)
#   * per-finding BUDGET -> caps how many probes one verification may issue (anti-runaway)
#   * polite jitter -> rate-limit / ban-avoidance (a ban is a form of exposure)
#   * full AUDIT log -> every probe is recorded (accountability)
# The worker enforces: unauth only, GET/HEAD/OPTIONS only, no redirect-follow, no internal/
# metadata targets, size-capped body. One url(+method) in, one JSON line out, always exit 0.
#
# Usage: recon_safe_probe.sh <url> [GET|HEAD|OPTIONS]
# Env (set by the caller per finding): SAFE_PROBE_LEDGER, SAFE_PROBE_BUDGET
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
es() { curl -fsS -m 15 --netrc-file "$NETRC" -H 'Content-Type: application/json' "$@"; }

emit() { printf '%s\n' "$1"; exit 0; }     # tool semantics: always JSON on stdout, exit 0

url="${1:-}"; method="${2:-GET}"
[[ -n "$url" ]] || emit '{"ok":false,"error":"usage: recon_safe_probe.sh <url> [GET|HEAD|OPTIONS]"}'
[[ -f "$STATE_DIR/vpn_down" ]] && emit '{"ok":false,"error":"vpn_down — probing disabled (fail-closed)"}'
[[ -f "$WORKER" ]] || emit '{"ok":false,"error":"probe worker missing"}'
command -v python3 >/dev/null 2>&1 || emit '{"ok":false,"error":"python3 missing"}'

# host + LIVE scope gate (authoritative at probe time — never trust a stale catalog)
host="$(printf '%s' "$url" | sed -E 's#^[a-zA-Z]+://([^/:]+).*#\1#')"
[[ -n "$host" && "$host" != "$url" ]] || emit '{"ok":false,"error":"could-not-parse-host"}'
if [[ -f "$NETRC" ]] && command -v jq >/dev/null 2>&1; then
  ins="$(es "$ES_URL/$INDEX_NAME/_source/$host" 2>/dev/null | jq -r \
     '((.triage_in_scope//false)==true) and ((.triage_pays//false)==true) and ((.triage_out_of_scope//false)!=true)' 2>/dev/null)"
  [[ "$ins" == "true" ]] || emit "$(jq -nc --arg h "$host" '{ok:false,error:"out-of-scope-or-nonpaying",host:$h}')"
fi

# per-finding probe budget (anti-runaway for the agentic loop)
if [[ -n "$LEDGER" ]]; then
  n=0; [[ -f "$LEDGER" ]] && n="$(wc -l < "$LEDGER" 2>/dev/null | tr -d ' ')"
  if [[ "${n:-0}" -ge "$BUDGET" ]]; then
    emit "$(jq -nc --argjson b "$BUDGET" '{ok:false,error:"probe-budget-exhausted",budget:$b}' 2>/dev/null || printf '{"ok":false,"error":"probe-budget-exhausted"}')"
  fi
  printf '%s %s\n' "$method" "$url" >> "$LEDGER" 2>/dev/null || true
fi

# polite jitter — rate-limit / ban avoidance
sleep "$(awk 'BEGIN{srand(); print 0.3+rand()*1.2}')" 2>/dev/null || true

out="$(timeout 30 python3 "$WORKER" "$url" "$method" 2>/dev/null)"
[[ -n "$out" ]] || out='{"ok":false,"error":"probe-failed"}'

# audit — every probe recorded (timestamp, method, status, url)
st="$(printf '%s' "$out" | jq -r '.status // "-"' 2>/dev/null || echo '-')"
mkdir -p "$STATE_DIR" 2>/dev/null || true
printf '%s\t%s\t%s\t%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$method" "$st" "$url" >> "$AUDIT" 2>/dev/null || true

emit "$out"

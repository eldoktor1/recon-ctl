#!/usr/bin/env bash
# =============================================================================
# recon_unauth_expose.sh — U1 lane: shadow-endpoint UNAUTHENTICATED data exposure.
#
# The most machine-confirmable high-sev unauth play (docs/knowledge/class-unauth-hunting.md
# play U1). Mines the jsintel endpoint feedstock for data-ish routes, probes each
# UNAUTHENTICATED via the vetted recon_safe_probe.sh (GET only, scope+pays+vpn+rate-limit
# +SSRF-guard+audit), and confirms a REAL leak only when the precision-first classifier
# (tools/unauth_expose_classify.py) says so: 200 + genuine sensitive data, NOT the SPA
# shell, NOT a 401/403, NOT public-by-design config. Confirmed -> state.py record-confirmed
# (signal_class=unauth-data-exposure) -> ai-pending -> 2IC Claude-verify -> SUBMIT card.
#
# HARD LINE: confirm exposure EXISTS, never harvest — evidence is REDACTED (field names +
# counts, masked values). GET only, in-scope+paying only, Mullvad-only, rate-limited.
# Target-facing -> run via run_scanner (reconrun) from the daemon.
# =============================================================================
set -uo pipefail
IFS=$'\n\t'
log()  { printf '[%s UEXPOSE] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s UEXPOSE WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
V3_DB="${V3_DB:-$BASE_DIR/v3/findings.db}"
EP_STORE="${EP_STORE:-$BASE_DIR/js_recon/endpoints.jsonl}"
SAFE_PROBE="${SAFE_PROBE:-$SCRIPT_DIR/recon_safe_probe.sh}"
CLASSIFY="${CLASSIFY:-$REPO_DIR/tools/unauth_expose_classify.py}"
STATE_PY="${STATE_PY:-$REPO_DIR/engine/state.py}"
SEEN="${SEEN:-$STATE_DIR/unauth_expose_seen.tsv}"          # host<TAB>endpoint<TAB>epoch
POOL="${UNAUTH_EXPOSE_POOL:-300}"                          # candidate pool scanned for fresh work
BATCH="${UNAUTH_EXPOSE_BATCH:-25}"                         # endpoints PROBED per cycle (anti-burn)
COOLDOWN_SECS="${UNAUTH_EXPOSE_COOLDOWN:-1209600}"         # 14d per (host,endpoint)
SCORE="${UNAUTH_EXPOSE_SCORE:-6}"

mkdir -p "$STATE_DIR" "$(dirname "$V3_DB")" 2>/dev/null || true
exec 9>"$STATE_DIR/unauth_expose.lock"; flock -n 9 || { warn "already running"; exit 0; }
[[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down — skipping (fail-closed)"; exit 0; }
command -v jq >/dev/null 2>&1      || { warn "jq missing"; exit 0; }
command -v python3 >/dev/null 2>&1 || { warn "python3 missing"; exit 0; }
[[ -f "$EP_STORE"   ]] || { warn "no endpoint feedstock ($EP_STORE)"; exit 0; }
[[ -f "$SAFE_PROBE" ]] || { warn "safe probe missing"; exit 0; }
[[ -f "$CLASSIFY"   ]] || { warn "classifier missing"; exit 0; }

now_epoch() { date -u +%s; }
NOW="$(now_epoch)"

# ---- prune the seen-ledger to the cooldown window (keeps it bounded) ----------
if [[ -f "$SEEN" ]]; then
  awk -F'\t' -v cut="$((NOW - COOLDOWN_SECS))" 'NF>=3 && ($3+0)>=cut' "$SEEN" > "$SEEN.tmp" 2>/dev/null \
    && mv "$SEEN.tmp" "$SEEN" 2>/dev/null || true
fi
seen_recent() {  # host endpoint -> 0 if seen within cooldown
  [[ -f "$SEEN" ]] || return 1
  awk -F'\t' -v h="$1" -v e="$2" -v cut="$((NOW - COOLDOWN_SECS))" \
    'NF>=3 && $1==h && $2==e && ($3+0)>=cut{f=1} END{exit f?0:1}' "$SEEN"
}
mark_seen() { printf '%s\t%s\t%s\n' "$1" "$2" "$(now_epoch)" >> "$SEEN" 2>/dev/null || true; }

# ---- candidate selection: data-ish endpoints from the jsintel feedstock ------
# (in-scope/pays is enforced AUTHORITATIVELY per-probe by recon_safe_probe.sh; here we
#  just pick interesting routes. dedup by host+endpoint, shuffle for fresh coverage.)
DATA_RE='(/api/|/v[1-9]|/internal|/private|/admin|/export|/download|/graphql|/users|/orders|/accounts|/invoice|/profile|/customer|/account|/rest/|/services/|/config|/backup|/dump|\.json$)'
mapfile -t CANDS < <(
  jq -rc --arg re "$DATA_RE" '
    select((.host // "") != "" and (.endpoint // "") != "")
    | select((.endpoint|tostring) | startswith("/"))
    | select((.endpoint|tostring) | test($re; "i"))
    | [ .host, (.endpoint|tostring), (.program // "") ] | @tsv' "$EP_STORE" 2>/dev/null \
  | sort -u | shuf 2>/dev/null | head -n "$POOL"
)
[[ "${#CANDS[@]}" -gt 0 ]] || { log "no candidate endpoints"; exit 0; }

declare -A ROOT_CACHE OOS_HOST
probed=0; confirmed=0; skipped=0

probe() {  # url -> JSON on stdout (safe_probe worker output); always exits 0
  bash "$SAFE_PROBE" "$1" GET 2>/dev/null
}
fp_known() {  # host signal vuln -> 0 if known FP
  [[ "$(V3_DB="$V3_DB" python3 "$STATE_PY" check-fp "$1" "$2" "$3" 2>/dev/null)" == "FP" ]]
}

for line in "${CANDS[@]}"; do
  [[ "$probed" -ge "$BATCH" ]] && break
  IFS=$'\t' read -r host endpoint program <<<"$line"
  [[ -n "$host" && -n "$endpoint" ]] || continue
  [[ -n "${OOS_HOST[$host]:-}" ]] && { skipped=$((skipped+1)); continue; }
  seen_recent "$host" "$endpoint" && { skipped=$((skipped+1)); continue; }
  fp_known "$host" "unauth-data-exposure" "info-disclosure" && { mark_seen "$host" "$endpoint"; skipped=$((skipped+1)); continue; }

  # root baseline per host (cached) — also doubles as the scope+vpn gate probe
  if [[ -z "${ROOT_CACHE[$host]:-}" ]]; then
    root_json="$(probe "https://$host/")"
    [[ -n "$root_json" ]] || root_json='{"ok":false}'
    err="$(printf '%s' "$root_json" | jq -r '.error // ""' 2>/dev/null)"
    case "$err" in
      *out-of-scope*|*nonpaying*) OOS_HOST[$host]=1; skipped=$((skipped+1)); continue ;;
      *global-probe-pause*) log "global probe pause active — backing off, ending cycle"; break ;;
    esac
    ROOT_CACHE[$host]="$root_json"
  fi
  root_json="${ROOT_CACHE[$host]}"

  url="https://$host$endpoint"
  pj="$(probe "$url")"; probed=$((probed+1)); mark_seen "$host" "$endpoint"
  [[ -n "$pj" ]] || continue
  perr="$(printf '%s' "$pj" | jq -r '.error // ""' 2>/dev/null)"
  case "$perr" in
    *global-probe-pause*) log "global probe pause — ending cycle"; break ;;
    *rate-limited*|*cooldown*) sleep 5; continue ;;
    *out-of-scope*|*nonpaying*) OOS_HOST[$host]=1; continue ;;
  esac

  verdict="$(jq -nc --argjson p "$pj" --argjson r "$root_json" --arg h "$host" --arg e "$endpoint" \
      '{host:$h,endpoint:$e,probe:$p,root:$r}' 2>/dev/null | python3 "$CLASSIFY" 2>/dev/null)"
  [[ -n "$verdict" ]] || continue
  if [[ "$(printf '%s' "$verdict" | jq -r '.exposure // false' 2>/dev/null)" == "true" ]]; then
    conf="$(printf '%s' "$verdict" | jq -r '.confidence // 0')"
    reason="$(printf '%s' "$verdict" | jq -r '.reason // ""')"
    ev="$(printf '%s' "$verdict" | jq -c --arg r "$reason" '(.evidence // {}) + {reason:$r}' 2>/dev/null)"
    V3_DB="$V3_DB" python3 "$STATE_PY" record-confirmed \
      "$host" "$url" "$program" "unauth-data-exposure" "info-disclosure" "$SCORE" "$conf" "$ev" >/dev/null 2>&1 \
      && { confirmed=$((confirmed+1)); log "CONFIRMED unauth-data-exposure $url (conf $conf) — $reason"; }
  fi
done

log "cycle done · probed=$probed confirmed=$confirmed skipped=$skipped (pool=${#CANDS[@]})"
exit 0

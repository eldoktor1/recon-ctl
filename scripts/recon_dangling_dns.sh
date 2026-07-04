#!/usr/bin/env bash
# =============================================================================
# recon_dangling_dns.sh — DANGLING-NS subdomain takeover (audit #10b).
#
# The existing takeover hunter is CNAME-only; it misses dangling NS delegations — the
# dominant 2025 takeover class (Hazy Hawk: CDC/Deloitte/PwC). A subdomain delegated to a
# nameserver whose OWN registrable domain has EXPIRED (NXDOMAIN) = an attacker registers
# that domain → controls the nameserver → controls the entire delegated zone = full takeover.
#
# Detection (DNS-only — queries public resolvers about the target's ZONE, never the target's
# web server, so this is recon not attack): for fresh in-scope+paying hosts, get delegated NS
# records; for each NS, check if its registrable apex (last 2 labels) is NXDOMAIN on TWO
# independent resolvers (1.1.1.1 + 8.8.8.8 must agree). Both NXDOMAIN => CONFIRMED dangling NS.
# The last-2-labels apex heuristic is CONSERVATIVE: a multi-label TLD (co.uk) returns NOERROR
# so it can never false-positive; worst case is a missed .co.uk delegation.
#
# Confirmed -> state.py record-confirmed (signal_class=takeover-dangling-ns) -> 2IC verify ->
# SUBMIT. Runs as d0k (DNS, not target-facing). Killswitch v2_dangling_dns.
# Dangling-A (released cloud IP) is intentionally NOT auto-confirmed here — it is highly
# FP-prone (an A to a live IP that 404s is not a takeover) and needs cloud-IP-pool intel.
# =============================================================================
set -uo pipefail
IFS=$'\n\t'
log()  { printf '[%s DANGLING-NS] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s DANGLING-NS WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/recon_net.sh" 2>/dev/null || true; setup_es_netrc 2>/dev/null || true
BASE_DIR="${BASE_DIR:-$HOME/recon}"; STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
V3_DB="${V3_DB:-$BASE_DIR/v3/findings.db}"; STATE_PY="${STATE_PY:-$REPO_DIR/engine/state.py}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"; INDEX_NAME="${INDEX_NAME:-recon_alive}"
NETRC="${NETRC:-$HOME/.recon_es_netrc}"
SEEN="${DANGLING_SEEN:-$STATE_DIR/dangling_dns_seen.tsv}"
DANGLING_HOSTS="${DANGLING_HOSTS:-150}"        # hosts checked per cycle (DNS is cheap)
COOLDOWN_SECS="${DANGLING_COOLDOWN:-1209600}"  # 14d per host
R1="${DANGLING_R1:-1.1.1.1}"; R2="${DANGLING_R2:-8.8.8.8}"

es() { curl -fsS -m 20 --netrc-file "$NETRC" -H 'Content-Type: application/json' "$@"; }
mkdir -p "$STATE_DIR" "$(dirname "$V3_DB")" 2>/dev/null || true
exec 9>"$STATE_DIR/dangling_dns.lock"; flock -n 9 || { warn "already running"; exit 0; }
[[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down — skipping (fail-closed)"; exit 0; }
command -v dig >/dev/null 2>&1 || { warn "dig missing"; exit 0; }
command -v jq  >/dev/null 2>&1 || { warn "jq missing"; exit 0; }
command -v python3 >/dev/null 2>&1 || { warn "python3 missing"; exit 0; }
NOW="$(date -u +%s)"
if [[ -f "$SEEN" ]]; then awk -F'\t' -v cut="$((NOW-COOLDOWN_SECS))" 'NF>=2 && ($2+0)>=cut' "$SEEN" > "$SEEN.tmp" 2>/dev/null && mv "$SEEN.tmp" "$SEEN" 2>/dev/null || true; fi
seen_recent() { [[ -f "$SEEN" ]] && awk -F'\t' -v h="$1" -v cut="$((NOW-COOLDOWN_SECS))" 'NF>=2 && $1==h && ($2+0)>=cut{f=1} END{exit f?0:1}' "$SEEN"; }
mark_seen() { printf '%s\t%s\n' "$1" "$(date -u +%s)" >> "$SEEN" 2>/dev/null || true; }

# registrable apex = last 2 labels (conservative — see header)
apex_of() { awk -F. '{n=NF; if(n>=2) print $(n-1)"."$n; else print $0}' <<<"$1"; }
# NXDOMAIN on a name at a resolver? (status: NXDOMAIN in dig comments)
is_nxdomain() { dig "$1" NS "@$2" +noall +comments +time=4 +tries=1 2>/dev/null | grep -q 'status: NXDOMAIN'; }
# strict RFC-ish hostname validator — a real NS is labelled alnum/hyphen with an alpha TLD.
# On a resolver timeout dig can print junk to STDOUT (";; communications error to 1.1.1.1#53:
# timed out") which previously flowed into the NS list, got mangled by apex_of into an apex
# like "1.1#53: timed out", and a malformed name can return NXDOMAIN on both resolvers => a
# BOGUS takeover mint (id196/197, 2026-07-03). This drops any such junk before it is used.
valid_hostname() { [[ "$1" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]; }
# delegated NS for a host from a given resolver, junk-filtered to valid hostnames only
get_valid_ns() {
  local h="$1" r="$2" n; local -a out=()
  while IFS= read -r n; do valid_hostname "$n" && out+=("$n"); done \
    < <(dig +short NS "$h" "@$r" +time=4 +tries=1 2>/dev/null | sed 's/\.$//' | awk 'NF')
  printf '%s\n' "${out[@]}"
}

q="$(jq -nc --argjson n "$DANGLING_HOSTS" '{size:($n*3),_source:["host","triage_program"],
  query:{bool:{filter:[{term:{triage_in_scope:true}},{term:{triage_pays:true}}],
               must_not:[{term:{triage_out_of_scope:true}},{range:{ignore_expires_at:{gt:"now"}}}]}},
  sort:[{triage_true_fresh:{order:"desc",missing:"_last"}},{triage_score:{order:"desc",missing:"_last"}}]}')"
mapfile -t cand < <(es "$ES_URL/$INDEX_NAME/_search" -d "$q" 2>/dev/null \
  | jq -r '.hits.hits[]._source | [.host,(.triage_program//"")] | @tsv' 2>/dev/null)
[[ "${#cand[@]}" -gt 0 ]] || { log "no candidate hosts"; exit 0; }

checked=0; confirmed=0; hosts_done=0
for line in "${cand[@]}"; do
  [[ "$hosts_done" -ge "$DANGLING_HOSTS" ]] && break
  IFS=$'\t' read -r host program <<<"$line"
  [[ -n "$host" ]] || continue
  seen_recent "$host" && continue
  [[ -f "$STATE_DIR/vpn_down" ]] && break
  mark_seen "$host"; hosts_done=$((hosts_done+1))
  # delegated NS for this host (only delegation points return their own NS), junk-filtered.
  # If R1 yields nothing valid (timeout/junk), re-resolve on R2 before giving up.
  mapfile -t nslist < <(get_valid_ns "$host" "$R1")
  [[ "${#nslist[@]}" -gt 0 ]] || mapfile -t nslist < <(get_valid_ns "$host" "$R2")
  [[ "${#nslist[@]}" -gt 0 ]] || continue
  checked=$((checked+1))
  for ns in "${nslist[@]}"; do
    [[ -n "$ns" ]] || continue
    apex="$(apex_of "$ns")"; { [[ -n "$apex" ]] && valid_hostname "$apex"; } || continue
    # the NS apex must be registrable (NXDOMAIN) on BOTH resolvers => dangling delegation
    if is_nxdomain "$apex" "$R1" && is_nxdomain "$apex" "$R2"; then
      url="https://${host}/"
      ev="$(jq -nc --arg h "$host" --arg ns "$ns" --arg ap "$apex" \
            '{probe:"dangling-ns", host:$h, dangling_ns:$ns, registrable_apex:$ap,
              reason:("subdomain delegated to nameserver \($ns) whose registrable domain \($ap) is NXDOMAIN (expired/unregistered) on 2 resolvers — register \($ap) to control the NS and take over the delegated zone")}' 2>/dev/null)"
      V3_DB="$V3_DB" python3 "$STATE_PY" record-confirmed \
        "$host" "$url" "$program" "takeover-dangling-ns" "subdomain-takeover" "15" "0.85" "$ev" >/dev/null 2>&1 \
        && { confirmed=$((confirmed+1)); log "   💥 DANGLING NS · $host → $ns (registrable apex: $apex)"; }
      break   # one finding per host
    fi
  done
done

log "cycle done · hosts=$hosts_done delegations=$checked CONFIRMED=$confirmed"
exit 0

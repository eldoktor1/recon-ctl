#!/usr/bin/env bash
# =============================================================================
# recon_permute.sh — PERMUTATION-DNS lane (project_permutation_pipeline_idea).
#
# alterx GENERATES subdomain permutations from high-value in-scope seeds → puredns RESOLVES
# them via cheap PUBLIC resolvers → only NEW resolved hosts (not already in the ever-seen
# ledger) are dropped into the validator queue so the rate-limited prober picks them up.
# Proven ad-hoc: permutation found apusadmin/bastion/bkcsplatform on ANT banks subfinder missed.
#
# DOCTRINE (how this stays safe + doesn't fry the box):
#  - BOUNDED wordlist: alterx default patterns + -enrich, capped at PERMUTE_LIMIT per cycle.
#  - SLIDING WINDOW: a small seed batch per cycle (cooldown'd via permute_seen) so it slides
#    through the in-scope pool over time instead of permuting everything at once.
#  - PUBLIC-resolver DNS = NOT target traffic (the bug-bounty host is never contacted here);
#    egress still rides the Mullvad default route. Runs as d0k; the supervise_loop vpn gate
#    pauses it on vpn_down. Permutations are same-root as their in-scope seed → in-scope by
#    construction; per-host scope/pays is still enforced downstream by validate/triage.
#  - Only NEW (not in known_hosts) resolved hosts reach the prober → no re-hammering.
# Killswitch: state/kill/v2_permute.
# =============================================================================
set -uo pipefail
IFS=$'\n\t'
log()  { printf '[%s PERMUTE] %s\n'      "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s PERMUTE WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/recon_net.sh" 2>/dev/null || true
BASE_DIR="${BASE_DIR:-$HOME/recon}"; STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"; INDEX_NAME="${INDEX_NAME:-recon_alive}"
NETRC="${NETRC:-$HOME/.recon_es_netrc}"
INBOX="${INBOX:-$BASE_DIR/queue/inbox}"
KNOWN="${KNOWN_HOSTS:-$STATE_DIR/known_hosts.txt}"     # 4M-host ever-seen ledger (has NUL → grep -a)
SEEN="${PERMUTE_SEEN:-$STATE_DIR/permute_seen.txt}"     # seeds already permuted (sliding window)
RESOLVERS="${PERMUTE_RESOLVERS:-$STATE_DIR/resolvers_trusted.txt}"
ALTERX="${ALTERX:-$HOME/go/bin/alterx}"
PUREDNS="${PUREDNS:-$HOME/go/bin/puredns}"
KILL_FILE="$STATE_DIR/kill/v2_permute"
PERMUTE_SEEDS="${PERMUTE_SEEDS:-25}"        # seeds permuted per cycle (sliding window)
PERMUTE_LIMIT="${PERMUTE_LIMIT:-8000}"      # max permutations generated per cycle (bound)
PERMUTE_RL="${PERMUTE_RL:-800}"             # puredns DNS queries/sec (polite to public resolvers)
PERMUTE_INBOX_CAP="${PERMUTE_INBOX_CAP:-180}"  # don't add to an already-backed-up validator queue
es() { curl -fsS -m 25 --netrc-file "$NETRC" -H 'Content-Type: application/json' "$@"; }

mkdir -p "$STATE_DIR" "$INBOX" "$(dirname "$KILL_FILE")"; touch "$SEEN"
[[ -f "$KILL_FILE" ]] && { warn "killed by $KILL_FILE"; exit 0; }
exec 9>"$STATE_DIR/permute.lock"; flock -n 9 || { warn "already running"; exit 0; }
[[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down — skipping (fail-closed)"; exit 0; }
for t in "$ALTERX" "$PUREDNS"; do [[ -x "$t" ]] || { warn "missing tool: $t"; exit 0; }; done
command -v massdns >/dev/null 2>&1 || { warn "massdns missing (puredns needs it)"; exit 0; }
command -v jq >/dev/null 2>&1 || { warn "jq missing"; exit 0; }

# Don't pile onto a backed-up validator queue.
nq="$(find "$INBOX" -maxdepth 1 -name '*.txt' 2>/dev/null | wc -l | tr -d ' ')"
[[ "${nq:-0}" -ge "$PERMUTE_INBOX_CAP" ]] && { log "validator queue full ($nq) — skip this cycle"; exit 0; }

# Trusted public resolvers (curated, reliable, no poisoning) — written once if absent.
if [[ ! -s "$RESOLVERS" ]]; then
  printf '%s\n' 1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 9.9.9.9 149.112.112.112 208.67.222.222 208.67.220.220 64.6.64.6 > "$RESOLVERS"
fi

# ---- seed selection: top-value in-scope+paying hosts, sliding window via SEEN ----------
q="$(jq -nc --argjson n "$PERMUTE_SEEDS" '{size:($n*6), _source:["host"],
  query:{bool:{filter:[{term:{triage_in_scope:true}},{term:{triage_pays:true}}],
               must_not:[{term:{triage_out_of_scope:true}},{range:{ignore_expires_at:{gt:"now"}}}]}},
  sort:[{triage_score:{order:"desc",missing:"_last"}},{triage_true_fresh:{order:"desc",missing:"_last"}}]}')"
mapfile -t seeds < <(es "$ES_URL/$INDEX_NAME/_search" -d "$q" 2>/dev/null \
  | jq -r '.hits.hits[]._source.host // empty' 2>/dev/null | awk 'NF && !s[$0]++' \
  | grep -avxF -f "$SEEN" 2>/dev/null | head -n "$PERMUTE_SEEDS")
[[ "${#seeds[@]}" -gt 0 ]] || { log "no fresh seeds (sliding window may have lapped — clearing SEEN)"; : > "$SEEN"; exit 0; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/permute.XXXXXX")"; trap 'rm -rf "$TMP"' EXIT
printf '%s\n' "${seeds[@]}" > "$TMP/seeds.txt"
log "🧬 permute · ${#seeds[@]} seed(s) → alterx (≤$PERMUTE_LIMIT) → puredns (public resolvers)"

# ---- generate (offline) → resolve (public resolvers) -----------------------------------
"$ALTERX" -l "$TMP/seeds.txt" -enrich -limit "$PERMUTE_LIMIT" -silent 2>/dev/null | awk 'NF && !s[$0]++' > "$TMP/perms.txt" || true
nperms="$(wc -l < "$TMP/perms.txt" 2>/dev/null | tr -d ' ')"
[[ "${nperms:-0}" -gt 0 ]] || { log "alterx produced no permutations"; printf '%s\n' "${seeds[@]}" >> "$SEEN"; exit 0; }
# wildcard-filter + validate with the trusted set (same reliable resolvers) so wildcard-DNS roots
# don't flood the validator queue with false hosts.
"$PUREDNS" resolve "$TMP/perms.txt" -r "$RESOLVERS" --resolvers-trusted "$RESOLVERS" --rate-limit "$PERMUTE_RL" -q 2>/dev/null \
  | awk 'NF && !s[$0]++' > "$TMP/resolved.txt" || true
nres="$(wc -l < "$TMP/resolved.txt" 2>/dev/null | tr -d ' ')"

# ---- keep only NEW hosts (not in the ever-seen ledger) → validator queue ---------------
if [[ "${nres:-0}" -gt 0 && -s "$KNOWN" ]]; then
  grep -avxF -f "$KNOWN" "$TMP/resolved.txt" 2>/dev/null > "$TMP/new.txt" || cp "$TMP/resolved.txt" "$TMP/new.txt"
else
  cp "$TMP/resolved.txt" "$TMP/new.txt" 2>/dev/null || : > "$TMP/new.txt"
fi
nnew="$(wc -l < "$TMP/new.txt" 2>/dev/null | tr -d ' ')"
printf '%s\n' "${seeds[@]}" >> "$SEEN"; tail -n 50000 "$SEEN" > "$SEEN.tmp" 2>/dev/null && mv "$SEEN.tmp" "$SEEN" 2>/dev/null || true

if [[ "${nnew:-0}" -gt 0 ]]; then
  out="$INBOX/15_$(date -u +%Y%m%dT%H%M%SZ)_permute.txt"
  sort -u "$TMP/new.txt" > "$out"
  log "🧬 permute done · $nperms perms → $nres resolved → 💎 $nnew NEW host(s) → $out (prober)"
else
  log "🧬 permute done · $nperms perms → $nres resolved → 0 new (all already known)"
fi
exit 0

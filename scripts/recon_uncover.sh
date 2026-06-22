#!/usr/bin/env bash
# =============================================================================
# recon_uncover.sh — SURFACE EXPANSION via uncover (internet-research-for-enumeration doctrine).
#
# Beside subfinder/gungnir, query the engines (Shodan/Censys) with dorks SCOPED to our in-scope
# roots/certs → candidate hosts → puredns-resolve → only NEW in-scope hosts reach the validator
# queue (prober picks them up). Finds surface CT/subfinder miss (cert-CN matches, org assets).
#
# CREDIT-CONSERVATIVE (the operator's quotas are SCARCE — see memory reference_api_credit_budget):
#  - HARD MONTHLY Shodan budget (UNCOVER_MONTHLY_BUDGET, default 60 of the 100/mo — leaves headroom
#    for manual use). Tracked in state/uncover_budget.txt ("YYYY-MM N"); resets monthly; checked
#    BEFORE every query; exhausted ⇒ skip. tiny -l per query. Sliding-window over roots.
#  - FOFA is SKIPPED (free tier API balance = 0/0 → unusable). Censys is opt-in/best-effort (Platform
#    PAT may not work with uncover's legacy engine). Shodan is the default engine.
# NOT target traffic (queries 3rd-party engine APIs + public-resolver DNS) → runs as d0k; the
# supervise_loop vpn gate still pauses it on vpn_down. Killswitch v2_uncover.
#
# MODES:  (default) one budgeted autonomous cycle;  query "<dork>" [engine]  = on-demand targeted.
# =============================================================================
set -uo pipefail
IFS=$'\n\t'
log()  { printf '[%s UNCOVER] %s\n'      "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s UNCOVER WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/recon_net.sh" 2>/dev/null || true
BASE_DIR="${BASE_DIR:-$HOME/recon}"; STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"; INDEX_NAME="${INDEX_NAME:-recon_alive}"
NETRC="${NETRC:-$HOME/.recon_es_netrc}"
INBOX="${INBOX:-$BASE_DIR/queue/inbox}"
KNOWN="${KNOWN_HOSTS:-$STATE_DIR/known_hosts.txt}"
SEEN="${UNCOVER_SEEN:-$STATE_DIR/uncover_seen.txt}"        # roots already dorked (sliding window)
RESOLVERS="${PERMUTE_RESOLVERS:-$STATE_DIR/resolvers_trusted.txt}"
BUDGET_FILE="${UNCOVER_BUDGET_FILE:-$STATE_DIR/uncover_budget.txt}"
UNCOVER="${UNCOVER:-$HOME/go/bin/uncover}"
PUREDNS="${PUREDNS:-$HOME/go/bin/puredns}"
KILL_FILE="$STATE_DIR/kill/v2_uncover"
UNCOVER_MONTHLY_BUDGET="${UNCOVER_MONTHLY_BUDGET:-60}"   # max Shodan queries/month (of the 100/mo plan)
UNCOVER_ROOTS="${UNCOVER_ROOTS:-2}"        # in-scope roots dorked per cycle
UNCOVER_LIMIT="${UNCOVER_LIMIT:-50}"       # -l results per query (small)
UNCOVER_RL="${UNCOVER_RL:-2}"              # engine requests/sec (polite)
UNCOVER_ENGINES="${UNCOVER_ENGINES:-shodan}"   # fofa skipped (0 API quota); censys opt-in
UNCOVER_INBOX_CAP="${UNCOVER_INBOX_CAP:-180}"
es() { curl -fsS -m 25 --netrc-file "$NETRC" -H 'Content-Type: application/json' "$@"; }

mkdir -p "$STATE_DIR" "$INBOX" "$(dirname "$KILL_FILE")"; touch "$SEEN"
[[ -x "$UNCOVER" ]] || { warn "uncover missing ($UNCOVER)"; exit 0; }
command -v jq >/dev/null 2>&1 || { warn "jq missing"; exit 0; }
[[ -s "$RESOLVERS" ]] || printf '%s\n' 1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 9.9.9.9 > "$RESOLVERS"

# ---- monthly Shodan budget guard --------------------------------------------------------
MONTH="$(date -u +%Y-%m)"
budget_used() { local m c; [[ -f "$BUDGET_FILE" ]] || { echo 0; return; }; read -r m c < "$BUDGET_FILE" 2>/dev/null || true; [[ "$m" == "$MONTH" ]] && echo "${c:-0}" || echo 0; }
budget_add()  { local n; n=$(( $(budget_used) + ${1:-1} )); printf '%s %s\n' "$MONTH" "$n" > "$BUDGET_FILE"; }
budget_left() { echo $(( UNCOVER_MONTHLY_BUDGET - $(budget_used) )); }

# ---- run uncover for one engine+dork, append host (no :port) lines to $2 (budget-charged for shodan) --
run_engine() {   # run_engine <engine> <dork> <outfile>
  local eng="$1" dork="$2" out="$3"
  if [[ "$eng" == "shodan" ]]; then
    [[ "$(budget_left)" -gt 0 ]] || { warn "Shodan monthly budget exhausted ($(budget_used)/$UNCOVER_MONTHLY_BUDGET) — skip"; return 1; }
    budget_add 1
  fi
  timeout 60 "$UNCOVER" "-$eng" "$dork" -f host -l "$UNCOVER_LIMIT" -rl "$UNCOVER_RL" -silent 2>/dev/null \
    | sed -E 's/:[0-9]+$//' | grep -aE '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' | awk 'NF && !s[$0]++' >> "$out" || true
}

# ---- resolve candidates, keep NEW (+ in-scope root), drop into the validator queue -------
emit_new() {   # emit_new <candidates-file> <root-or-tag>
  local cands="$1" tag="$2"
  [[ -s "$cands" ]] || { log "  no candidate hosts ($tag)"; return 0; }
  local res new; res="$(mktemp)"; new="$(mktemp)"
  "$PUREDNS" resolve "$cands" -r "$RESOLVERS" --resolvers-trusted "$RESOLVERS" --rate-limit 800 -q 2>/dev/null \
    | awk 'NF && !s[$0]++' > "$res" || true
  if [[ -s "$KNOWN" ]]; then grep -avxF -f "$KNOWN" "$res" 2>/dev/null > "$new" || cp "$res" "$new"; else cp "$res" "$new" 2>/dev/null; fi
  local nnew; nnew="$(wc -l < "$new" 2>/dev/null | tr -d ' ')"
  if [[ "${nnew:-0}" -gt 0 ]]; then
    local f="$INBOX/16_$(date -u +%Y%m%dT%H%M%SZ)_uncover.txt"
    sort -u "$new" >> "$f"
    log "  💎 $nnew NEW resolved host(s) ($tag) → $f (prober)"
  else
    log "  $(wc -l < "$res" 2>/dev/null | tr -d ' ') resolved, 0 new ($tag)"
  fi
  rm -f "$res" "$new"
}

# ============================== MODES ====================================================
cmd_query() {   # on-demand: query "<dork>" [engine]
  local dork="${1:-}" eng="${2:-shodan}"
  [[ -n "$dork" ]] || { echo "usage: recon-uncover query \"<dork>\" [shodan|censys|fofa|quake]"; exit 1; }
  local cands; cands="$(mktemp)"
  log "🔭 uncover on-demand · $eng · $dork (budget left: $(budget_left))"
  run_engine "$eng" "$dork" "$cands"
  emit_new "$cands" "ondemand:$eng"
  rm -f "$cands"
}

cmd_cycle() {   # autonomous budgeted cycle
  [[ -f "$KILL_FILE" ]] && { warn "killed by $KILL_FILE"; exit 0; }
  exec 9>"$STATE_DIR/uncover.lock"; flock -n 9 || { warn "already running"; exit 0; }
  [[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down — skipping"; exit 0; }
  [[ "$(budget_left)" -gt 0 ]] || { log "Shodan monthly budget spent ($(budget_used)/$UNCOVER_MONTHLY_BUDGET) — idle until $MONTH rolls over"; exit 0; }
  # Count only HIGH-PRIORITY files: exclude the low-priority background-VOLUME producers
  # (restale_* refresh churn, bulk_* mass-discovery) — they sort after our numeric batches in
  # the validate queue, so they must not gate fresh-surface discovery (bulk_ once held a 33k pile).
  local nq; nq="$(find "$INBOX" -maxdepth 1 -name '*.txt' ! -name 'restale_*' ! -name 'bulk_*' 2>/dev/null | wc -l | tr -d ' ')"
  [[ "${nq:-0}" -ge "$UNCOVER_INBOX_CAP" ]] && { log "validator queue full ($nq high-prio) — skip"; exit 0; }

  # in-scope+paying ROOT domains, sliding window (skip ones already dorked this window)
  local q; q="$(jq -nc '{size:1500,_source:["root_domain"],
    query:{bool:{filter:[{term:{triage_in_scope:true}},{term:{triage_pays:true}}],
                 must_not:[{term:{triage_out_of_scope:true}},{range:{ignore_expires_at:{gt:"now"}}}]}}}')"
  mapfile -t roots < <(es "$ES_URL/$INDEX_NAME/_search" -d "$q" 2>/dev/null \
    | jq -r '.hits.hits[]._source.root_domain // empty' 2>/dev/null \
    | awk 'NF && $0 ~ /\./ && !s[$0]++' | grep -avxF -f "$SEEN" 2>/dev/null | head -n "$UNCOVER_ROOTS")
  [[ "${#roots[@]}" -gt 0 ]] || { log "no fresh in-scope roots (window lapped — clearing SEEN)"; : > "$SEEN"; exit 0; }
  log "🔭 ─── UNCOVER ─── ${#roots[@]} root(s) · engines=$UNCOVER_ENGINES · budget left $(budget_left)/$UNCOVER_MONTHLY_BUDGET ───"

  local root cands eng
  for root in "${roots[@]}"; do
    [[ "$(budget_left)" -gt 0 ]] || { warn "budget hit mid-cycle — stopping"; break; }
    cands="$(mktemp)"
    # cert/hostname dork per engine, scoped to the in-scope root
    IFS=',' read -ra _engs <<< "$UNCOVER_ENGINES"
    for eng in "${_engs[@]}"; do
      case "$eng" in
        shodan) run_engine shodan "ssl.cert.subject.CN:\"$root\"" "$cands" ;;
        censys) run_engine censys "services.tls.certificates.leaf_data.subject.common_name:\"$root\"" "$cands" || true ;;
        *)      run_engine "$eng" "$root" "$cands" || true ;;
      esac
    done
    # keep only candidates within the in-scope root (cert dorks can return unrelated SANs)
    grep -aE "(^|\.)${root//./\\.}$" "$cands" 2>/dev/null | awk 'NF && !s[$0]++' > "$cands.f" && mv "$cands.f" "$cands"
    emit_new "$cands" "$root"
    printf '%s\n' "$root" >> "$SEEN"
    rm -f "$cands"
  done
  tail -n 20000 "$SEEN" > "$SEEN.tmp" 2>/dev/null && mv "$SEEN.tmp" "$SEEN" 2>/dev/null || true
  log "🔭 uncover cycle done · budget now $(budget_used)/$UNCOVER_MONTHLY_BUDGET this month"
}

case "${1:-cycle}" in
  cycle|"") cmd_cycle ;;
  query)    shift; cmd_query "$@" ;;
  budget)   echo "Shodan uncover budget: $(budget_used)/$UNCOVER_MONTHLY_BUDGET used this month ($MONTH)" ;;
  *)        echo "usage: recon_uncover.sh {cycle|query \"<dork>\" [engine]|budget}" >&2; exit 1 ;;
esac

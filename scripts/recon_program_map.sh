#!/usr/bin/env bash
# =============================================================================
# recon_program_map.sh — standing PROGRAM-MAP routine for the committed program.
#
# The program walk's two most productive techniques are mechanical, so they belong on a
# cadence rather than in a human's evening:
#   (1) response-signature clustering, which turned 624 hosts into a 177-host worklist by
#       collapsing two thirds of the estate into ~24 commodity classes answering identically;
#   (2) bundle mining, which recovered an entire account GraphQL surface, a 64-route auth
#       table, two Cognito pools and a crisis backend — without probing one app endpoint.
#
# TRANSITION GATE: reports on CHANGE, not state. First sighting is a SILENT baseline; after
# that only new hosts, moved signatures and newly-mined surface are surfaced. What was already
# exposed when we started watching is months old and duplicate-bait; what appeared today is not.
#
# SCANNER BANS RESPECTED BY CONSTRUCTION: programs listed NO_PROBE in program_map.py (booking.com
# among them, whose policy prohibits automated scanning) get ZERO requests to the application —
# the routine reads the pipeline index and fetches only static JS from CDN hosts. Fetching a
# public CDN asset is not a scan of the target app.
#
# Records every delta into the program WORKSPACE as a note (so it lands in the walk artifact and
# the record is never just a file on disk), then regenerates the artifact.
#
# Not target-app traffic → runs as d0k. The supervise_loop VPN gate still pauses it on vpn_down,
# and this script re-checks fail-closed. Killswitch: state/kill/v2_progmap.
#
# MODES:
#   map  (default)  cluster + mine + record + regenerate the artifact
#   enum            passive subdomain discovery scoped to THIS program's roots, so the estate
#                   list keeps growing instead of ageing. Passive sources + public resolvers
#                   only (CT logs and third-party APIs, never the target), and NEW hosts are
#                   handed to the existing validator queue rather than probed here.
#
# USAGE:  recon_program_map.sh [workspace-key]            # map
#         recon_program_map.sh enum [workspace-key]       # discover
# =============================================================================
set -uo pipefail
IFS=$'\n\t'

log()  { printf '[%s PROGMAP] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s PROGMAP WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
LOCK="$STATE_DIR/progmap.lock"
PY="${PY:-python3}"

mkdir -p "$STATE_DIR" "$BASE_DIR/briefings" 2>/dev/null || true

# ---- killswitch + VPN gate (fail closed: no flag file, no run) --------------
[[ -f "$STATE_DIR/kill/v2_progmap" ]] && { log "killswitch set — skipping"; exit 0; }
[[ -f "$STATE_DIR/vpn_down" ]]      && { log "vpn_down — skipping (fail closed)"; exit 0; }

# ---- one at a time ----------------------------------------------------------
exec 9>"$LOCK" || exit 0
flock -n 9 || { log "another cycle holds the lock — skipping"; exit 0; }

# ---- mode -------------------------------------------------------------------
MODE="map"
if [[ "${1:-}" == "enum" || "${1:-}" == "map" ]]; then MODE="$1"; shift; fi

# ---- which program? ---------------------------------------------------------
KEY="${1:-}"
if [[ -z "$KEY" ]]; then
  KEY="$("$PY" - <<'PY' 2>/dev/null
import os, sys
sys.path.insert(0, os.path.expanduser("~/recon-ctl/ui"))
try:
    from backend import workspace as W
    cur = next((w for w in W.list_all() if w.get("current")), None)
    print(cur["key"] if cur else "")
except Exception:
    print("")
PY
)"
fi
[[ -n "$KEY" ]] || { warn "no workspace key and no current workspace — nothing to map"; exit 0; }

DELTA="$(mktemp)"; trap 'rm -f "$DELTA"' EXIT
LIMIT="${PROGMAP_LIMIT:-8}"

# =============================================================================
# enum mode — passive discovery scoped to this program's own roots.
# Passive sources only (CT logs / third-party APIs) and public resolvers: none of this is
# traffic to the bug-bounty host, which is why it is safe on a program that bans scanning.
# NEW hosts go to the validator queue; this script never probes them itself.
# =============================================================================
if [[ "$MODE" == "enum" ]]; then
  INBOX="${INBOX:-$BASE_DIR/queue/inbox}"
  KNOWN="${KNOWN_HOSTS:-$STATE_DIR/known_hosts.txt}"
  INBOX_CAP="${PROGMAP_INBOX_CAP:-180}"
  mkdir -p "$INBOX" || true

  nq="$(find "$INBOX" -maxdepth 1 -type f -name '[0-9][0-9]_*' 2>/dev/null | wc -l | tr -d ' ')"
  [[ "${nq:-0}" -ge "$INBOX_CAP" ]] && { log "validator queue backed up ($nq) — skipping enum"; exit 0; }

  SUBFINDER="$(command -v subfinder || true)"
  [[ -n "$SUBFINDER" ]] || { warn "subfinder not installed — enum unavailable"; exit 0; }

  # the program's root domains, taken from what the index already holds for it
  mapfile -t ROOTS < <("$PY" - "$KEY" <<'PY'
import json, os, subprocess, sys, collections
key = sys.argv[1]
pw = os.path.expanduser("~/.recon_es_pass")
auth = ["-u", "elastic:" + open(pw).read().strip()] if os.path.exists(pw) else []
q = {"query": {"term": {"triage_program": key}}, "size": 0,
     "aggs": {"r": {"terms": {"field": "root_domain", "size": 25}}}}
out = subprocess.run(["curl", "-s", "--max-time", "30", *auth,
                      "-H", "Content-Type: application/json",
                      f"{os.environ.get('ES_URL','http://127.0.0.1:9200')}/"
                      f"{os.environ.get('INDEX_NAME','recon_alive')}/_search",
                      "-d", json.dumps(q)], capture_output=True, text=True).stdout
try:
    for b in json.loads(out)["aggregations"]["r"]["buckets"]:
        print(b["key"])
except Exception:
    pass
PY
)
  [[ "${#ROOTS[@]}" -gt 0 ]] || { warn "no root domains known for $KEY"; exit 0; }
  log "enum: ${#ROOTS[@]} root(s) for '$KEY' — ${ROOTS[*]}"

  TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"; rm -f "$DELTA"' EXIT
  : > "$TMP/all.txt"
  for r in "${ROOTS[@]}"; do
    timeout 300 "$SUBFINDER" -silent -all -d "$r" >> "$TMP/all.txt" 2>/dev/null || true
  done
  awk 'NF && !s[$0]++' "$TMP/all.txt" > "$TMP/uniq.txt"
  ntot="$(wc -l < "$TMP/uniq.txt" | tr -d ' ')"

  if [[ -s "$KNOWN" ]]; then
    grep -avxF -f "$KNOWN" "$TMP/uniq.txt" 2>/dev/null > "$TMP/unseen.txt" || cp "$TMP/uniq.txt" "$TMP/unseen.txt"
  else
    cp "$TMP/uniq.txt" "$TMP/unseen.txt"
  fi
  nunseen="$(wc -l < "$TMP/unseen.txt" 2>/dev/null | tr -d ' ')"

  # RESOLVE BEFORE QUEUEING. Passive sources on a large estate return many thousands of names,
  # most of them dead or wildcard noise — on booking.com a single pass produced 12,168 names of
  # which 9,411 were unseen. Handing that to the prober would be an unbounded flood, so resolve
  # against PUBLIC resolvers first (cheap, and not target traffic) and queue only what answers.
  PUREDNS="$(command -v puredns || true)"
  RESOLVERS="${RESOLVERS_FILE:-$STATE_DIR/resolvers.txt}"
  if [[ -n "$PUREDNS" && -s "$RESOLVERS" && "${nunseen:-0}" -gt 0 ]]; then
    timeout 900 "$PUREDNS" resolve "$TMP/unseen.txt" -r "$RESOLVERS" --resolvers-trusted "$RESOLVERS" \
      --rate-limit "${PROGMAP_ENUM_RL:-800}" -q 2>/dev/null \
      | awk 'NF && !s[$0]++' > "$TMP/live.txt" || cp "$TMP/unseen.txt" "$TMP/live.txt"
  else
    [[ -n "$PUREDNS" ]] || warn "puredns absent — queueing unresolved names, capped"
    cp "$TMP/unseen.txt" "$TMP/live.txt" 2>/dev/null || : > "$TMP/live.txt"
  fi
  nlive="$(wc -l < "$TMP/live.txt" 2>/dev/null | tr -d ' ')"

  # Hard per-cycle cap with a sliding window: the remainder is not lost, it is picked up next
  # cycle, so a large estate is worked through steadily instead of in one burst.
  CAP="${PROGMAP_ENUM_CAP:-300}"
  ESEEN="${PROGMAP_ENUM_SEEN:-$STATE_DIR/progmap_enum_seen_${KEY}.txt}"
  touch "$ESEEN"
  grep -avxF -f "$ESEEN" "$TMP/live.txt" 2>/dev/null > "$TMP/fresh.txt" || cp "$TMP/live.txt" "$TMP/fresh.txt"
  head -n "$CAP" "$TMP/fresh.txt" > "$TMP/new.txt"
  nnew="$(wc -l < "$TMP/new.txt" 2>/dev/null | tr -d ' ')"
  nheld="$(( $(wc -l < "$TMP/fresh.txt" 2>/dev/null | tr -d ' ') - nnew ))"

  if [[ "${nnew:-0}" -gt 0 ]]; then
    out="$INBOX/15_$(date -u +%Y%m%dT%H%M%SZ)_progmap_${KEY}.txt"
    sort -u "$TMP/new.txt" > "$out"
    cat "$TMP/new.txt" >> "$ESEEN"
    tail -n 200000 "$ESEEN" > "$ESEEN.tmp" 2>/dev/null && mv "$ESEEN.tmp" "$ESEEN" 2>/dev/null || true
    log "enum done · $ntot passive → $nunseen unseen → $nlive resolving → $nnew queued (cap $CAP, $nheld held for next cycle) → $out"
    "$PY" - "$KEY" "$nnew" "$ntot" "$nlive" "$nheld" "$out" <<'PY'
import os, sys
sys.path.insert(0, os.path.expanduser("~/recon-ctl/ui"))
from backend import workspace as W
key, nnew, ntot, nlive, nheld, out = sys.argv[1:7]
W.add_note(key,
  f"PROGRAM-MAP ENUM - passive discovery queued {nnew} newly-surfaced host(s) for classification. "
  f"Pass: {ntot} names returned across this program's root domains, {nlive} resolved live, {nnew} "
  f"queued this cycle and {nheld} held for the next (a per-cycle cap keeps a large estate from "
  f"flooding the prober). Passive sources plus PUBLIC resolvers only, so no traffic reached the "
  f"target - which is what makes this safe on a program that prohibits scanning. Queued at {out}; "
  f"they enter the estate map once the rate-limited prober has classified them. Newly-surfaced "
  f"hosts carry the lowest duplicate risk on a saturated program, which is why this runs on a "
  f"cadence rather than once.")
print("  recorded an enum note")
PY
  else
    log "enum done · $ntot passive → $nunseen unseen → $nlive resolving → 0 to queue (all already handled)"
  fi
  exit 0
fi

log "mapping program '$KEY' (bundle-mine limit $LIMIT)"
if ! "$PY" "$REPO_DIR/tools/program_map.py" "$KEY" --limit "$LIMIT" --json "$DELTA"; then
  warn "program_map.py failed for $KEY"; exit 1
fi

# ---- record the delta into the WORKSPACE so it reaches the walk artifact ----
"$PY" - "$KEY" "$DELTA" <<'PY'
import json, os, sys
sys.path.insert(0, os.path.expanduser("~/recon-ctl/ui"))
from backend import workspace as W

key, dpath = sys.argv[1], sys.argv[2]
try:
    d = json.load(open(dpath))
except Exception as exc:
    print(f"  ! unreadable delta: {exc}"); raise SystemExit(0)

c = d.get("counts", {})
new, chg, gone = d.get("new_hosts") or [], d.get("changed") or [], d.get("gone") or []
surf = d.get("new_surface") or {}

# Nothing moved and nothing mined => say nothing. A routine that posts every cycle
# teaches the reader to ignore it, which is how a real change gets missed.
if not (new or chg or surf) and not d.get("first_run"):
    print("  no change this cycle — nothing recorded (by design)")
    raise SystemExit(0)

bits = [f"PROGRAM-MAP ROUTINE {d.get('date')} - automated cycle, transition-gated."]
bits.append(f"Estate: {c.get('indexed')} hosts indexed, {c.get('answering')} in-scope+paying and "
            f"answering, {c.get('commodity_classes')} commodity classes covering most of them, "
            f"{c.get('distinct')} with a DISTINCT response (the worklist).")
if d.get("first_run"):
    # On a first run EVERY host is "new", which is noise rather than news - state the
    # baseline size and let the next cycle report actual arrivals.
    bits.append(f"FIRST RUN: baseline of {len(new)} answering hosts established; from here "
                "only new arrivals, moved signatures and newly-mined surface are reported.")
elif new:
    bits.append(f"NEW HOSTS ({len(new)}): " + ", ".join(new[:22]) + ("..." if len(new) > 22 else ""))
if chg:
    bits.append(f"CHANGED SIGNATURE ({len(chg)}) - a response that moved is the thing worth a look: "
                + ", ".join(chg[:22]) + ("..." if len(chg) > 22 else ""))
if gone:
    bits.append(f"STOPPED ANSWERING ({len(gone)}): " + ", ".join(gone[:16]))
# SURFACE IS ONLY "NEW" IF THE RECORD DOES NOT ALREADY HOLD IT. The miner slides a cursor across
# the distinct-host pool, so each cycle mines a DIFFERENT eight hosts and reports their surface as
# new relative to the mining baseline - even when those exact routes were written down by an
# earlier pass. Hourly, that produced eight near-identical notes whose only real content was the
# same estate counts, and the routine's own strategy pass called it out: "this cycle's new surface
# re-derived recorded routes". A record that restates itself teaches the reader to skim it, which
# is the failure this transition gate exists to prevent. So filter against what is already written.
_ws = W.load(key) or {}
_corpus = " ".join(
    [n.get("text") or "" for n in _ws.get("notes", [])]
    + [(r.get("threat") or "") + " " + (r.get("note") or "")
       for rows in _ws.get("stride", {}).values() for r in rows]
    + [w.get("note") or "" for w in _ws.get("wstg", [])]
)
_surf_fresh = {}
for h, delta in surf.items():
    keep = {}
    for k in ("identity", "api_paths", "gql_ops", "env_keys"):
        unseen = [v for v in (delta.get(k) or []) if v not in _corpus]
        if unseen:
            keep[k] = unseen
    if keep:
        _surf_fresh[h] = keep
_suppressed = len(surf) - len(_surf_fresh)
surf = _surf_fresh

# Re-apply the say-nothing rule now that re-derived surface is gone: if the ONLY reason this cycle
# looked eventful was already-recorded routes, it is not eventful.
if not (new or chg or gone or surf) and not d.get("first_run"):
    print(f"  no change this cycle — {_suppressed} host(s) re-mined surface already in the record; "
          "nothing recorded (by design)")
    raise SystemExit(0)

for h, delta in list(surf.items())[:10]:
    parts = []
    for k in ("identity", "api_paths", "gql_ops", "env_keys"):
        v = delta.get(k)
        if v:
            parts.append(f"{k}: " + ", ".join(v[:12]))
    if parts:
        bits.append(f"NEW SURFACE on {h} - " + " | ".join(parts))
if _suppressed:
    bits.append(f"({_suppressed} further host(s) re-mined surface already in the record and were "
                "suppressed rather than restated.)")
bits.append(f"Full briefing: {d.get('briefing')}")

W.add_note(key, " ".join(bits)[:4000])
print(f"  recorded a note for {key}")

# An identity artefact (a Cognito pool, an Auth0 tenant, an SCIM endpoint) appearing on a
# host that had none is the kind of change that deserves a threat row, not just a note.
for h, delta in surf.items():
    ids = delta.get("identity") or []
    if not ids:
        continue
    W.update_stride(key, "S",
        f"Program-map routine found identity infrastructure newly exposed on {h}: "
        + ", ".join(ids[:6])
        + ". A user pool, tenant or provisioning endpoint reachable from a client bundle is a "
          "registration-gate and token-audience question - check whether self-signup is open and "
          "which relying parties trust it.",
        None, "", "open", [h])
    print(f"  raised a STRIDE row for identity on {h}")
PY

# ---- regenerate the walk artifact so the record and the document agree ------
if [[ -x "$REPO_DIR/tools/walk_publish.sh" || -f "$REPO_DIR/tools/walk_publish.sh" ]]; then
  # Its output goes where log()/warn() go — the inherited stderr, which the daemon already
  # redirects into its log. Never reopen /dev/stderr: when stderr is a pipe (a `| tail` on the
  # command line) that open fails EACCES, and the failed redirect was being misread as
  # walk_publish reporting an inconsistency.
  if bash "$REPO_DIR/tools/walk_publish.sh" "$KEY" 1>&2; then
    log "artifact regenerated for $KEY (republish is the operator's step)"
  else
    warn "walk_publish.sh reported an inconsistency for $KEY — artifact NOT safe to republish"
  fi
fi

log "cycle complete for '$KEY'"

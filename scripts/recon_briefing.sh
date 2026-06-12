#!/usr/bin/env bash
# =============================================================================
# recon_briefing.sh — the 6:30pm "TONIGHT" worklist for a part-time hunter.
#
# Turns 24h of machine work into one ranked, actionable card delivered when you get home:
#   1. BAC/IDOR leads to TEST tonight (endpoint + the exact two-account test)  ← the money
#   2. Verified LIVE secrets + Claude-validated findings ready to SUBMIT
# Runs hourly; compiles + posts ONCE per day at/after BRIEFING_HOUR (local). Writes a
# durable .md too. Read-only; no target traffic.
# =============================================================================
set -uo pipefail
IFS=$'\n\t'
log() { printf '[%s BRIEFING] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/recon_net.sh" 2>/dev/null || true
BASE_DIR="${BASE_DIR:-$HOME/recon}"; STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"; INDEX_NAME="${INDEX_NAME:-recon_alive}"
V3_DB="${V3_DB:-$BASE_DIR/v3/findings.db}"
WORKLIST="${IDOR_WORKLIST:-$BASE_DIR/idor_worklist.jsonl}"
BRIEF_FILTER="${BRIEF_FILTER:-$REPO_DIR/tools/brief_filter.py}"
BRIEF_DIR="${BRIEF_DIR:-$BASE_DIR/briefings}"
BRIEFING_HOUR="${BRIEFING_HOUR:-18}"     # local hour to deliver (default 6pm)
FORCE="${BRIEFING_FORCE:-0}"

mkdir -p "$STATE_DIR" "$BRIEF_DIR"
exec 9>"$STATE_DIR/briefing.lock"; flock -n 9 || exit 0
command -v jq >/dev/null 2>&1 || exit 0

# ---- render-time FP gate (doctrine: an adjudicated/known-noise finding never re-queues) ----
# Applied to every findings.db / digest stream AT RENDER: (1) the P2 structural class rules
# (brief_filter.py --noise — generalises to BRAND-NEW hosts, downgrades unverified KEV), then
# (2) the SQLite false_positive_signatures table + knowledge_base fp-lessons read LIVE (so the
# post-B1 dismissed/known FPs are dropped here too even if they linger in a non-terminal state).
GATE_SUPP=0
read -r -d '' PY_DBGATE <<'PY' || true
import os,sys,json,sqlite3,hashlib
def sig(h,s,v): return hashlib.sha1(f"{(h or '').lower()}|{s or ''}|{v or ''}".encode('utf-8','ignore')).hexdigest()[:20]
def rd(h):
    p=[x for x in (h or '').lower().split(':')[0].split('.') if x]
    return '.'.join(p[-2:]) if len(p)>=2 else (h or '')
try: arr=json.load(sys.stdin)
except Exception: arr=[]
if not isinstance(arr,list): arr=[]
keep=arr
try:
    c=sqlite3.connect(os.environ.get("V3_DB","")); c.row_factory=sqlite3.Row
    fps=set(r["signature"] for r in c.execute("SELECT signature FROM false_positive_signatures"))
    kbfp=set(((r["root_domain"] or "").lower(),(r["vuln_class"] or "").lower())
             for r in c.execute("SELECT root_domain,vuln_class FROM knowledge_base WHERE verdict='fp'"))
    keep=[]
    for o in arr:
        h=o.get("host",""); s=o.get("signal_class","")
        v=o.get("vuln_class") or o.get("vuln_type") or o.get("cls") or ""
        if sig(h,s,v) in fps: continue
        if (rd(h),(v or "").lower()) in kbfp: continue
        keep.append(o)
except Exception:
    keep=arr
print(json.dumps(keep))
PY

render_gate() {   # arg1: JSON array -> stdout filtered JSON array; bumps GATE_SUPP
  local arr="${1:-[]}"
  [[ -z "$arr" || "$arr" == "[]" ]] && { printf '[]'; return; }
  if [[ -f "$BRIEF_FILTER" ]]; then
    local nf; nf="$(printf '%s' "$arr" | python3 "$BRIEF_FILTER" --noise 2>/dev/null || echo '')"
    if [[ -n "$nf" ]] && printf '%s' "$nf" | jq -e . >/dev/null 2>&1; then
      GATE_SUPP=$(( GATE_SUPP + $(printf '%s' "$nf" | jq -r '.suppressed_count // 0') ))
      arr="$(printf '%s' "$nf" | jq -c '.keep')"
    fi
  fi
  local before after; before="$(printf '%s' "$arr" | jq 'length' 2>/dev/null || echo 0)"
  local gated; gated="$(printf '%s' "$arr" | V3_DB="$V3_DB" python3 -c "$PY_DBGATE" 2>/dev/null || echo '')"
  if [[ -n "$gated" ]] && printf '%s' "$gated" | jq -e . >/dev/null 2>&1; then
    after="$(printf '%s' "$gated" | jq 'length' 2>/dev/null || echo 0)"
    [[ "$((before - after))" -gt 0 ]] && GATE_SUPP=$(( GATE_SUPP + before - after ))
    arr="$gated"
  fi
  printf '%s' "$arr"
}

today="$(date '+%Y-%m-%d')"; hour="$(date '+%H')"; sent="$STATE_DIR/briefing_sent_$today"
if [[ "$FORCE" != "1" ]]; then
  [[ "$((10#$hour))" -ge "$BRIEFING_HOUR" ]] || exit 0   # not yet the briefing hour
  [[ -f "$sent" ]] && exit 0                              # already delivered today
fi

# --- 1) IDOR/BAC worklist: rank then feed a WIDE pool to the filter. We must filter
# BEFORE capping — if 88% of the worklist is product-class/shared-tenant noise, a
# pre-filter .[0:12] would be all noise and crowd out the genuine leads ranked #13+. -->
leads="$(grep -aE '"status":"to-test"' "$WORKLIST" 2>/dev/null \
  | jq -c '. ' 2>/dev/null \
  | jq -s 'unique_by(.host+.endpoint)
           | map(. + {rank: (({"critical":4,"high":3,"medium":2,"low":1}[.impact]) // 0) + (.confidence // 0)})
           | sort_by(-.rank) | .[0:80]' 2>/dev/null || echo '[]')"
nlead="$(printf '%s' "$leads" | jq 'length' 2>/dev/null || echo 0)"

# --- 1b) dup-risk + shared-tenant SAFETY triage (promote / hold / suppress) ---
# Collapses product-class repeats (same endpoint on N hosts = standard shipped API
# = dup) and suppresses shared-tenant landmines (cross-tenant test on a per-customer
# console you don't own = third-party data). Keeps winnable, SAFE leads on top.
show="$leads"; nsupp=0; supp_reasons=""; held="[]"
if [[ -f "$BRIEF_FILTER" ]] && [[ "${nlead:-0}" -gt 0 ]]; then
  filtered="$(printf '%s' "$leads" \
    | EP_STORE="$BASE_DIR/js_recon/endpoints.jsonl" ES_URL="$ES_URL" INDEX_NAME="$INDEX_NAME" \
      python3 "$BRIEF_FILTER" 2>/dev/null || echo '')"
  if [[ -n "$filtered" ]] && printf '%s' "$filtered" | jq -e . >/dev/null 2>&1; then
    show="$(printf '%s' "$filtered" | jq -c '.promote')"   # full set; collapsed per-host + capped below
    held="$(printf '%s' "$filtered" | jq -c '.hold | .[0:8]')"
    nsupp="$(printf '%s' "$filtered" | jq -r '.suppressed_count // 0')"
    supp_reasons="$(printf '%s' "$filtered" | jq -r '(.suppressed_reasons // {}) | to_entries | map("\(.value)× \(.key)") | join(", ")')"
  fi
fi
nshow="$(printf '%s' "$show" | jq 'length' 2>/dev/null || echo 0)"
nheld="$(printf '%s' "$held" | jq 'length' 2>/dev/null || echo 0)"

# --- 2) findings ready to SUBMIT: Claude-real + verified-live-secrets ---
subs="[]"
if [[ -f "$V3_DB" ]]; then
  subs="$(V3_DB="$V3_DB" python3 - <<'PY' 2>/dev/null || echo '[]'
import os,sqlite3,json
try:
    c=sqlite3.connect(os.environ["V3_DB"]); c.row_factory=sqlite3.Row
    rows=[dict(r) for r in c.execute(
      "SELECT host,vuln_class,signal_class,COALESCE(ai_confidence,confidence) cf,COALESCE(ai_reason,'') reason "
      "FROM findings WHERE (ai_verdict='real' OR signal_class='verified-secret') "
      "AND state IN ('confirmed','reported') ORDER BY cf DESC LIMIT 15")]
    print(json.dumps(rows))
except Exception: print('[]')
PY
)"
fi
[[ -n "$subs" ]] || subs="[]"
subs="$(render_gate "$subs")"   # drop adjudicated-FP / known-noise-class rows at render
nsub="$(printf '%s' "$subs" | jq 'length' 2>/dev/null || echo 0)"

# --- 3) needs-human verdicts: Claude couldn't settle it — batched here (no live ping) ---
needh="[]"
if [[ -f "$V3_DB" ]]; then
  needh="$(V3_DB="$V3_DB" python3 - <<'PY' 2>/dev/null || echo '[]'
import os,sqlite3,json
try:
    c=sqlite3.connect(os.environ["V3_DB"]); c.row_factory=sqlite3.Row
    rows=[dict(r) for r in c.execute(
      "SELECT host,vuln_class,COALESCE(ai_confidence,confidence) cf,COALESCE(ai_reason,'') reason "
      "FROM findings WHERE ai_verdict='needs-human' AND state IN ('confirmed','reported') "
      "ORDER BY cf DESC LIMIT 8")]
    print(json.dumps(rows))
except Exception: print('[]')
PY
)"
fi
[[ -n "$needh" ]] || needh="[]"
needh="$(render_gate "$needh")"   # the 6 third-party-repo secrets etc. die here (class rule + fp/KB)
nneed="$(printf '%s' "$needh" | jq 'length' 2>/dev/null || echo 0)"

# --- 4) verified VULN leads (KEV/exposure/bypass) — reuse the digest selector's
# FP-filtered, version-aware, deduped PROMOTE set so this one card replaces the
# separate 5:30 lead-digest. Read-only emit; bounded so a slow run can't hang the card. ---
vleads="[]"
DIGEST_SELECTOR="${DIGEST_SELECTOR:-$SCRIPT_DIR/recon_digest_leads.sh}"
if [[ -f "$DIGEST_SELECTOR" ]]; then
  vleads="$(timeout 150 bash "$DIGEST_SELECTOR" emit 2>/dev/null \
    | jq -c '[.promote[] | {host, cls, what, check, prog, url, score, cves}] | sort_by(-(.score // 0)) | .[0:10]' 2>/dev/null || echo '[]')"
fi
[[ -n "$vleads" ]] || vleads="[]"
vleads="$(render_gate "$vleads")"   # class rules downgrade unverified KEV (-> _noise_action=downgrade)
nvln="$(printf '%s' "$vleads" | jq 'length' 2>/dev/null || echo 0)"

# split promoted leads: genuine BAC/IDOR (endpoint = path) vs n-day-cve (CVE, no path) —
# they render differently; otherwise host+endpoint concatenates into garbage like
# "technik.bild.deCVE: CVE-2024-34102".
# COLLAPSE same-host route-guesses into ONE lead with a route list (doctrine: N route
# guesses on one host = one lead, not N cards — e.g. 12 admin.indeedflex.com routes -> 1).
# Collapse BEFORE the [0:12] cap so genuinely-distinct hosts aren't crowded out by one noisy host.
show_idor="$(printf '%s' "$show" | jq -c '[.[] | select((.vuln_type // "") != "n-day-cve")]
  | group_by(.host)
  | map( (max_by(.rank // 0)) + {routes: (map(.endpoint) | map(select(. != null and . != "")) | unique),
                                 route_count: length} )
  | sort_by(-(.rank // 0)) | .[0:12]' 2>/dev/null || echo '[]')"
show_nday="$(printf '%s' "$show" | jq -c '[.[] | select((.vuln_type // "") == "n-day-cve")] | .[0:12]' 2>/dev/null || echo '[]')"
nidor="$(printf '%s' "$show_idor" | jq 'length' 2>/dev/null || echo 0)"
nnday="$(printf '%s' "$show_nday" | jq 'length' 2>/dev/null || echo 0)"

if [[ "${nshow:-0}" -eq 0 && "${nheld:-0}" -eq 0 && "${nsub:-0}" -eq 0 && "${nneed:-0}" -eq 0 && "${nvln:-0}" -eq 0 ]]; then
  [[ "${nsupp:-0}" -gt 0 ]] && log "all $nlead lead(s) suppressed ($supp_reasons); nothing to submit" \
                            || log "nothing actionable to brief today"
  touch "$sent"; exit 0
fi

# --- compile the card + durable .md ---
md="$BRIEF_DIR/tonight_$today.md"
{
  printf '# 🌙 TONIGHT — %s\n\n' "$today"
  printf '## 🎯 Test these (BAC/IDOR — the money class) — %s winnable lead(s)\n' "$nidor"
  printf '%s' "$show_idor" | jq -r '
    def loc: if ((.endpoint//"")|startswith("http")) then .endpoint elif ((.endpoint//"")|startswith("/")) then (.host+.endpoint) elif ((.endpoint//"")=="") then .host else (.host+" · "+.endpoint) end;
    .[] |
    "\n### [\(.impact|ascii_upcase) · conf \(.confidence)] \(.vuln_type) — `\(.host)`"
    + (if (.route_count // 1) > 1
         then "\n- **routes to test (\(.route_count)):** " + ((.routes // []) | map("`"+.+"`") | join(", "))
         else "\n- **endpoint:** `\(loc)`" end)
    + "\n- **why:** \(.why)\n- **test:** \(.test)\n- program: \(.program // "?")"' 2>/dev/null
  if [[ "${nnday:-0}" -gt 0 ]]; then
    printf '\n\n## ⚡ n-day CVE candidates (version-reasoned) — %s\n' "$nnday"
    printf '%s' "$show_nday" | jq -r '.[] | "\n### [\(.impact|ascii_upcase) · conf \(.confidence)] \(.host) — \(.cve // .endpoint // "?")\n- **why:** \(.why)\n- **verify:** \(.test)\n- program: \(.program // "?")"' 2>/dev/null
  fi
  if [[ "${nheld:-0}" -gt 0 ]]; then
    printf '\n\n## 🟡 If time (medium dup-risk) — %s\n' "$nheld"
    printf '%s' "$held" | jq -r 'def loc: if ((.endpoint//"")|startswith("http")) then .endpoint elif ((.endpoint//"")|startswith("/")) then (.host+.endpoint) elif ((.endpoint//"")=="") then .host else (.host+" · "+.endpoint) end;
      .[] | "- [\(.impact)] \(.vuln_type) `\(loc)` — \(.hold_reason // "")"' 2>/dev/null
  fi
  nsupp_total=$(( ${nsupp:-0} + GATE_SUPP ))
  if [[ "$nsupp_total" -gt 0 ]]; then
    printf '\n\n## 🔕 Suppressed — %s lead(s)' "$nsupp_total"
    [[ -n "$supp_reasons" ]] && printf ': %s' "$supp_reasons"
    printf '\n'
    [[ "$GATE_SUPP" -gt 0 ]] && printf '_(+%s dropped at render by the FP-class rules + fp-signature/KB gate — adjudicated/known noise never re-queued)_\n' "$GATE_SUPP"
    printf '_(product-class duplicates and shared-tenant/third-party-data landmines — not worth your evening, kept here for audit)_\n'
  fi
  printf '\n\n## ✅ Ready to submit (validated) — %s\n' "$nsub"
  printf '%s' "$subs" | jq -r '.[] | "- **\(.vuln_class)** on `\(.host)` (conf \(.cf)) — \(.reason[0:140])"' 2>/dev/null
  if [[ "${nneed:-0}" -gt 0 ]]; then
    printf '\n\n## 🔍 Needs a human eye (Claude unsure) — %s\n' "$nneed"
    printf '%s' "$needh" | jq -r '.[] | "- **\(.vuln_class)** on `\(.host)` (conf \(.cf)) — \(.reason[0:140])"' 2>/dev/null
  fi
  if [[ "${nvln:-0}" -gt 0 ]]; then
    printf '\n\n## 🧪 Vuln leads (KEV / exposure / bypass — verify before trusting) — %s\n' "$nvln"
    printf '%s' "$vleads" | jq -r '.[] |
      (if ._noise_action=="downgrade" then "LEAD · version-unconfirmed — " else "" end) as $tag |
      "- \($tag)**\(.cls)** `\(.host)` [\(.prog // "?")]\n  - \(.what)\n  - check: \(.check)"' 2>/dev/null
  fi
  printf '\n\n_Deep-check any lead before you spend time on it:_ `recon-verify <host>` _(Claude + safe probes)._\n'
  printf '_Test BAC/IDOR with your own two accounts. Submission is always your call._\n'
} > "$md" 2>/dev/null

log "🌙 briefing compiled · 🎯 $nidor host-lead(s) ($nshow pre-collapse) · 🟡 $nheld hold · 🔕 $nsupp dup + $GATE_SUPP render-gated · ✅ $nsub to-submit · 🔍 $nneed needs-human · 🧪 $nvln vuln-leads → $md"

# --- deliver to Discord (#digest — the single nightly card; #review is live-confirmed only) ---
rh="$(discord_hook digest 2>/dev/null || true)"
[[ -n "$rh" ]] || rh="$(discord_hook review 2>/dev/null || true)"   # fallback if #digest unset
if [[ -n "$rh" ]]; then
  card="$(printf '🌙 **TONIGHT — %s**\n\n🎯 **Test these (BAC/IDOR — %s winnable):**\n' "$today" "$nidor")"
  card+="$(printf '%s' "$show_idor" | jq -r '.[] |
    "• **\(.impact)** \(.vuln_type) `\(.host)`" + (if (.route_count // 1) > 1 then " (\(.route_count) routes)" else "" end) + " (c\(.confidence))\n   test: \(.test)"' 2>/dev/null | head -c 1000)"
  [[ "${nnday:-0}" -gt 0 ]] && { card+="$(printf '\n\n⚡ **n-day CVE candidates (%s):**\n' "$nnday")"; card+="$(printf '%s' "$show_nday" | jq -r '.[] | "• **\(.impact)** `\(.host)` — \(.cve // .endpoint) (c\(.confidence))"' 2>/dev/null | head -c 400)"; }
  card+="$(printf '\n\n✅ **Ready to submit (%s):**\n' "$nsub")"
  card+="$(printf '%s' "$subs" | jq -r '.[] | "• \(.vuln_class) `\(.host)` (c\(.cf))"' 2>/dev/null | head -c 350)"
  [[ "${nvln:-0}" -gt 0 ]] && { card+="$(printf '\n\n🧪 **Vuln leads (verify before trusting) (%s):**\n' "$nvln")"; card+="$(printf '%s' "$vleads" | jq -r '.[] | (if ._noise_action=="downgrade" then "LEAD·ver-unconf " else "" end) as $t | "• \($t)\(.cls) `\(.host)` — \(.check)"' 2>/dev/null | head -c 500)"; }
  [[ "${nneed:-0}" -gt 0 ]] && { card+="$(printf '\n\n🔍 **Needs a human eye (%s):**\n' "$nneed")"; card+="$(printf '%s' "$needh" | jq -r '.[] | "• \(.vuln_class) `\(.host)` (c\(.cf))"' 2>/dev/null | head -c 300)"; }
  [[ "$(( ${nsupp:-0} + GATE_SUPP ))" -gt 0 ]] && card+="$(printf '\n\n🔕 _%s lead(s) suppressed (%s noise-class/dup, %s adjudicated-FP at render)_' "$(( ${nsupp:-0} + GATE_SUPP ))" "${nsupp:-0}" "$GATE_SUPP")"
  discord_post "$rh" "$(jq -nc --arg c "${card:0:1950}" '{content:$c}')" >/dev/null 2>&1 \
    && log "🌙 briefing posted to #digest" || log "discord post failed (card saved to $md)"
fi
touch "$sent"

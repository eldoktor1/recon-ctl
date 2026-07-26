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
# FRESHNESS: a to-test entry stays to-test forever, so without an age bound the same
# months-old lead (e.g. an admin.* IDOR from weeks back) re-serves every night. Drop
# entries whose `at` is older than the window; keep un-stamped ones (never seen, but a
# producer without `at` shouldn't be silently muted). Mirrors the digest-leads gate.
WL_FRESH_DAYS="${WL_FRESH_DAYS:-30}"
WL_CUTOFF="$(date -u -d "${WL_FRESH_DAYS} days ago" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null \
  || date -u -v-"${WL_FRESH_DAYS}"d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo '1970-01-01T00:00:00Z')"
leads="$(grep -aE '"status":"to-test"' "$WORKLIST" 2>/dev/null \
  | jq -c '. ' 2>/dev/null \
  | jq -s --arg cut "$WL_CUTOFF" 'map(select((.at // "") == "" or (.at >= $cut)))
           | unique_by(.host+.endpoint)
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

# --- 4b) cloud-bucket exposure LEADS (public-read / read-acl / dangling-takeover). Confirmed
# public-WRITE buckets already flow via db_confirm → findings.db → the SUBMIT section above; this
# surfaces the read/acl LEADS that need a content-sensitivity + by-design check. Recent + deduped. ---
BKT_LEADS="${BKT_LEADS:-$BASE_DIR/buckets/leads.jsonl}"
bkts="[]"
if [[ -s "$BKT_LEADS" ]]; then
  bkts="$(tail -n 300 "$BKT_LEADS" 2>/dev/null | jq -c '.' 2>/dev/null \
    | jq -s 'map(select(.ts and (.ts >= (now - 3*86400 | todate))))
             | unique_by(.bucket)
             | sort_by({"critical":4,"high":3,"medium":2,"low":1,"info":0}[.severity] // 0) | reverse
             | .[0:12]' 2>/dev/null || echo '[]')"
fi
[[ -n "$bkts" ]] || bkts="[]"
nbkt="$(printf '%s' "$bkts" | jq 'length' 2>/dev/null || echo 0)"

# --- 4d) GraphQL worklist: introspection-on endpoints with sensitive unauth ops / IDOR-injectable args
# (human test with 2 owned accounts — never third-party IDs). Recent, deduped, sensitive-first. ---
GQL_WORKLIST="${GQL_WORKLIST:-$BASE_DIR/graphql/graphql_worklist.jsonl}"
gql="[]"
if [[ -s "$GQL_WORKLIST" ]]; then
  gql="$(tail -n 300 "$GQL_WORKLIST" 2>/dev/null | jq -c '.' 2>/dev/null \
    | jq -s 'map(select(.ts and (.ts >= (now - 3*86400 | todate)) and (.introspection_enabled or .recovery=="field-suggestion") and ((.n_sensitive//0)>0)))
             | unique_by(.endpoint) | sort_by(.n_sensitive//0) | reverse | .[0:8]' 2>/dev/null || echo '[]')"
fi
[[ -n "$gql" ]] || gql="[]"
ngql="$(printf '%s' "$gql" | jq 'length' 2>/dev/null || echo 0)"

# --- 4e) Web-cache deception/poisoning LEADs (detect-only; impact PoC = owned account, operator) ---
WCD_LEADS="${WCD_LEADS:-$BASE_DIR/wcd/leads.jsonl}"
wcd="[]"
if [[ -s "$WCD_LEADS" ]]; then
  wcd="$(tail -n 200 "$WCD_LEADS" 2>/dev/null | jq -c '.' 2>/dev/null \
    | jq -s 'map(select(.ts and (.ts >= (now - 3*86400 | todate)))) | unique_by(.host+.kind)
             | sort_by(if .severity=="high" then 2 else 1 end) | reverse | .[0:8]' 2>/dev/null || echo '[]')"
fi
[[ -n "$wcd" ]] || wcd="[]"
nwcd="$(printf '%s' "$wcd" | jq 'length' 2>/dev/null || echo 0)"

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

# --- SUPPRESS worked-and-killed hosts: stop re-serving corpses. A host whose host_notes
# verdict is "dead" (killed / not-a-finding / by-design / "do NOT re-walk", not re-armed) is
# dropped from every LEAD stream. Confirmed findings (subs/held) are NOT touched. Open/armed
# leads (RESUME/precondition-still-met without a kill) survive. See tools/note_verdict.py. ---
NOTES_FILE="${NOTES_FILE:-$STATE_DIR/host_notes.jsonl}"
KILLED_JSON="$(python3 "$REPO_DIR/tools/note_verdict.py" killed-hosts "$NOTES_FILE" 2>/dev/null | jq -R . | jq -s -c . 2>/dev/null || echo '[]')"
_dk(){ printf '%s' "$1" | jq -c --argjson k "$KILLED_JSON" '[.[] | select((((.host // .source_host // "")|ascii_downcase) as $h | ($k|index($h)|not)))]' 2>/dev/null || printf '%s' "$1"; }
_klen(){ printf '%s' "$1" | jq 'length' 2>/dev/null || echo 0; }
_before=$(( $(_klen "$vleads") + $(_klen "$bkts") + $(_klen "$gql") + $(_klen "$wcd") + $(_klen "$show_idor") + $(_klen "$show_nday") ))
vleads="$(_dk "$vleads")"; bkts="$(_dk "$bkts")"; gql="$(_dk "$gql")"; wcd="$(_dk "$wcd")"; show_idor="$(_dk "$show_idor")"; show_nday="$(_dk "$show_nday")"
nvln="$(_klen "$vleads")"; nbkt="$(_klen "$bkts")"; ngql="$(_klen "$gql")"; nwcd="$(_klen "$wcd")"; nidor="$(_klen "$show_idor")"; nnday="$(_klen "$show_nday")"
nkilled_supp=$(( _before - (nvln + nbkt + ngql + nwcd + nidor + nnday) ))
[[ "$nkilled_supp" -gt 0 ]] && log "🔕 suppressed $nkilled_supp worked-and-killed lead(s) (host_notes verdict=dead — no longer re-served)"

if [[ "${nshow:-0}" -eq 0 && "${nheld:-0}" -eq 0 && "${nsub:-0}" -eq 0 && "${nneed:-0}" -eq 0 && "${nvln:-0}" -eq 0 && "${nbkt:-0}" -eq 0 && "${ngql:-0}" -eq 0 && "${nwcd:-0}" -eq 0 ]]; then
  [[ "${nsupp:-0}" -gt 0 ]] && log "all $nlead lead(s) suppressed ($supp_reasons); nothing to submit" \
                            || log "nothing actionable to brief today"
  touch "$sent"; exit 0
fi

# --- noted hosts: flag (do NOT suppress) leads I've already worked. Emit the exact noted HOST;
# only contribute the root_domain when the note is genuinely ROOT-LEVEL (host empty or host==root)
# — otherwise a note on one subdomain flags every unrelated sibling under the apex (the leak). ---
NOTES_FILE="${NOTES_FILE:-$STATE_DIR/host_notes.jsonl}"
NOTED='[]'
[[ -s "$NOTES_FILE" ]] && NOTED="$(jq -r 'if ((.host // "") == "") or (.host == .root_domain) then (.root_domain // .host // empty) else (.host // empty) end' "$NOTES_FILE" 2>/dev/null | sort -u | jq -R . | jq -s -c . 2>/dev/null || echo '[]')"
[[ -n "$NOTED" ]] || NOTED='[]'

# --- rs0n XSS/SQLi lane: regenerate today's ranked, dup-proof worklist (ES-only, read-only —
# no target traffic, consistent with the briefing contract) and surface a pointer to the full
# .md lists. The card just headlines the counts + top unique hosts; `recon-params candidates`
# / the .md files hold the rest. Confirm with `recon-params confirm xss|sqli <host>`. ---
XSS_CAND_LINE=""; SQLI_CAND_LINE=""; XSS_TOP=""; SQLI_TOP=""
if [[ -f "$SCRIPT_DIR/recon_xss_sqli_candidates.py" ]]; then
  cand_out="$(python3 "$SCRIPT_DIR/recon_xss_sqli_candidates.py" --class both --stamp "$today" 2>/dev/null || true)"
  xf="$BRIEF_DIR/xss_candidates_$today.md"; sf="$BRIEF_DIR/sqli_candidates_$today.md"
  XSS_CAND_LINE="$(printf '%s' "$cand_out" | grep -m1 '^\[xss\]' | sed 's/ → .*//')"
  SQLI_CAND_LINE="$(printf '%s' "$cand_out" | grep -m1 '^\[sqli\]' | sed 's/ → .*//')"
  [[ -f "$xf" ]] && XSS_TOP="$(awk '/^## TOP UNIQUE/{f=1;next} /^## /{f=0} f&&/^### /{print;n++} n>=4{exit}' "$xf" 2>/dev/null)"
  [[ -f "$sf" ]] && SQLI_TOP="$(awk '/^## TOP UNIQUE/{f=1;next} /^## /{f=0} f&&/^### /{print;n++} n>=4{exit}' "$sf" 2>/dev/null)"
fi

# --- compile the card + durable .md ---
# day-mode banner (emphasis only — see docs/OPERATING.md; matches the 2IC routine modes)
case "$(date '+%u')" in
  1|2|3) mode_banner=" · UNAUTH night (lead: SUBMIT + DIG)" ;;
  4|6)   mode_banner=" · AUTHED night (ENGIE DCP / TOTO — your 2 accounts)" ;;
  5)     mode_banner=" · CLEANUP night" ;;
  7)     mode_banner=" · light" ;;
  *)     mode_banner="" ;;
esac

md="$BRIEF_DIR/tonight_$today.md"
{
  printf '# 🌙 TONIGHT — %s%s\n\n' "$today" "$mode_banner"

  # --- 🎯 HUNT THESE: the Under-Hunted Target Board — the selection layer at the mouth of the
  #     funnel. Point your DEPTH at fresh, low-saturation, authed-app programs (be unique, not
  #     duplicated) instead of grinding saturated giants. Top N are auto-onboarded to enumeration. ---
  tgt_json="$BRIEF_DIR/targets_latest.json"
  if [[ -s "$tgt_json" ]]; then
    printf '## 🎯 HUNT THESE — under-hunted target board (point your depth here)\n'
    jq -r '.programs[0:5][] | "- **\(.name)** [\(.platform)] — \(if .payout and .payout>0 then "$"+(.payout|tostring) else "pays" end) · authed×\(.n_authed) · fresh \(.fresh_days)d · `\(.key)`"' "$tgt_json" 2>/dev/null
    printf '  _menu: `recon-targets` · onboard any: `recon-targets onboard <key>`_\n\n'
  fi

  # --- ✅ SUBMIT first: machine-CONFIRMED (a confirm primitive fired) — ready to report ---
  printf '## ✅ Ready to submit (validated, confirm-fired) — %s\n' "$nsub"
  printf '%s' "$subs" | jq -r '.[] | "- **\(.vuln_class)** on `\(.host)` (conf \(.cf)) — \(.reason[0:140])"' 2>/dev/null

  # --- 🔬 DIG: unauth leads to work tonight (n-day version-reasoned + exposure/bypass) ---
  if [[ "${nnday:-0}" -gt 0 ]]; then
    printf '\n\n## ⚡ n-day CVE candidates (version-reasoned) — %s\n' "$nnday"
    printf '%s' "$show_nday" | jq -r '.[] | "\n### [\(.impact|ascii_upcase) · conf \(.confidence)] \(.host) — \(.cve // .endpoint // "?")\n- **why:** \(.why)\n- **verify:** \(.test)\n- program: \(.program // "?")"' 2>/dev/null
  fi
  if [[ "${nvln:-0}" -gt 0 ]]; then
    printf '\n\n## 🧪 Vuln leads (KEV / exposure / bypass — verify before trusting) — %s\n' "$nvln"
    printf '%s' "$vleads" | jq -r '.[] |
      (if ._noise_action=="downgrade" then "LEAD · version-unconfirmed — " else "" end) as $tag |
      "- \($tag)**\(.cls)** `\(.host)` [\(.prog // "?")]\n  - \(.what)\n  - check: \(.check)"' 2>/dev/null
  fi

  # --- ☁️ Cloud-bucket leads (public-read / acl / dangling — verify content + not by-design) ---
  if [[ "${nbkt:-0}" -gt 0 ]]; then
    printf '\n\n## ☁️ Cloud-bucket exposure (verify content sensitivity / not by-design) — %s\n' "$nbkt"
    printf '%s' "$bkts" | jq -r '.[] | "- **[\(.severity)] \(.kind)** `\(.bucket)` (\(.provider)\(if (.region//"")!="" then "/"+.region else "" end)) ← \(.host // .source_host) [\(.program // "?")]\n  - \(.access)\n  - inspect: `recon-buckets check \(.bucket) \(.provider)`\(if .provider=="aws" then "  · write-test: `recon-buckets writecheck \(.bucket) \(.region // "us-east-1")`" else "" end)"' 2>/dev/null
  fi

  # --- 🔮 GraphQL worklist (introspection-on; sensitive ops + IDOR/injectable args — human 2-acct test) ---
  if [[ "${ngql:-0}" -gt 0 ]]; then
    printf '\n\n## 🔮 GraphQL (schema exposed — human 2-account / injection test) — %s\n' "$ngql"
    printf '%s' "$gql" | jq -r '.[] | "- **`\(.host)`** `\(.endpoint)` — \(if .recovery=="field-suggestion" then "RECOVERED (introspection off)" else "introspection ON" end) · \(.n_sensitive) sensitive op(s) [\(.program // "?")]\n" + ([.candidates[]? | select(.sensitive or (.idor_args|length>0) or (.injectable_args|length>0)) | "  - [\(.score)] \(.op_type) **\(.name)** — \(.reason)"] | .[0:5] | join("\n"))' 2>/dev/null
  fi

  # --- ☁️ Web-cache deception/poisoning LEADs (detect-only; impact = owned account) ---
  if [[ "${nwcd:-0}" -gt 0 ]]; then
    printf '\n\n## ☁️ Web-cache deception/poisoning (verify w/ owned account) — %s\n' "$nwcd"
    printf '%s' "$wcd" | jq -r '.[] | "- **[\(.severity)] \(.kind)** `\(.host)` — \(.evidence)\n  - confirm: `recon-wcd confirm \(.host)`"' 2>/dev/null
  fi

  # --- 💉 XSS / SQLi (unauth) — ranked candidates to CONFIRM (rs0n dup-proof lane).
  #     Confirmed ones (dalfox executes / SQLi diff) already promote to SUBMIT above. ---
  if [[ -n "$XSS_CAND_LINE$SQLI_CAND_LINE" ]]; then
    printf '\n\n## 💉 XSS / SQLi (unauth — confirm to promote) — rs0n dup-proof, ranked\n'
    [[ -n "$XSS_CAND_LINE" ]]  && printf '**XSS** — %s · `xss_candidates_%s.md`\n%s\n'  "${XSS_CAND_LINE#\[xss\] }"  "$today" "$(printf '%s' "$XSS_TOP"  | sed 's/^/  /')"
    [[ -n "$SQLI_CAND_LINE" ]] && printf '\n**SQLi** — %s · `sqli_candidates_%s.md`\n%s\n' "${SQLI_CAND_LINE#\[sqli\] }" "$today" "$(printf '%s' "$SQLI_TOP" | sed 's/^/  /')"
    printf '_Confirm:_ `recon-params confirm xss <host>` _(dalfox, executes — reflection≠XSS)_ · `recon-params confirm sqli <host>` _(SAFE `'"'"'`vs`'"'"''"'"'` diff)._\n'
  fi

  # --- 🔑 AUTHED lane: BAC/IDOR (your 2 accounts; led on AUTHED nights) ---
  if [[ "${nidor:-0}" -gt 0 ]]; then
    printf '\n\n## 🔑 Authed lane — BAC/IDOR (your two accounts) — %s\n' "$nidor"
    printf '%s' "$show_idor" | jq -r --argjson noted "$NOTED" '
      def loc: if ((.endpoint//"")|startswith("http")) then .endpoint elif ((.endpoint//"")|startswith("/")) then (.host+.endpoint) elif ((.endpoint//"")=="") then .host else (.host+" · "+.endpoint) end;
      def rd: (.host|split(".")| if length>=2 then (.[-2]+"."+.[-1]) else .host end);
      def mark: . as $o | (if (($noted|index($o.host)) or ($noted|index($o|rd))) then "📝 " else "" end);
      .[] |
      "\n### " + mark + "[\(.impact|ascii_upcase) · conf \(.confidence)] \(.vuln_type) — `\(.host)`"
      + (if (.route_count // 1) > 1
           then "\n- **routes to test (\(.route_count)):** " + ((.routes // []) | map("`"+.+"`") | join(", "))
           else "\n- **endpoint:** `\(loc)`" end)
      + "\n- **why:** \(.why)\n- **test:** \(.test)\n- program: \(.program // "?")"' 2>/dev/null
  fi

  # --- 🟡 If time (medium dup-risk) ---
  if [[ "${nheld:-0}" -gt 0 ]]; then
    printf '\n\n## 🟡 If time (medium dup-risk) — %s\n' "$nheld"
    printf '%s' "$held" | jq -r 'def loc: if ((.endpoint//"")|startswith("http")) then .endpoint elif ((.endpoint//"")|startswith("/")) then (.host+.endpoint) elif ((.endpoint//"")=="") then .host else (.host+" · "+.endpoint) end;
      .[] | "- [\(.impact)] \(.vuln_type) `\(loc)` — \(.hold_reason // "")"' 2>/dev/null
  fi

  # --- 🔍 Needs a human eye ---
  if [[ "${nneed:-0}" -gt 0 ]]; then
    printf '\n\n## 🔍 Needs a human eye (Claude unsure) — %s\n' "$nneed"
    printf '%s' "$needh" | jq -r '.[] | "- **\(.vuln_class)** on `\(.host)` (conf \(.cf)) — \(.reason[0:140])"' 2>/dev/null
  fi

  # --- 🔕 Suppressed (logged, not worked — the narrow-hands discipline) ---
  nsupp_total=$(( ${nsupp:-0} + GATE_SUPP ))
  if [[ "$nsupp_total" -gt 0 ]]; then
    printf '\n\n## 🔕 Suppressed — %s lead(s)' "$nsupp_total"
    [[ -n "$supp_reasons" ]] && printf ': %s' "$supp_reasons"
    printf '\n'
    [[ "$GATE_SUPP" -gt 0 ]] && printf '_(+%s dropped at render by the FP-class rules + fp-signature/KB gate — adjudicated/known noise never re-queued)_\n' "$GATE_SUPP"
    printf '_(product-class duplicates and shared-tenant/third-party-data landmines — not worth your evening, kept here for audit)_\n'
  fi

  printf '\n\n_Deep-check any lead before you spend time on it:_ `recon-verify <host>` _(Claude + safe probes)._\n'
  printf '_SUBMIT = a confirm primitive fired. DIG = work it tonight. Authed/IDOR uses your own two accounts. Submission is always your call._\n'
} > "$md" 2>/dev/null

log "🌙 briefing compiled · 🎯 $nidor host-lead(s) ($nshow pre-collapse) · 🟡 $nheld hold · 🔕 $nsupp dup + $GATE_SUPP render-gated · ✅ $nsub to-submit · 🔍 $nneed needs-human · 🧪 $nvln vuln-leads → $md"

# --- deliver to Discord (#digest — the single nightly card) ---
# NOTIFICATION POLICY (2026-07-23): the nightly card is UI-FIRST — it lives in the
# recon-ui "Tonight" worklist (parsed from the durable .md written above). Discord
# is reserved for immediate-attention signals only, so #digest is off the allowlist
# by default and this resolves empty (the block is skipped). No fallback to #review —
# the big card must NEVER leak into the live-confirmed channel. Re-enable the ping
# with RECON_DISCORD_ALLOW="review takeovers ops digest".
rh="$(discord_hook digest 2>/dev/null || true)"
if [[ -n "$rh" ]]; then
  card="$(printf '🌙 **TONIGHT — %s%s**\n\n✅ **Ready to submit (%s):**\n' "$today" "$mode_banner" "$nsub")"
  card+="$(printf '%s' "$subs" | jq -r '.[] | "• \(.vuln_class) `\(.host)` (c\(.cf))"' 2>/dev/null | head -c 350)"
  [[ "${nnday:-0}" -gt 0 ]] && { card+="$(printf '\n\n⚡ **n-day CVE candidates (%s):**\n' "$nnday")"; card+="$(printf '%s' "$show_nday" | jq -r '.[] | "• **\(.impact)** `\(.host)` — \(.cve // .endpoint) (c\(.confidence))"' 2>/dev/null | head -c 400)"; }
  [[ "${nvln:-0}" -gt 0 ]] && { card+="$(printf '\n\n🧪 **Vuln leads (verify before trusting) (%s):**\n' "$nvln")"; card+="$(printf '%s' "$vleads" | jq -r '.[] | (if ._noise_action=="downgrade" then "LEAD·ver-unconf " else "" end) as $t | "• \($t)\(.cls) `\(.host)` — \(.check)"' 2>/dev/null | head -c 500)"; }
  [[ "${nbkt:-0}" -gt 0 ]] && { card+="$(printf '\n\n☁️ **Cloud-bucket leads (verify content / not by-design) (%s):**\n' "$nbkt")"; card+="$(printf '%s' "$bkts" | jq -r '.[] | "• [\(.severity)] \(.kind) `\(.bucket)` (\(.provider)) ← \(.host // .source_host)"' 2>/dev/null | head -c 500)"; }
  [[ "${ngql:-0}" -gt 0 ]] && { card+="$(printf '\n\n🔮 **GraphQL (introspection ON — 2-acct/injection test) (%s):**\n' "$ngql")"; card+="$(printf '%s' "$gql" | jq -r '.[] | "• `\(.host)` — \(.n_sensitive) sensitive op(s)"' 2>/dev/null | head -c 500)"; }
  [[ "${nwcd:-0}" -gt 0 ]] && { card+="$(printf '\n\n☁️ **Web-cache deception/poison LEADs (%s):**\n' "$nwcd")"; card+="$(printf '%s' "$wcd" | jq -r '.[] | "• [\(.severity)] \(.kind) `\(.host)`"' 2>/dev/null | head -c 400)"; }
  if [[ -n "$XSS_CAND_LINE$SQLI_CAND_LINE" ]]; then
    card+="$(printf '\n\n💉 **XSS/SQLi (unauth — confirm to promote):**')"
    [[ -n "$XSS_CAND_LINE" ]]  && card+="$(printf '\n• %s'  "${XSS_CAND_LINE#\[xss\] }")"
    [[ -n "$SQLI_CAND_LINE" ]] && card+="$(printf '\n• %s' "${SQLI_CAND_LINE#\[sqli\] }")"
    card+="$(printf '\n_see xss/sqli_candidates_%s.md · confirm: recon-params confirm xss|sqli <host>_' "$today")"
  fi
  if [[ "${nidor:-0}" -gt 0 ]]; then
    card+="$(printf '\n\n🔑 **Authed — BAC/IDOR (your 2 accounts) (%s):**\n' "$nidor")"
    card+="$(printf '%s' "$show_idor" | jq -r --argjson noted "$NOTED" '
      def rd: (.host|split(".")| if length>=2 then (.[-2]+"."+.[-1]) else .host end);
      def mark: . as $o | (if (($noted|index($o.host)) or ($noted|index($o|rd))) then "📝 " else "" end);
      .[] | "• " + mark + "**\(.impact)** \(.vuln_type) `\(.host)`" + (if (.route_count // 1) > 1 then " (\(.route_count) routes)" else "" end) + " (c\(.confidence))\n   test: \(.test)"' 2>/dev/null | head -c 1000)"
  fi
  [[ "${nneed:-0}" -gt 0 ]] && { card+="$(printf '\n\n🔍 **Needs a human eye (%s):**\n' "$nneed")"; card+="$(printf '%s' "$needh" | jq -r '.[] | "• \(.vuln_class) `\(.host)` (c\(.cf))"' 2>/dev/null | head -c 300)"; }
  [[ "$(( ${nsupp:-0} + GATE_SUPP ))" -gt 0 ]] && card+="$(printf '\n\n🔕 _%s lead(s) suppressed (%s noise-class/dup, %s adjudicated-FP at render)_' "$(( ${nsupp:-0} + GATE_SUPP ))" "${nsupp:-0}" "$GATE_SUPP")"
  discord_post "$rh" "$(jq -nc --arg c "${card:0:1950}" '{content:$c}')" >/dev/null 2>&1 \
    && log "🌙 briefing posted to #digest" || log "discord post failed (card saved to $md)"
fi
touch "$sent"

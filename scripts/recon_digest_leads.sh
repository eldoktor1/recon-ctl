#!/usr/bin/env bash
# =============================================================================
# recon_digest_leads.sh — curated high-signal lead digest -> Discord #leads
#
# The "second enforcer" against pipeline + ollama noise. Reads ES (read-only),
# ranks ONLY genuinely vuln-worthy leads, scrutinizes the ollama AI verdict
# instead of trusting it, dedups against everything already worked on, and
# emits three tiers: PROMOTE / HOLD / SUPPRESS (every suppression has a reason).
#
# This is the DETERMINISTIC fallback. The richer judgment (version-aware
# over-rating, hallucinated-safe-check detection) is done by the headless
# Claude run that normally drives the digest; this script guarantees a digest
# still lands before 6:30 PM if a Claude run ever fails.
#
# MODES:
#   print  (default) — render to stdout, NO side effects (safe preview)
#   post             — post embed to #leads AND append surfaced leads to ledger
#
# CHANNEL: leads  (reads ~/.recon_discord_leads)
# Not target-facing: only ES reads + Discord POST + a local state-file append.
# Runs as d0k. No killswitch needed.
#
# Doctrine: memory feedback_enforcer_doctrine ; scrutiny rules: project_daily_lead_digest
# =============================================================================
set -uo pipefail
IFS=$'\n\t'

log() { printf '[%s LEADS] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/recon_net.sh"
setup_es_netrc
ES_AUTH=(--netrc-file "$HOME/.recon_es_netrc")

BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"
INDEX_NAME="${INDEX_NAME:-recon_alive}"
LEDGER="${LEDGER:-$STATE_DIR/worked_targets.jsonl}"
IGNORED="${IGNORED:-$STATE_DIR/ignored.jsonl}"
MAXN="${LEADS_MAX:-25}"

MODE="${1:-print}"
NOTE_FILE="${2:-}"          # optional: file whose contents become a 2nd "Claude enforcer" embed
NOW="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
DATE_LABEL="$(date -u '+%a %d %b %Y, %H:%M UTC')"

mkdir -p "$STATE_DIR"
touch "$LEDGER" "$IGNORED" 2>/dev/null || true

ec() { curl -sS -m 30 "${ES_AUTH[@]}" -H 'Content-Type: application/json' "$@"; }

# ── 1) Fetch candidates: any high-value signal, gated to paying scope ────────
read -r -d '' QBODY <<JSON || true
{
  "size": 600,
  "track_total_hits": true,
  "query": {
    "bool": {
      "filter": [ {"term": {"triage_pays": true}} ],
      "must_not": [ {"term": {"triage_ignored": true}} ],
      "minimum_should_match": 1,
      "should": [
        {"term":  {"triage_kev_match": true}},
        {"term":  {"triage_breaking_vuln": true}},
        {"term":  {"js_secret_hit": true}},
        {"range": {"bypass_top_confidence": {"gte": 60}}},
        {"term":  {"v2_nuclei_status": "confirmed"}},
        {"term":  {"portscan_critical": 1}},
        {"term":  {"takeover_confirmed": true}}
      ]
    }
  },
  "sort": [ {"triage_score": {"order": "desc"}} ],
  "_source": ["host","url","status_code","title","tech","ip","cname","cdn_name",
    "triage_score","triage_priority","triage_program","triage_payout_tier",
    "triage_kev_match","triage_kev_signal","triage_kev_cves","triage_kev_needs_verify",
    "triage_breaking_vuln","triage_vuln_tier","triage_true_fresh","js_secret_hit",
    "bypass_top_confidence","bypass_technique","bypass_paths",
    "v2_nuclei_status","v2_nuclei_template","v2_nuclei_severity",
    "portscan_critical","portscan_open_ports","takeover_confirmed",
    "ai_relevance_score","ai_recommendation","ai_confidence","ai_reason",
    "ai_safe_checks","ai_risk_flags","ai_reviewed_at",
    "triage_at","last_seen","first_seen"]
}
JSON

resp="$(ec -X POST "$ES_URL/$INDEX_NAME/_search" -d "$QBODY" 2>/dev/null || true)"
if ! printf '%s' "$resp" | jq -e '.hits' >/dev/null 2>&1; then
  log "ES query failed or returned no hits envelope — aborting"
  exit 1
fi
# Stream candidates to a temp file (JSONL) and slurp them in jq — passing a
# 600-doc array via --argjson overflows ARG_MAX.
CANDFILE="$(mktemp)"
trap 'rm -f "$CANDFILE"' EXIT
printf '%s' "$resp" | jq -c '.hits.hits[]._source' > "$CANDFILE"

# ── 2) Classify (hard signal), scrutinize ollama, tier, fingerprint, dedup ──
# Enforcer doctrine: dismissal needs a checkable reason; doubt -> HOLD (never
# SUPPRESS); module-confirmed signals are floor-protected (>= HOLD always).
selected="$(jq -n \
  --slurpfile cand "$CANDFILE" \
  --slurpfile led "$LEDGER" \
  --slurpfile ign "$IGNORED" \
  --arg now "$NOW" \
  --argjson maxn "$MAXN" '
  # ledger: last fingerprint per host ; ignored: dismissed host set
  (reduce ($led // [])[] as $e ({}; . + {($e.host): ($e.fp // "")})) as $seen |
  (reduce ($ign // [])[] as $e ({}; . + {($e.host): true}))        as $ignset |

  def is_wp:
    ((.tech // []) | map(ascii_downcase)
     | any(test("wordpress|woocommerce|elementor|wp engine|wp rocket")));

  # server-software KEV split: real RCE-class (verify-now, PROMOTE) vs the
  # generic Drupalgeddon list (version-dependent, floods hosts -> HOLD).
  # kev-rce = exposed appliance/app where KEV is likely exploitable -> PROMOTE
  # kev-cms = CMS tech-map (Drupal/AEM), version+surface unconfirmed, floods -> HOLD
  def srvkev:
    ((.triage_kev_signal // "") | ascii_downcase) as $s
    | if   ($s|test("confluence|moveit|spring|magento|gitlab|weblogic|jenkins|exchange|citrix|fortinet|ivanti|jira")) then {w:84, kind:"kev-rce"}
      elif ($s|test("drupal|aem")) then {w:70, kind:"kev-cms"}
      else {w:0, kind:""} end;

  def hard:
    . as $h | (.triage_kev_cves // []) as $cves
    | if   (.takeover_confirmed // false) then {cls:"takeover", w:100, floor:true,  what:"Confirmed subdomain takeover — claim now"}
      elif ((.v2_nuclei_status // "") == "confirmed") then {cls:"nuclei", w:96, floor:true,  what:("Nuclei-confirmed: " + (.v2_nuclei_template // "?") + " [" + (.v2_nuclei_severity // "?") + "]")}
      elif (((.portscan_critical // 0)|tonumber) == 1) then {cls:"portcrit", w:90, floor:true,  what:("Exposed critical port(s): " + ((.portscan_open_ports // [])|map(tostring)|join(",")))}
      elif (((.bypass_top_confidence // 0)|tonumber) >= 60) then {cls:"bypass", w:88, floor:true,  what:("Auth bypass conf " + ((.bypass_top_confidence)|tostring) + " via " + (.bypass_technique // "?"))}
      elif ((.triage_kev_match // false) and (srvkev.w > 0)) then (srvkev as $k | {cls:$k.kind, w:$k.w, floor:false, what:("KEV " + (.triage_kev_signal // "") + ": " + ($cves|join(", ")))})
      elif ((.triage_breaking_vuln // false) and (($cves|length)>0) and (is_wp|not)) then {cls:"breaking", w:66, floor:false, what:("Breaking vuln " + (.triage_vuln_tier // "") + ": " + ($cves|join(", ")))}
      elif (.js_secret_hit // false) then {cls:"js", w:55, floor:false, what:"JS secret regex hit (verify it is live/sensitive)"}
      elif ((.triage_kev_match // false) and is_wp) then {cls:"kev-wp", w:8, floor:false, what:("Generic WordPress KEV map: " + ($cves|join(", ")))}
      else {cls:"low", w:0, floor:false, what:"below threshold / insufficient signal"} end;

  # canonical per-class verification step — replaces ollama hallucinated safe_checks
  def canon($cls):
    ((.triage_kev_signal // "") | ascii_downcase) as $s
    | if   $cls=="bypass" then ("replay bypass [" + (.bypass_technique // "?") + "] on the gated path; confirm 200 + sensitive body")
      elif $cls=="kev-rce" then
        ( if   ($s|test("confluence")) then "GET /wiki/ ; read version (footer / X-Confluence-*); test CVE-2023-22527 OGNL"
          elif ($s|test("spring"))     then "GET /actuator/env and /actuator/heapdump (creds/token leak -> RCE)"
          elif ($s|test("moveit"))     then "GET /human.aspx ; read MOVEit version banner"
          elif ($s|test("magento"))    then "GET /magento_version ; CosmicSting CVE-2024-34102 surface"
          elif ($s|test("jira"))       then "GET /secure/Dashboard.jspa ; read version in footer"
          elif ($s|test("gitlab"))     then "GET /help ; read GitLab version"
          else "fingerprint the exact version and map it to the CVE" end )
      elif $cls=="kev-cms" then
        ( if ($s|test("aem")) then "GET /system/console , /crx/de , /etc.json ; confirm AEM author/console is actually exposed (most are CDN/dispatcher-fronted = N/A)"
          else "GET /CHANGELOG.txt or /core/CHANGELOG.txt for exact version; Drupalgeddon2 only if <7.58 / <8.5.1, otherwise check CVE-2026-9082" end )
      elif $cls=="breaking"   then "confirm the component version actually matches the CVE before testing"
      elif $cls=="js"         then "open the flagged JS asset; grep for live keys; validate the secret works"
      elif $cls=="nuclei"     then "reproduce the nuclei finding by hand; confirm real impact"
      elif $cls=="portcrit"   then "connect to the exposed service; check auth / default creds"
      elif $cls=="takeover"   then "confirm the dangling target is unclaimed; register to claim"
      else "" end;

  # ollama scrutiny — input, not verdict
  def scrut:
    (.ai_reviewed_at // null) as $rev |
    (.triage_at // .last_seen // null) as $tat |
    if   ($rev == null) then {state:"missing", txt:"ollama never reviewed"}
    elif (($tat != null) and ($rev < $tat)) then {state:"stale", txt:("ollama verdict " + ($rev|split("T")[0]) + " predates current signal")}
    else {state:"present",
          score:(.ai_relevance_score // null),
          rec:(.ai_recommendation // null),
          txt:((.ai_reason // "") | .[0:180])} end;

  ([ $cand[]
    | . as $h
    | (hard)  as $H
    | (scrut) as $S
    | (.triage_kev_cves // []) as $cves
    | ($H.cls + "|" + ((.triage_score // 0)|tostring) + "|" + ($cves|sort|join(",")) + "|" + (.v2_nuclei_status // "") + "|" + ((.bypass_top_confidence // 0)|tostring)) as $fp
    | ($seen[.host] // null) as $prev
    # enforcer tiers:
    | (if   $H.floor then (if $H.w >= 88 then "PROMOTE" else "HOLD" end)
       elif ($H.cls=="kev-rce") then "PROMOTE"
       elif ($H.cls=="kev-cms" or $H.cls=="breaking" or $H.cls=="js") then "HOLD"
       elif ($H.cls=="kev-wp") then "SUPPRESS"
       else "SUPPRESS" end) as $tier
    | (if   $H.cls=="kev-wp" then "managed/CDN WordPress; core KEV map not version-confirmed, high FP"
       elif $H.cls=="low" then "below promotion threshold; no confirmed or server-software signal"
       else "" end) as $supreason
    | {
        host: .host,
        cls: $H.cls, w: $H.w, floor: $H.floor, what: $H.what,
        score: (.triage_score // 0),
        prog: (.triage_program // "?"),
        ptier: (.triage_payout_tier // "none"),
        fresh: (.triage_true_fresh // false),
        cves: $cves,
        sig: ((.triage_kev_signal // "") | gsub("tech:"; "")),
        tech: (.tech // []),
        title: ((.title // "") | .[0:140]),
        status: (.status_code // 0),
        url: (.url // .host),
        ai: $S,
        check: (canon($H.cls)),
        tier: $tier,
        supreason: $supreason,
        fp: $fp,
        in_ledger: ($prev != null),
        changed: (($prev != null) and ($prev != $fp)),
        dup: (($prev != null) and ($prev == $fp)),
        ignored: ($ignset[.host] // false)
      }
   ]
   # drop operator-dismissed hosts entirely
   | map(select(.ignored | not))
  ) as $all |

  # Dedup policy: HOLD/SUPPRESS dedup on same-fingerprint repeats (do not re-nag
  # verify-tasks daily). PROMOTE is dedup-EXEMPT — a confirmed/RCE-class lead keeps
  # surfacing every day until the operator actions it (adds it to ignored.jsonl,
  # claims, or submits). ignored.jsonl is the "worked, drop it" list.
  ($all | map(select(.dup | not))) as $live |

  {
    promote: ($all  | map(select(.tier=="PROMOTE")) | sort_by(-(.w*1000 + .score)) | .[0:$maxn]),
    hold:    ($live | map(select(.tier=="HOLD"))    | sort_by(-(.w*1000 + .score)) | .[0:$maxn]),
    suppress_sample: ($live | map(select(.tier=="SUPPRESS")) | sort_by(-.score) | .[0:12]),
    counts: {
      total_candidates: ($all | length),
      promote:  ($all  | map(select(.tier=="PROMOTE")) | length),
      hold:     ($live | map(select(.tier=="HOLD"))    | length),
      suppress: ($live | map(select(.tier=="SUPPRESS"))| length),
      deduped:  ($all  | map(select(.dup and (.tier!="PROMOTE"))) | length),
      changed:  ($all  | map(select(.changed))         | length)
    }
  }
')"

# ── 3) Renderers ────────────────────────────────────────────────────────────
emoji_for() { case "$1" in
  takeover) printf '🏴';; nuclei) printf '✅';; portcrit) printf '🚨';;
  bypass) printf '💥';; kev-srv) printf '🔴';; breaking) printf '🟠';;
  js) printf '🟡';; *) printf '•';; esac; }

render_text() {
  printf '%s\n' "$selected" | jq -r --arg dl "$DATE_LABEL" '
    def line:
      (.host) as $h |
      "  - [" + (.cls) + " w" + (.w|tostring) + "/s" + (.score|tostring) + "] " + $h
      + "  (" + (.prog) + "/" + (.ptier) + (if .fresh then ", fresh" else "" end) + ")"
      + (if .changed then "  *** NEW SIGNAL ***" else "" end)
      + "\n      " + (.what)
      + "\n      ollama: " + (.ai.state)
        + (if .ai.state=="present" then " score=" + ((.ai.score // "?")|tostring) + " rec=" + ((.ai.rec // "?")|tostring) else "" end)
      + (if (.check|length)>0 then "\n      check: " + (.check) else "" end);
    "===== CURATED LEADS — " + $dl + " =====",
    ("counts: " + (.counts.promote|tostring) + " promote / " + (.counts.hold|tostring) + " hold / "
      + (.counts.suppress|tostring) + " suppressed / " + (.counts.deduped|tostring) + " deduped"
      + "  (from " + (.counts.total_candidates|tostring) + " candidates, " + (.counts.changed|tostring) + " new-signal)"),
    "",
    "## PROMOTE — worth your time today",
    (if (.promote|length)==0 then "  (none)" else (.promote[] | line) end),
    "",
    "## HOLD — real signal, one cheap check resolves it",
    (if (.hold|length)==0 then "  (none)" else (.hold[] | line) end),
    "",
    "## SUPPRESSED (sample, with reason — audit me)",
    (if (.suppress_sample|length)==0 then "  (none)" else (.suppress_sample[] | "  - " + .host + " — " + .supreason) end)
  '
}

build_discord_payload() {
  printf '%s\n' "$selected" | jq -c --arg dl "$DATE_LABEL" --arg ts "$NOW" '
    def em:
      {takeover:"🏴",nuclei:"✅",portcrit:"🚨",bypass:"💥","kev-rce":"🔴","kev-cms":"🟠",breaking:"🟠","kev-wp":"⚪",js:"🟡"}[.cls] // "🔵";
    def lab:
      if   .cls=="bypass"   then "Auth bypass"
      elif .cls=="nuclei"   then "Nuclei-confirmed"
      elif .cls=="portcrit" then "Critical port"
      elif .cls=="takeover" then "Takeover"
      elif .cls=="js"       then "JS secret"
      elif .cls=="breaking" then "Breaking vuln"
      elif (.cls|startswith("kev")) then ((if (.sig|length)>0 then .sig else "tech" end) + " KEV")
      else .cls end;
    def cve1:
      if (.cves|length)==0 then ""
      else ("`" + .cves[0] + "`" + (if (.cves|length)>1 then " +" + (((.cves|length)-1)|tostring) else "" end)) end;
    def chk: ((.check // "") | split(";")[0] | .[0:88]);
    def meta: "`" + .prog + "/" + .ptier + "` · s" + (.score|tostring)
              + (if .fresh then " · fresh" else "" end) + (if .changed then " 🆕" else "" end);
    # PROMOTE: 2 lines (headline + cve/check). HOLD: 1 compact line.
    def pline: em + " **" + .host + "** · " + lab + " · " + meta
               + "\n└ " + (if (cve1|length)>0 then cve1 + " — " else "" end) + chk;
    def hline: em + " **" + .host + "** · " + lab + " · " + meta
               + (if (chk|length)>0 then " — " + chk else "" end);

    (.counts) as $c
    | ([ ("**PROMOTE — " + ($c.promote|tostring) + "** · worth your time today"),
         (if (.promote|length)==0 then "_none today_" else (.promote | map(pline) | join("\n")) end),
         "",
         ("**HOLD — top " + ((if (.hold|length)<12 then (.hold|length) else 12 end)|tostring)
            + " of " + ($c.hold|tostring) + "** · verify, do not skip · full list: `recon-leads`"),
         (if (.hold|length)==0 then "_none_" else (.hold[0:12] | map(hline) | join("\n")) end)
       ] | join("\n")) as $desc0
    | ($desc0 | if (length>3900) then ((.[0:3900] | sub("\n[^\n]*$";"")) + "\n…") else . end) as $desc
    | {
        username: "recon enforcer",
        embeds: [{
          title: ("🎯 Curated Leads — " + $dl),
          description: $desc,
          color: 15158332,
          fields: [
            {name:"Promote", value:("**" + ($c.promote|tostring) + "**"), inline:true},
            {name:"Hold",    value:($c.hold|tostring),    inline:true},
            {name:"Suppressed", value:($c.suppress|tostring), inline:true},
            {name:"Deduped",  value:($c.deduped|tostring), inline:true},
            {name:"Re-surfaced (new signal)", value:($c.changed|tostring), inline:true},
            {name:"Candidates", value:($c.total_candidates|tostring), inline:true}
          ],
          footer:{text:"second enforcer · suppression always has a reason · 🔴=RCE 🟠=verify-version 💥=confirmed bypass 🟡=JS secret"},
          timestamp:$ts
        }]
      }'
}

append_ledger() {
  # surfaced = promote + hold ; record fp so same-signal repeats dedup next run
  printf '%s\n' "$selected" | jq -c --arg now "$NOW" '
    (.promote + .hold)[] | {host, surfaced_at:$now, category:.cls, tier:.tier,
                            reason:.what, score, fp, source:"daily-leads"}' >> "$LEDGER"
}

# ── 4) Act per mode ─────────────────────────────────────────────────────────
case "$MODE" in
  print|--print|dry|--dry-run)
    render_text
    ;;
  emit)
    # machine-readable selection (promote/hold/suppress_sample/counts) for the
    # headless-Claude verification layer. No side effects.
    printf '%s\n' "$selected"
    ;;
  post|--post)
    hook="$(discord_hook digest)"
    if [[ -z "$hook" ]]; then
      log "No #leads webhook (~/.recon_discord_leads) — printing instead, NOT writing ledger"
      render_text
      exit 0
    fi
    payload="$(build_discord_payload)"
    # optional: attach Claude verification as a second embed
    if [[ -n "$NOTE_FILE" && -s "$NOTE_FILE" ]]; then
      payload="$(printf '%s' "$payload" | jq -c --rawfile n "$NOTE_FILE" --arg ts "$NOW" \
        '.embeds += [{title:"🧠 Claude enforcer — verification & scrutiny",
                      description:($n[0:4000]), color:5793266, timestamp:$ts}]')"
    fi
    idfile="$STATE_DIR/leads_last_msg"
    prev=""; [[ -f "$idfile" ]] && prev="$(cat "$idfile" 2>/dev/null)"
    # POST FIRST (with ?wait=true so Discord returns the message id). Only delete
    # the previous message AFTER the new one is confirmed posted — otherwise a
    # failed post would leave the channel empty.
    resp="$(curl -sS -m 25 -H 'Content-Type: application/json' -X POST "${hook}?wait=true" -d "$payload" 2>/dev/null)"
    newid="$(printf '%s' "$resp" | jq -r '.id // empty' 2>/dev/null)"
    if [[ -n "$newid" ]]; then
      printf '%s' "$newid" > "$idfile"
      [[ -n "$prev" && "$prev" != "$newid" ]] && curl -sS -m 15 -X DELETE "$hook/messages/$prev" >/dev/null 2>&1 || true
      append_ledger
      log "Posted curated leads to #leads (msg $newid) + appended ledger ($(printf '%s' "$selected" | jq -c '.counts'))"
    else
      log "Discord post failed (prior message kept): $(printf '%s' "$resp" | head -c 200)"
      exit 1
    fi
    ;;
  *)
    echo "usage: recon_digest_leads.sh [print|post]" >&2
    exit 2
    ;;
esac

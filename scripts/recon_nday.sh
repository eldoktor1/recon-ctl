#!/usr/bin/env bash
# =============================================================================
# recon_nday.sh — n-day RACING pillar: be first on fresh CVEs, without the KEV false-positive.
#
# The pipeline already matches KEV/breaking CVEs to assets by tech class (triage_kev_*).
# But a tech-class match is a LEAD, not a bug (our own doctrine: "KEV match without a
# confirmed in-range version = FP"). The unique edge is Claude doing the VERSION reasoning
# the crowd skips: given the detected tech/version, is the host LIKELY in the vulnerable
# range? Is a public exploit out? What is the single safest way to verify, right now, in the
# race window before everyone's templates catch up? Reasoning only -> high-value candidates
# land on the worklist for the briefing; the human/gate verifies. Runs as d0k (Claude auth).
# =============================================================================
set -uo pipefail
IFS=$'\n\t'
log()  { printf '[%s NDAY] %s\n'      "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s NDAY WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/recon_net.sh" 2>/dev/null || true
BASE_DIR="${BASE_DIR:-$HOME/recon}"; STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"; INDEX_NAME="${INDEX_NAME:-recon_alive}"
NETRC="${NETRC:-$HOME/.recon_es_netrc}"
WORKLIST="${IDOR_WORKLIST:-$BASE_DIR/idor_worklist.jsonl}"   # shared worklist -> briefing
SEEN="${NDAY_SEEN:-$STATE_DIR/nday_seen.txt}"
CLAUDE_BIN="${CLAUDE_BIN:-$HOME/.local/bin/claude}"; [[ -x "$CLAUDE_BIN" ]] || CLAUDE_BIN="$(command -v claude 2>/dev/null || echo '')"
CLAUDE_MODEL="${CLAUDE_NDAY_MODEL:-sonnet}"
CLAUDE_TIMEOUT="${CLAUDE_TIMEOUT:-150}"
NDAY_HOSTS="${NDAY_HOSTS:-12}"
SAFE_PROBE="${SAFE_PROBE:-$SCRIPT_DIR/recon_safe_probe.sh}"
NDAY_AUTOCONFIRM="${NDAY_AUTOCONFIRM:-1}"   # 1 = run Claude's safe verify_probe via the harness → auto-confirm
V3_DB="${V3_DB:-$BASE_DIR/v3/findings.db}"
# second-pass schema: given the real probe response, is the CVE actually confirmed?
CONFIRM_SCHEMA='{"type":"object","additionalProperties":false,"properties":{"confirmed":{"type":"boolean"},"reason":{"type":"string"},"confidence":{"type":"number","minimum":0,"maximum":1}},"required":["confirmed","reason","confidence"]}'
score_for() { case "$1" in critical) echo 90;; high) echo 75;; medium) echo 55;; *) echo 40;; esac; }
es() { curl -fsS -m 25 --netrc-file "$NETRC" -H 'Content-Type: application/json' "$@"; }

mkdir -p "$STATE_DIR" "$(dirname "$WORKLIST")"; touch "$SEEN"
exec 9>"$STATE_DIR/nday.lock"; flock -n 9 || { warn "already running"; exit 0; }
[[ -n "$CLAUDE_BIN" && -x "$CLAUDE_BIN" ]] || { warn "claude CLI not found — skipping"; exit 0; }
command -v jq >/dev/null 2>&1 || { warn "jq missing"; exit 0; }

SCHEMA='{"type":"object","additionalProperties":false,"properties":{"likely_vulnerable":{"type":"boolean"},"cve":{"type":"string"},"reason":{"type":"string"},"exploit_available":{"type":"boolean"},"verify_method":{"type":"string"},"verify_probe":{"type":"object","additionalProperties":false,"properties":{"path":{"type":"string"},"method":{"type":"string","enum":["GET","HEAD","OPTIONS"]},"confirm_signal":{"type":"string"}},"required":["path","method","confirm_signal"]},"impact":{"type":"string","enum":["critical","high","medium","low"]},"confidence":{"type":"number","minimum":0,"maximum":1}},"required":["likely_vulnerable","reason","verify_method","impact","confidence"]}'

# in-scope+paying assets with a KEV/breaking-vuln match, freshest first, not yet assessed
q="$(jq -nc --argjson n "$NDAY_HOSTS" '{size:($n*4),
  _source:["host","tech","webserver","status_code","title","triage_kev_cves","triage_program","triage_breaking_vuln"],
  query:{bool:{filter:[{term:{triage_in_scope:true}},{term:{triage_pays:true}},{bool:{must_not:{term:{triage_scan_deny:true}}}}],
               should:[{term:{triage_kev_match:true}},{exists:{field:"triage_kev_cves"}},{term:{triage_breaking_vuln:true}}],
               minimum_should_match:1, must_not:[{term:{triage_out_of_scope:true}}]}},
  sort:[{triage_true_fresh:{order:"desc",missing:"_last"}},{triage_score:{order:"desc",missing:"_last"}}]}')"
resp="$(es "$ES_URL/$INDEX_NAME/_search" -d "$q" 2>/dev/null)"
mapfile -t rows < <(printf '%s' "$resp" | jq -c '.hits.hits[]._source' 2>/dev/null \
  | while IFS= read -r r; do h="$(printf '%s' "$r" | jq -r '.host // empty')"; grep -qxF "$h" "$SEEN" 2>/dev/null || printf '%s\n' "$r"; done | head -n "$NDAY_HOSTS")
# AUDIT #8: race the EPSS / nuclei-template-available subset FIRST. recon_vuln_feed.sh already
# joins EPSS + nuclei-template + KEV into a per-asset best_vuln_tier (T0/T1 = highest risk), but
# nday only sorted by fresh+score and ignored it. Pull T0/T1 in-scope+paying hosts from
# vuln_targets.jsonl and PREPEND them (one per host) so the highest-EV CVEs are version-reasoned
# first. Purely additive: missing/empty feed => unchanged ES behaviour.
VULN_TARGETS="${VULN_TARGETS:-$BASE_DIR/vuln/vuln_targets.jsonl}"
NDAY_FEED="${NDAY_FEED:-8}"
feed_rows=()
if [[ -f "$VULN_TARGETS" ]]; then
  declare -A _fhseen
  while IFS= read -r fr; do
    [[ -z "$fr" ]] && continue
    fh="$(printf '%s' "$fr" | jq -r '.host // empty' 2>/dev/null)"; [[ -z "$fh" ]] && continue
    [[ -n "${_fhseen[$fh]:-}" ]] && continue                 # one entry per host
    grep -qxF "$fh" "$SEEN" 2>/dev/null && continue           # not already assessed
    _fhseen[$fh]=1; feed_rows+=("$fr")
    [[ "${#feed_rows[@]}" -ge "$NDAY_FEED" ]] && break
  done < <(jq -c 'select(.triage_in_scope==true and .triage_pays==true and (.triage_out_of_scope!=true)
                    and ((.best_vuln_tier // "")|test("^T[01]$")) and (.best_vuln_id != null))
                  | {host, tech:(.tech//[]), triage_kev_cves:[.best_vuln_id], triage_program:"",
                     webserver:"", status_code:(.status_code//0), title:(.title//""),
                     triage_breaking_vuln:false, nday_tier:.best_vuln_tier}' "$VULN_TARGETS" 2>/dev/null)
fi
if [[ "${#feed_rows[@]}" -gt 0 ]]; then
  declare -A _seenhost; merged=()
  for r in "${feed_rows[@]}" "${rows[@]}"; do
    h="$(printf '%s' "$r" | jq -r '.host // empty' 2>/dev/null)"; [[ -z "$h" ]] && continue
    [[ -n "${_seenhost[$h]:-}" ]] && continue; _seenhost[$h]=1; merged+=("$r")
  done
  rows=("${merged[@]:0:$NDAY_HOSTS}")
  log "🏁 n-day feed: ${#feed_rows[@]} T0/T1 (EPSS/template) host(s) prepended → race first"
fi
[[ "${#rows[@]}" -gt 0 ]] || { log "no fresh KEV/CVE-matched assets to assess"; exit 0; }
log "🏁 ─── N-DAY RACE ─── ${#rows[@]} CVE-matched asset(s) · Claude version-reasoning (kill the KEV FP) ───"

leads=0
for r in "${rows[@]}"; do
  host="$(printf '%s' "$r" | jq -r '.host // empty')"; [[ -z "$host" ]] && continue
  printf '%s\n' "$host" >> "$SEEN"
  prog="$(printf '%s' "$r" | jq -r '.triage_program // ""')"
  cves="$(printf '%s' "$r" | jq -r '(.triage_kev_cves // []) | if type=="array" then join(",") else tostring end' 2>/dev/null)"
  tech="$(printf '%s' "$r" | jq -r '(.tech // []) | join(", ")' 2>/dev/null)"
  prompt="$(cat <<EOF
An in-scope host matched a known-exploited / breaking CVE BY TECH CLASS. A tech-class match
is NOT a bug — most are false positives because the running version isn't actually in the
vulnerable range. Do the reasoning the crowd skips.

HOST: $host
PROGRAM: ${prog:-?}
DETECTED TECH/VERSIONS: ${tech:-unknown}
WEBSERVER: $(printf '%s' "$r" | jq -r '.webserver // "?"')
TITLE: $(printf '%s' "$r" | jq -r '(.title // "")[0:90]')
MATCHED CVE(s): ${cves:-unknown}

Judge: is this host LIKELY actually vulnerable (running version plausibly in range for the
CVE), or is it just a same-product tech-class match (FP)? Is a public exploit/PoC available?
Rate impact + confidence. Set likely_vulnerable=false if the evidence is only a product-name
match with no version signal.

DESIGN THE SAFE CHECK (verify_probe): give the single best UNAUTHENTICATED, NON-DESTRUCTIVE
request that would CONFIRM the version is in range — a path that returns a version
banner/string, a fingerprintable endpoint, an OPTIONS/HEAD that reveals the build. It MUST be
GET/HEAD/OPTIONS only, no creds, no exploitation — recon, not attack. Provide:
  path           — the request path (e.g. "/magento_version", "/wp-includes/version.php"); "/" if just headers
  method         — GET | HEAD | OPTIONS
  confirm_signal — exactly what in the response confirms the in-range version (a regex/string/header)
If no safe unauthenticated request can confirm the version, omit verify_probe entirely.
EOF
)"
  out="$(timeout "$CLAUDE_TIMEOUT" "$CLAUDE_BIN" -p "$prompt" --model "$CLAUDE_MODEL" --tools "" \
         --no-session-persistence --json-schema "$SCHEMA" --output-format json </dev/null 2>/dev/null)"
  so="$(printf '%s' "$out" | jq -c '.structured_output // empty' 2>/dev/null)"
  [[ -z "$so" || "$so" == "null" ]] && continue
  lv="$(printf '%s' "$so" | jq -r '.likely_vulnerable // false')"
  conf="$(printf '%s' "$so" | jq -r '.confidence // 0')"
  if [[ "$lv" != "true" ]] || ! awk "BEGIN{exit !(${conf:-0}>=0.5)}"; then
    log "   · $host — KEV FP (tech-class only, not in-range)"
    continue
  fi
  ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  cve_id="$(printf '%s' "$so" | jq -r '.cve // empty')"; [[ -z "$cve_id" ]] && cve_id="$cves"
  impact="$(printf '%s' "$so" | jq -r '.impact')"

  # ---- AUTO-CONFIRM LOOP: run Claude's safe verify_probe via the TRUSTED harness, then
  # re-judge the real response. A confirm -> a CONFIRMED finding in the DB (-> ai-review ->
  # real -> briefing "ready to submit"), racing the window. No confirm -> a worklist LEAD.
  # The model NEVER executes: recon_safe_probe is GET/HEAD/OPTIONS, unauth, no creds, no
  # redirect-follow, SSRF/metadata-guarded, scope+pays-gated, rate-limited, Mullvad-only. ----
  confirmed=0
  vp="$(printf '%s' "$so" | jq -c '.verify_probe // empty' 2>/dev/null)"
  if [[ "$NDAY_AUTOCONFIRM" == "1" && -n "$vp" && "$vp" != "null" && -f "$SAFE_PROBE" ]]; then
    ppath="$(printf '%s' "$vp" | jq -r '.path // empty')"
    pmethod="$(printf '%s' "$vp" | jq -r '.method // "GET"')"
    psignal="$(printf '%s' "$vp" | jq -r '.confirm_signal // empty')"
    [[ "$ppath" != /* ]] && ppath="/$ppath"
    purl="https://${host}${ppath}"
    log "   🔎 $host — safe verify_probe: $pmethod $purl  (signal: ${psignal:0:60})"
    pres="$(bash "$SAFE_PROBE" "$purl" "$pmethod" 2>/dev/null)"
    if [[ -n "$pres" ]]; then
      cprompt="$(cat <<CEOF
You designed a safe probe to confirm $cve_id on $host. The TRUSTED harness ran it and returned
the REAL response below. Decide STRICTLY from this response whether the in-range vulnerable
version is CONFIRMED — do not assume. confirm_signal you expected: ${psignal}
PROBE: $pmethod $purl
RESPONSE (status/headers/body, size-capped): $pres
Set confirmed=true ONLY if the response actually shows the in-range/vulnerable version or the
definitive fingerprint. A generic 200/404, a login page, a WAF block, or no version signal =
confirmed=false (still a lead, not a confirmed finding).
CEOF
)"
      cout="$(timeout "$CLAUDE_TIMEOUT" "$CLAUDE_BIN" -p "$cprompt" --model "$CLAUDE_MODEL" --tools "" \
              --no-session-persistence --json-schema "$CONFIRM_SCHEMA" --output-format json </dev/null 2>/dev/null)"
      cso="$(printf '%s' "$cout" | jq -c '.structured_output // empty' 2>/dev/null)"
      if [[ -n "$cso" && "$cso" != "null" && "$(printf '%s' "$cso" | jq -r '.confirmed // false')" == "true" ]]; then
        confirmed=1
        cc="$(printf '%s' "$cso" | jq -r '.confidence // 0.6')"
        creason="$(printf '%s' "$cso" | jq -r '.reason')"
        ev="$(jq -nc --arg cve "$cve_id" --arg sig "$psignal" --arg u "$purl" --arg m "$pmethod" \
              --argjson resp "${pres:-{}}" --arg r "$creason" \
              '{probe:"nday-safe-verify",cve:$cve,confirm_signal:$sig,url:$u,method:$m,response:$resp,judge:$r}' 2>/dev/null)"
        STATE_PY="$SCRIPT_DIR/../engine/state.py" V3_DB="$V3_DB" \
          db_confirm "$host" "$purl" "$prog" "n-day" "cve-$cve_id" "$(score_for "$impact")" "$cc" "$ev" 2>/dev/null || true
        leads=$((leads+1))
        log "   💥 N-DAY CONFIRMED · $host · $cve_id · $impact/$cc → findings DB (→ ai-review → briefing)"
      fi
    fi
  fi

  if [[ "$confirmed" -eq 0 ]]; then
    # not auto-confirmed (no safe probe, or probe didn't prove it) -> worklist LEAD for the human
    printf '%s' "$so" | jq -c --arg h "$host" --arg p "$prog" --arg c "$cves" --arg t "$ts" \
      '{host:$h,program:$p,endpoint:"",cve:(.cve // $c),vuln_type:"n-day-cve",
        why:.reason,test:.verify_method,impact:.impact,confidence:.confidence,
        exploit_available:(.exploit_available//false),at:$t,status:"to-test"}' >> "$WORKLIST" 2>/dev/null
    leads=$((leads+1))
    log "   🏁 LIKELY VULN (lead) · $host · ${cves:-?} · $impact/$conf → worklist"
  fi
done
# ---- WordPress-plugin n-day pass (research vulns 2026-07-01): deterministic readme.txt `Stable tag`
# version checks for the high-install UNAUTH criticals. A confirmed in-range version = strong LEAD (these
# are RCE/admin-takeover class ⇒ the operator exploits/verifies + dup-checks; we NEVER auto-exploit RCE).
# Unauth GET only, via the trusted safe_probe (Mullvad + scope+pays + rate-limit enforced there). ----
WP_ENABLE="${NDAY_WP:-1}"
WP_HOSTS="${NDAY_WP_HOSTS:-12}"
_vge() {  # echo yes if semver $1 >= $2 (self-contained; _ver_lt isn't defined until the EXTRA pass below)
  [[ -z "$1" ]] && { echo no; return; }
  [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" == "$2" ]] && echo yes || echo no
}
_wp_wp2shell_range() {  # echo full|sqli|no|unknown for WP core version $1 vs CVE-2026-63030/60137 "wp2shell"
  local v="$1"; [[ -z "$v" ]] && { echo unknown; return; }
  # full unauth RCE chain: core 6.9.0–6.9.4 or 7.0.0–7.0.1 (fixed 6.9.5 / 7.0.2)
  if { [[ "$(_vge "$v" 6.9.0)" == yes ]] && [[ "$(_vge "$v" 6.9.5)" == no ]]; } \
     || { [[ "$(_vge "$v" 7.0.0)" == yes ]] && [[ "$(_vge "$v" 7.0.2)" == no ]]; }; then echo full; return; fi
  # SQLi-only precursor (CVE-2026-60137 present, no RCE): core 6.8.0–6.8.5
  if [[ "$(_vge "$v" 6.8.0)" == yes ]] && [[ "$(_vge "$v" 6.8.6)" == no ]]; then echo sqli; return; fi
  echo no
}
if [[ "$WP_ENABLE" == "1" && -f "$SAFE_PROBE" ]]; then
  # slug|cve|vuln_ceiling(empty=unknown → report presence+version for operator version-reasoning)|note
  wp_plugins="updraftplus|CVE-2026-10795|1.26.4|unauth admin RCE (3M+ installs, actively exploited); patch 1.26.5
wpvivid-backuprestore|CVE-2026-1357||unauth arbitrary PHP upload → RCE (900K installs)
kirki|CVE-2026-8206||unauth password-reset admin takeover (~150K installs)
user-registration|CVE-2026-1492/1779||client-side token leak → admin bypass
miniorange-oauth-single-sign-on|CVE-2026-57807||unauth login bypass via password-recovery flow → admin takeover (CVSS 9.8, ≤38.5.8, no vendor patch as of 2026-07)
miniorange-oauth|CVE-2026-57807||unauth login bypass via password-recovery flow → admin takeover (CVSS 9.8, ≤38.5.8, no vendor patch as of 2026-07)"
  wpq="$(jq -nc --argjson n "$WP_HOSTS" '{size:($n*3),_source:["host","triage_program"],
    query:{bool:{filter:[{term:{triage_in_scope:true}},{term:{triage_pays:true}},{bool:{must_not:{term:{triage_scan_deny:true}}}},{term:{tech:{value:"wordpress",case_insensitive:true}}}],
                 must_not:[{term:{triage_out_of_scope:true}},{range:{ignore_expires_at:{gt:"now"}}}]}}}')"
  wpresp="$(es "$ES_URL/$INDEX_NAME/_search" -d "$wpq" 2>/dev/null)"
  wp_checked=0
  while IFS=$'\t' read -r wh wprog; do
    [[ -z "$wh" ]] && continue
    [[ "$wp_checked" -ge "$WP_HOSTS" ]] && break
    grep -qxF "wp:$wh" "$SEEN" 2>/dev/null && continue
    printf 'wp:%s\n' "$wh" >> "$SEEN"; wp_checked=$((wp_checked+1))

    # ---- WP core "wp2shell" — CVE-2026-63030 (REST /batch/v1 route-confusion) + CVE-2026-60137 (unauth
    # SQLi) → unauth RCE for core 6.9.0–6.9.4 / 7.0.0–7.0.1 (ITW per 2026-07-21). Version-gate first
    # (readme.html / generator meta), then a SAFE /wp-json/batch/v1 EXISTENCE probe (GET only — route
    # presence, NOT the batch exploit). In-range core is RCE-class ⇒ strong LEAD; operator confirms +
    # dup-checks + NEVER auto-exploits the chain. ----
    wpcore=""
    for cpath in /readme.html '/?rest_route=/'; do
      cpr="$(bash "$SAFE_PROBE" "https://${wh}${cpath}" GET 2>/dev/null)"
      [[ "$(printf '%s' "$cpr" | jq -r '.ok // false')" == "true" ]] || continue
      cbody="$(printf '%s' "$cpr" | jq -r '.body_snippet // ""')"
      wpcore="$(printf '%s' "$cbody" | grep -ioE 'wordpress[^0-9]{0,8}[0-9]+\.[0-9]+(\.[0-9]+)?' | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)"
      [[ -z "$wpcore" ]] && wpcore="$(printf '%s' "$cbody" | grep -ioE 'version[[:space:]]+[0-9]+\.[0-9]+(\.[0-9]+)?' | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)"
      [[ -n "$wpcore" ]] && break
    done
    w2range="$(_wp_wp2shell_range "$wpcore")"
    if [[ "$w2range" != "no" ]]; then   # full | sqli | unknown → check the batch route before flagging
      batchhit=""
      for bpath in /wp-json/batch/v1 '/?rest_route=/batch/v1'; do
        bpr="$(bash "$SAFE_PROBE" "https://${wh}${bpath}" GET 2>/dev/null)"
        [[ "$(printf '%s' "$bpr" | jq -r '.ok // false')" == "true" ]] || continue
        bbody="$(printf '%s' "$bpr" | jq -r '.body_snippet // ""')"
        printf '%s' "$bbody" | grep -qi 'rest_no_route' && continue   # route not registered
        batchhit="$bpath"; break
      done
      # emit only on a real signal: version in-range, OR (version unknown AND batch route present)
      if [[ "$w2range" == "full" || "$w2range" == "sqli" || ( "$w2range" == "unknown" && -n "$batchhit" ) ]]; then
        case "$w2range" in
          full)    w2conf="0.8"; w2imp="critical"; w2rng="core ${wpcore} in-range (6.9.0–6.9.4 / 7.0.0–7.0.1) — full unauth RCE chain";;
          sqli)    w2conf="0.55"; w2imp="high"; w2rng="core ${wpcore} in SQLi-only band (6.8.0–6.8.5) — CVE-2026-60137 precursor, no RCE";;
          *)       w2conf="0.5"; w2imp="critical"; w2rng="core version unknown but /wp-json/batch/v1 route present — operator version-reason vs 6.9.0–7.0.1";;
        esac
        [[ -n "$batchhit" ]] && w2conf="$(awk "BEGIN{printf \"%.2f\", ($w2conf+0.05>0.9?0.9:$w2conf+0.05)}")"
        ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        jq -nc --arg h "$wh" --arg p "$wprog" --arg t "$ts" --arg ver "${wpcore:-unknown}" --arg bh "${batchhit:-not-confirmed}" \
          --arg why "WordPress wp2shell — $w2rng. CVE-2026-63030 (REST /batch/v1 sub-request handler desync) + CVE-2026-60137 (unauth SQLi) → unauth RCE; PoC public + actively exploited ITW." \
          --argjson conf "$w2conf" --arg imp "$w2imp" \
          '{host:$h,program:$p,endpoint:"/wp-json/batch/v1",cve:"CVE-2026-63030",vuln_type:"n-day-wp-core-wp2shell",why:$why,
            test:("Confirm WP core in 6.9.0–6.9.4/7.0.0–7.0.1 (detected "+$ver+"; batch route "+$bh+"). Operator confirms + dup-checks; NEVER auto-exploit the batch/SQLi chain (RCE)."),
            impact:$imp,confidence:$conf,exploit_available:true,at:$t,status:"to-test"}' >> "$WORKLIST" 2>/dev/null
        leads=$((leads+1))
        log "   🐚 WP2SHELL $([[ "$w2range" == "full" ]] && echo IN-RANGE || echo "$w2range") · $wh · core ${wpcore:-?} · batch ${batchhit:-none} · CVE-2026-63030 → worklist"
      fi
    fi

    while IFS='|' read -r slug cve ceiling note; do
      [[ -z "$slug" ]] && continue
      purl="https://${wh}/wp-content/plugins/${slug}/readme.txt"
      pr="$(bash "$SAFE_PROBE" "$purl" GET 2>/dev/null)"
      [[ -n "$pr" ]] || continue
      [[ "$(printf '%s' "$pr" | jq -r '.ok // false')" == "true" ]] || continue
      [[ "$(printf '%s' "$pr" | jq -r '.status // 0')" == "200" ]] || continue
      ver="$(printf '%s' "$pr" | jq -r '.body_snippet // ""' \
             | grep -ioE 'stable tag:[[:space:]]*[0-9][0-9a-zA-Z.-]*' | head -1 \
             | grep -oE '[0-9][0-9a-zA-Z.-]*' | head -1)"
      [[ -n "$ver" ]] || continue
      inrange="unknown"
      if [[ -n "$ceiling" ]]; then
        if [[ "$(printf '%s\n%s\n' "$ver" "$ceiling" | sort -V | tail -1)" == "$ceiling" ]]; then inrange="yes"; else inrange="no"; fi
      fi
      [[ "$inrange" == "no" ]] && { log "   · $wh $slug $ver > $ceiling — patched, skip $cve"; continue; }
      if [[ "$inrange" == "yes" ]]; then wpconf="0.85"; wprng="CONFIRMED in-range (<= $ceiling)"; else wpconf="0.5"; wprng="present — version-reason vs $cve"; fi
      ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
      jq -nc --arg h "$wh" --arg p "$wprog" --arg cve "$cve" --arg t "$ts" --arg slug "$slug" \
        --arg ver "$ver" --arg why "WordPress plugin $slug $ver $wprng: $note" --argjson conf "$wpconf" \
        '{host:$h,program:$p,endpoint:("/wp-content/plugins/"+$slug+"/readme.txt"),cve:$cve,
          vuln_type:"n-day-wp-plugin",why:$why,
          test:("Confirm "+$slug+" "+$ver+" is exploitable per "+$cve+" (operator; dup-check first; never auto-exploit RCE)"),
          impact:"high",confidence:$conf,exploit_available:true,at:$t,status:"to-test"}' >> "$WORKLIST" 2>/dev/null
      leads=$((leads+1))
      log "   🔌 WP-PLUGIN $([[ "$inrange" == "yes" ]] && echo "IN-RANGE" || echo "present") · $wh · $slug $ver · $cve → worklist"
    done <<< "$wp_plugins"
  done < <(printf '%s' "$wpresp" | jq -r '.hits.hits[]?._source | [.host,(.triage_program//"")] | @tsv' 2>/dev/null)
  log "🔌 WP-plugin pass · $wp_checked host(s) checked"
fi

# ---- UniFi-OS / NGINX-Rift / PHP-SOAP n-day pass (research vulns 2026-07-01). Deterministic unauth
# version/endpoint fingerprints for the fresh criticals the WP pass doesn't cover. Same guards as the
# WP pass: in-scope+paying ES filter, SEEN dedup, unauth GET via the trusted SAFE_PROBE (Mullvad +
# scope+pays + rate-limit enforced there). Version-reason → LEAD (never auto-exploit; never P0 on a
# bare version match — the operator confirms + dup-checks). ----
NDAY_EXTRA="${NDAY_EXTRA:-1}"
NDAY_EXTRA_HOSTS="${NDAY_EXTRA_HOSTS:-14}"
_ver_lt() {  # echo yes if $1 < $2 (semver-ish); no if >=; unknown if $1 empty
  [[ -z "$1" ]] && { echo unknown; return; }
  if [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" == "$1" && "$1" != "$2" ]]; then echo yes; else echo no; fi
}
_ngx_42533_inrange() {  # echo yes if nginx $1 is in the CVE-2026-42533 map-regex range: 0.9.6–1.31.2,
  # branch-aware fix (stable 1.30.4 / mainline 1.31.3). Anything below 0.9.6 or a fixed build = no.
  local v="$1"; [[ -z "$v" ]] && { echo unknown; return; }
  [[ "$(_ver_lt "$v" "0.9.6")" == "yes" ]] && { echo no; return; }     # below range floor
  if [[ "$(_ver_lt "$v" "1.31.0")" == "no" ]]; then                     # mainline branch (>=1.31.0)
    [[ "$(_ver_lt "$v" "1.31.3")" == "yes" ]] && echo yes || echo no; return
  fi
  if [[ "$(_ver_lt "$v" "1.30.0")" == "no" ]]; then                     # stable 1.30.x branch
    [[ "$(_ver_lt "$v" "1.30.4")" == "yes" ]] && echo yes || echo no; return
  fi
  echo yes                                                              # 0.9.6 – 1.29.x → in range
}
_es_hosts() {  # $1=tech term → host<TAB>program<TAB>webserver<TAB>tech-joined for in-scope+paying, un-benched
  local q; q="$(jq -nc --arg t "$1" --argjson n "$NDAY_EXTRA_HOSTS" '{size:($n*3),
    _source:["host","triage_program","webserver","tech"],
    query:{bool:{filter:[{term:{triage_in_scope:true}},{term:{triage_pays:true}},{bool:{must_not:{term:{triage_scan_deny:true}}}},{term:{tech:{value:$t,case_insensitive:true}}}],
                 must_not:[{term:{triage_out_of_scope:true}},{range:{ignore_expires_at:{gt:"now"}}},
                          {wildcard:{host:"*.unifi-hosting.ui.com"}}]}}}')"
  es "$ES_URL/$INDEX_NAME/_search" -d "$q" 2>/dev/null \
    | jq -r '.hits.hits[]?._source | [.host,(.triage_program//""),(.webserver//""),((.tech//[])|join(" "))] | @tsv' 2>/dev/null
}
_es_unifi() {  # UniFi consoles by real console TITLE (no "unifi" tech tag exists); exclude Ubiquiti-owned +
  # third-party *.unifi-hosting.ui.com shared tenants (hard line). host<TAB>program<TAB>webserver<TAB>tech
  local q; q="$(jq -nc --argjson n "$NDAY_EXTRA_HOSTS" '{size:($n*3),
    _source:["host","triage_program","webserver","tech"],
    query:{bool:{filter:[{term:{triage_in_scope:true}},{term:{triage_pays:true}},{bool:{must_not:{term:{triage_scan_deny:true}}}}],
      should:[{match_phrase:{title:"UniFi Network"}},{match_phrase:{title:"UniFi OS"}},{match_phrase:{title:"UniFi Dream"}}],
      minimum_should_match:1,
      must_not:[{term:{triage_out_of_scope:true}},{range:{ignore_expires_at:{gt:"now"}}},
                {wildcard:{host:"*.unifi-hosting.ui.com"}},{wildcard:{host:"*.ui.com"}},{term:{host:"ui.com"}}]}}}')"
  es "$ES_URL/$INDEX_NAME/_search" -d "$q" 2>/dev/null \
    | jq -r '.hits.hits[]?._source | [.host,(.triage_program//""),(.webserver//""),((.tech//[])|join(" "))] | @tsv' 2>/dev/null
}

if [[ "$NDAY_EXTRA" == "1" ]]; then
  # --- 1) UniFi OS Triple KEV — CVE-2026-34908/34909/34910 (unauth auth-bypass→traversal→cmd-inj,
  # actively exploited; fixed UniFi OS Server 5.0.8). Unauth version confirm via /status or /api/self. ---
  if [[ -f "$SAFE_PROBE" ]]; then
    uf_checked=0
    while IFS=$'\t' read -r uh uprog uws utech; do
      [[ -z "$uh" ]] && continue
      [[ "$uf_checked" -ge "$NDAY_EXTRA_HOSTS" ]] && break
      grep -qxF "unifi:$uh" "$SEEN" 2>/dev/null && continue
      printf 'unifi:%s\n' "$uh" >> "$SEEN"; uf_checked=$((uf_checked+1))
      ver=""; hit=""
      for upath in /status /api/self; do
        pr="$(bash "$SAFE_PROBE" "https://${uh}${upath}" GET 2>/dev/null)"
        [[ "$(printf '%s' "$pr" | jq -r '.ok // false')" == "true" ]] || continue
        [[ "$(printf '%s' "$pr" | jq -r '.status // 0')" == "200" ]] || continue
        body="$(printf '%s' "$pr" | jq -r '.body_snippet // ""')"
        printf '%s' "$body" | grep -qiE 'unifi|server_version|softwareVersion' || continue
        ver="$(printf '%s' "$body" | grep -ioE '(server_version|softwareVersion)"?[: ]+"?[0-9]+\.[0-9]+\.[0-9]+' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
        hit="$upath"; break
      done
      [[ -n "$hit" ]] || continue
      if [[ "$(_ver_lt "$ver" "5.0.8")" == "yes" ]]; then ufconf="0.85"; ufrng="CONFIRMED in-range (< 5.0.8)"; else ufconf="0.5"; ufrng="UniFi live${ver:+ v$ver} — operator version-reason vs 5.0.8 (OS Server ver, NOT the Network-App 8.x ver)"; fi
      ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
      jq -nc --arg h "$uh" --arg p "$uprog" --arg t "$ts" --arg path "$hit" --arg ver "${ver:-unknown}" \
        --arg why "UniFi OS $ufrng — CVE-2026-34908/34909/34910 KEV triple (unauth auth-bypass→path-traversal→OS-cmd-inj; actively exploited, rogue-admin creation; fixed UniFi OS Server 5.0.8)" --argjson conf "$ufconf" \
        '{host:$h,program:$p,endpoint:$path,cve:"CVE-2026-34908",vuln_type:"n-day-unifi-kev",why:$why,
          test:("Confirm UniFi OS Server version < 5.0.8 (operator; softwareVersion from "+$path+"). NEVER auto-probe the traversal/cmd-inj chain — that is exploitation. Version="+$ver),
          impact:"critical",confidence:$conf,exploit_available:true,at:$t,status:"to-test"}' >> "$WORKLIST" 2>/dev/null
      leads=$((leads+1))
      log "   📡 UniFi-OS $([[ "$ufconf" == "0.85" ]] && echo IN-RANGE || echo live) · $uh · ${ver:-?} · CVE-2026-34908 → worklist"
    done < <(_es_unifi)
    log "📡 UniFi n-day pass · $uf_checked host(s) checked"
  fi

  # --- 2) NGINX "Rift" — CVE-2026-42945 (heap overflow in ngx_http_rewrite_module; vuln < 1.30.1).
  # Version already fingerprinted in ES (Server banner) → pure version-reason, no probe. DoS universal
  # for the range; RCE config-dependent (unnamed-capture rewrite + no-ASLR) → LEAD-not-P0. ---
  ngx_checked=0
  while IFS=$'\t' read -r nh nprog nws ntech; do
    [[ -z "$nh" ]] && continue
    [[ "$ngx_checked" -ge "$NDAY_EXTRA_HOSTS" ]] && break
    grep -qxF "ngxrift:$nh" "$SEEN" 2>/dev/null && continue
    printf 'ngxrift:%s\n' "$nh" >> "$SEEN"
    # version is NOT in ES (webserver is name-only) → read it from a live Server: banner (HEAD, via safe_probe)
    npr="$(bash "$SAFE_PROBE" "https://${nh}/" HEAD 2>/dev/null)"
    [[ "$(printf '%s' "$npr" | jq -r '.ok // false')" == "true" ]] || continue
    nver="$(printf '%s' "$npr" | jq -r '.headers.server // ""' | grep -ioE 'nginx/[0-9]+\.[0-9]+\.[0-9]+' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
    [[ -n "$nver" ]] || continue   # Server banner has no version → cannot version-reason, skip (avoid FP)
    rift="$(_ver_lt "$nver" "1.30.1")"        # CVE-2026-42945 "Rift": range 0.6.27–1.30.0 (fixed 1.30.1/1.31.0)
    maprx="$(_ngx_42533_inrange "$nver")"      # CVE-2026-42533 map-regex: range 0.9.6–1.31.2 (fixed 1.30.4/1.31.3)
    [[ "$rift" == "yes" || "$maprx" == "yes" ]] || { log "   · $nh nginx $nver — patched vs Rift + map-regex, skip"; continue; }
    ngx_checked=$((ngx_checked+1))
    ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    if [[ "$rift" == "yes" ]]; then
      jq -nc --arg h "$nh" --arg p "$nprog" --arg t "$ts" --arg ver "$nver" \
        --arg why "nginx $nver < 1.30.1 → CVE-2026-42945 'Rift' heap overflow in ngx_http_rewrite_module (public PoC, actively exploited ITW). Unauth DoS reliable across the range; RCE needs an unnamed-capture rewrite config + no-ASLR (config-dependent)." \
        '{host:$h,program:$p,endpoint:"/",cve:"CVE-2026-42945",vuln_type:"n-day-nginx-rift",why:$why,
          test:("nginx "+$ver+" version-confirmed in-range. DoS submittable with version PoC where the program pays infra n-days; RCE only after confirming an unnamed-capture rewrite (operator). Version-only = LEAD-not-CONFIRMED; never trigger (DoS = out of bounds)."),
          impact:"high",confidence:0.6,exploit_available:true,at:$t,status:"to-test"}' >> "$WORKLIST" 2>/dev/null
      leads=$((leads+1))
      log "   🩸 NGINX-Rift IN-RANGE · $nh · nginx $nver < 1.30.1 · CVE-2026-42945 → worklist"
    fi
    if [[ "$maprx" == "yes" ]]; then
      jq -nc --arg h "$nh" --arg p "$nprog" --arg t "$ts" --arg ver "$nver" \
        --arg why "nginx $nver in-range for CVE-2026-42533 map-regex heap overflow (0.9.6–1.31.2; fixed 1.30.4 stable / 1.31.3 mainline). Carries its own info-leak that defeats ASLR from one unauth GET → RCE reachable, but exploitation is config-dependent (needs a vulnerable map/regex-capture construct, not remotely fingerprintable) and the only public scanner is a LOCAL nginx.conf reader — no external unauth PoC." \
        '{host:$h,program:$p,endpoint:"/",cve:"CVE-2026-42533",vuln_type:"n-day-nginx-map-regex",why:$why,
          test:("nginx "+$ver+" version-confirmed in-range for CVE-2026-42533. Version-only = LEAD-not-CONFIRMED; config precondition invisible externally and no safe live PoC exists — never trigger. Operator version-reasons + dup-checks."),
          impact:"high",confidence:0.55,exploit_available:false,at:$t,status:"to-test"}' >> "$WORKLIST" 2>/dev/null
      leads=$((leads+1))
      log "   🧩 NGINX-map-regex IN-RANGE · $nh · nginx $nver · CVE-2026-42533 → worklist"
    fi
  done < <(_es_hosts "nginx")
  log "🩸 NGINX-Rift/map-regex n-day pass · $ngx_checked in-range host(s)"

  # --- 3) PHP SOAP UAF RCE — CVE-2026-6722 (unauth when SOAP endpoint public; PHP < 8.2.31/8.3.31/
  # 8.4.21/8.5.6). Endpoint-presence LEAD: a live WSDL/SOAP endpoint on a PHP host → operator
  # version-reasons the PHP branch. NEVER send malformed SOAP (that is exploitation). ---
  if [[ -f "$SAFE_PROBE" ]]; then
    soap_checked=0
    while IFS=$'\t' read -r ph pprog pws ptech; do
      [[ -z "$ph" ]] && continue
      [[ "$soap_checked" -ge "$NDAY_EXTRA_HOSTS" ]] && break
      grep -qxF "phpsoap:$ph" "$SEEN" 2>/dev/null && continue
      printf 'phpsoap:%s\n' "$ph" >> "$SEEN"; soap_checked=$((soap_checked+1))
      soaphit=""
      for spath in '/?wsdl' /soap /api/soap /services/soap; do
        pr="$(bash "$SAFE_PROBE" "https://${ph}${spath}" GET 2>/dev/null)"
        [[ "$(printf '%s' "$pr" | jq -r '.ok // false')" == "true" ]] || continue
        [[ "$(printf '%s' "$pr" | jq -r '.status // 0')" == "200" ]] || continue
        printf '%s' "$pr" | jq -r '.body_snippet // ""' | grep -qiE 'wsdl|soap:envelope|soap:binding|<definitions' || continue
        soaphit="$spath"; break
      done
      [[ -n "$soaphit" ]] || continue
      pver="$(printf '%s' "$pr" | jq -r '.headers["x-powered-by"] // ""' | grep -ioE 'php/?[0-9]+\.[0-9]+\.[0-9]+' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
      ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
      jq -nc --arg h "$ph" --arg p "$pprog" --arg t "$ts" --arg sp "$soaphit" --arg ver "${pver:-unknown}" \
        --arg why "Live SOAP/WSDL endpoint on a PHP host${pver:+ (PHP $pver)} → CVE-2026-6722 SOAP-extension use-after-free RCE (unauth when the SOAP endpoint is public; fixed 8.2.31/8.3.31/8.4.21/8.5.6)." \
        '{host:$h,program:$p,endpoint:$sp,cve:"CVE-2026-6722",vuln_type:"n-day-php-soap",why:$why,
          test:("SOAP endpoint present. Operator confirm PHP branch < patched (detected "+$ver+") then verify per CVE; NEVER send malformed SOAP (exploitation)."),
          impact:"high",confidence:0.45,exploit_available:false,at:$t,status:"to-test"}' >> "$WORKLIST" 2>/dev/null
      leads=$((leads+1))
      log "   🧼 PHP-SOAP endpoint · $ph · $soaphit${pver:+ · PHP $pver} · CVE-2026-6722 → worklist"
    done < <(_es_hosts "php")
    log "🧼 PHP-SOAP n-day pass · $soap_checked host(s) checked"
  fi
fi

tail -n 8000 "$SEEN" > "$SEEN.tmp" 2>/dev/null && mv "$SEEN.tmp" "$SEEN" 2>/dev/null || true
log "🏁 n-day done · 🏁 $leads likely-vulnerable candidate(s) → worklist"

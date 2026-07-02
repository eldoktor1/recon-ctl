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
  query:{bool:{filter:[{term:{triage_in_scope:true}},{term:{triage_pays:true}}],
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
if [[ "$WP_ENABLE" == "1" && -f "$SAFE_PROBE" ]]; then
  # slug|cve|vuln_ceiling(empty=unknown → report presence+version for operator version-reasoning)|note
  wp_plugins="updraftplus|CVE-2026-10795|1.26.4|unauth admin RCE (3M+ installs, actively exploited); patch 1.26.5
wpvivid-backuprestore|CVE-2026-1357||unauth arbitrary PHP upload → RCE (900K installs)
kirki|CVE-2026-8206||unauth password-reset admin takeover (~150K installs)
user-registration|CVE-2026-1492/1779||client-side token leak → admin bypass"
  wpq="$(jq -nc --argjson n "$WP_HOSTS" '{size:($n*3),_source:["host","triage_program"],
    query:{bool:{filter:[{term:{triage_in_scope:true}},{term:{triage_pays:true}},{match:{tech:"wordpress"}}],
                 must_not:[{term:{triage_out_of_scope:true}},{range:{ignore_expires_at:{gt:"now"}}}]}}}')"
  wpresp="$(es "$ES_URL/$INDEX_NAME/_search" -d "$wpq" 2>/dev/null)"
  wp_checked=0
  while IFS=$'\t' read -r wh wprog; do
    [[ -z "$wh" ]] && continue
    [[ "$wp_checked" -ge "$WP_HOSTS" ]] && break
    grep -qxF "wp:$wh" "$SEEN" 2>/dev/null && continue
    printf 'wp:%s\n' "$wh" >> "$SEEN"; wp_checked=$((wp_checked+1))
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

tail -n 8000 "$SEEN" > "$SEEN.tmp" 2>/dev/null && mv "$SEEN.tmp" "$SEEN" 2>/dev/null || true
log "🏁 n-day done · 🏁 $leads likely-vulnerable candidate(s) → worklist"

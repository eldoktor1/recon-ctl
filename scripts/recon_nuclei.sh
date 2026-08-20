#!/usr/bin/env bash
# =============================================================================
# recon_nuclei.sh — Targeted nuclei scanner
#
# RULES (all must be true to fire):
#   1. Host has CVE-tech tag in ES (matched by recon_cve_intel.sh match phase)
#   2. CVE is in CISA KEV catalog (highest-signal subset)
#   3. Host is IN SCOPE (verified by recon_scope_check.sh)
#   4. Host is on a paying program OR VDP (we filter at alert time, not here)
#   5. Not nuclei-scanned in last 24h (unless new CVE appeared for this tech)
#
# OUTPUT:
#   ~/recon/nuclei/results/<ts>_<host>.jsonl   raw nuclei output
#   ~/recon/nuclei/confirmed.jsonl              all confirmed (cumulative)
#   ES update: v2_nuclei_status, v2_nuclei_template, v2_nuclei_severity
#   Discord: KEV-P0 channel for confirmed
#
# RATE LIMITING:
#   Max 5 concurrent hosts
#   10 rps per host
#   60s timeout per template
#
# =============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

log()  { printf '[%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
die()  { printf '[%s ERROR] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/recon_net.sh"


for c in jq curl; do command -v "$c" >/dev/null || die "missing: $c"; done
command -v nuclei >/dev/null || die "nuclei not installed"

NUCLEI_DIR="${NUCLEI_DIR:-$HOME/recon/nuclei}"
RESULTS_DIR="$NUCLEI_DIR/results"
FP_DIR="$NUCLEI_DIR/fp"
BOUNTY_TEMPLATES_DIR="$NUCLEI_DIR/bounty_templates"

# -----------------------------------------------------------------------------
# Subcommand: `recon_nuclei.sh bounty <target_file>`
# Runs nuclei using ONLY the curated bounty template set against the hosts in
# <target_file> (one URL per line). Emits .jsonl results under
# results/bounty_<ts>/. Used by recon_fresh_modules.sh (smart-scan mode).
# -----------------------------------------------------------------------------
if [[ "${1:-}" == "bounty" ]]; then
  shift
  target_file="${1:-}"; shift || true
  [[ -s "$target_file" ]] || { warn "bounty mode: target file empty or missing"; exit 0; }
  [[ -d "$BOUNTY_TEMPLATES_DIR" ]] || { warn "bounty templates dir missing — run tools/sync_bounty_templates.sh"; exit 0; }
  RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)"
  RUN_DIR="$RESULTS_DIR/bounty_$RUN_TS"
  out_file="$RUN_DIR/findings.jsonl"
  mkdir -p "$RUN_DIR"
  log "Bounty scan: $(wc -l < "$target_file" | tr -d ' ') targets, templates=$BOUNTY_TEMPLATES_DIR"
  timeout 900 nuclei \
    -l "$target_file" \
    -t "$BOUNTY_TEMPLATES_DIR" \
    -severity critical,high,medium \
    -rate-limit "${RATE_LIMIT:-10}" \
    -bulk-size "${NUCLEI_BULK_SIZE:-25}" \
    -timeout "${TIMEOUT:-60}" \
    -retries 1 -no-color -silent -nc \
    -jsonl -o "$out_file" 2>/dev/null || true
  # Append confirmed
  if [[ -s "$out_file" ]]; then
    cat "$out_file" >> "$NUCLEI_DIR/confirmed.jsonl"
    log "Bounty scan: $(wc -l < "$out_file") findings written"
  else
    log "Bounty scan: no findings"
  fi
  exit 0
fi
# =============================================================================
# Subcommand: `recon_nuclei.sh exposure`
# Scans P0/P1 in-scope paying hosts for exposed files, backup configs, and
# common misconfigurations (CORS, Spring actuators, directory listings,
# environment files, git repos in webroot, etc.).
#
# This runs SEPARATELY from the KEV CVE scanner — different target pool
# (all P0/P1, not just KEV-matched), different templates, different cooldown.
# Findings go to ~/recon/nuclei/exposure_confirmed.jsonl + ES + Discord #vulns.
#
# Template coverage:
#   http/exposed-files/   — .env, wp-config.php.bak, docker-compose.yml, etc.
#   http/exposures/       — broader exposure category (git, config, secrets)
#   http/misconfiguration/cors-misconfig.yaml — CORS origin reflection
#   http/misconfiguration/springboot/         — Spring actuator endpoints
#   http/misconfiguration/proxy-open-redirect.yaml
#   http/misconfiguration/aws-object-listing.yaml — S3/CloudFront misconfig
# =============================================================================
if [[ "${1:-}" == "exposure" ]]; then
  shift

  EXP_BATCH="${EXP_BATCH:-100}"
  EXP_COOLDOWN_DAYS="${EXP_COOLDOWN_DAYS:-7}"
  EXP_RATE="${EXP_RATE:-15}"
  EXP_TIMEOUT="${EXP_TIMEOUT:-30}"
  EXP_RESULTS="$NUCLEI_DIR/exposure_confirmed.jsonl"

  LOCK_FILE_EXP="$HOME/recon/state/nuclei_exposure.lock"
  exec 9>"$LOCK_FILE_EXP"
  flock -n 9 || { log "exposure scan already running"; exit 0; }

  KILL_FILE_EXP="$HOME/recon/state/kill/v2_exposure"
  [[ -f "$KILL_FILE_EXP" ]] && { warn "exposure nuclei killswitch active"; exit 0; }

  setup_es_netrc
  ES_AUTH_EXP=(--netrc-file "$HOME/.recon_es_netrc")

  exp_cutoff="$(date -u -d "-${EXP_COOLDOWN_DAYS} days" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || \
    python3 -c "
from datetime import datetime, timedelta
print((datetime.utcnow()-timedelta(days=${EXP_COOLDOWN_DAYS})).strftime('%Y-%m-%dT%H:%M:%SZ'))
")"

  # Build target list from ES: P0/P1, in-scope, pays, not WAF-blocked,
  # not exposure-scanned in last 7 days
  exp_query="$(jq -nc \
    --argjson size "$EXP_BATCH" \
    --arg cutoff "$exp_cutoff" '{
      size: $size,
      _source: ["host","url","triage_score"],
      query: {bool: {
        filter: [
          {terms: {triage_priority: ["P0","P1"]}},
          {term: {triage_in_scope: true}},
          {term: {triage_pays: true}},{bool:{must_not:{term:{triage_scan_deny:true}}}}
        ],
        must_not: [
          {term: {waf_blocks_scanners: true}},
          {range: {exposure_scan_at: {gte: $cutoff}}}
        ]
      }},
      sort: [{triage_score: {order: "desc"}}]
    }')"

  exp_resp="$(curl -sS -m30 "${ES_AUTH_EXP[@]}" -H 'Content-Type: application/json' \
    -X POST "${ES_URL:-http://127.0.0.1:9200}/${INDEX_NAME:-recon_alive}/_search" \
    -d "$exp_query" 2>/dev/null)"

  exp_total="$(printf '%s' "$exp_resp" | jq -r '.hits.total.value // 0')"
  log "[exposure] targets (P0/P1, not scanned in ${EXP_COOLDOWN_DAYS}d): $exp_total — scanning up to $EXP_BATCH"
  [[ "$exp_total" -eq 0 ]] && { log "[exposure] nothing to scan"; exit 0; }

  # Write URL list for nuclei
  exp_url_list="$(mktemp)"
  printf '%s' "$exp_resp" | jq -r '.hits.hits[]._source | .url // ("https://" + .host)' \
    > "$exp_url_list"

  EXP_RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)"
  EXP_OUT="$RESULTS_DIR/exposure_${EXP_RUN_TS}.jsonl"
  mkdir -p "$RESULTS_DIR"
  touch "$EXP_RESULTS"

  log "[exposure] scanning $(wc -l < "$exp_url_list" | tr -d ' ') hosts"

  # Template set: exposed-files + exposures + targeted misconfigs
  # Use -tags to include community templates not under these paths too
  timeout 3600 nuclei \
    -l "$exp_url_list" \
    -t "http/exposed-files/" \
    -t "http/exposures/" \
    -t "http/misconfiguration/cors-misconfig.yaml" \
    -t "http/misconfiguration/springboot/" \
    -t "http/misconfiguration/proxy-open-redirect.yaml" \
    -t "http/misconfiguration/aws-object-listing.yaml" \
    -tags "exposure,backup,config,env,cors,spring" \
    -severity critical,high,medium \
    -rate-limit "$EXP_RATE" \
    -timeout "$EXP_TIMEOUT" \
    -retries 1 -no-color -silent -nc \
    -jsonl -o "$EXP_OUT" 2>/dev/null || true

  rm -f "$exp_url_list"

  exp_now="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

  # Mark all queried hosts as scanned regardless of findings
  printf '%s' "$exp_resp" | jq -r '.hits.hits[]._source.host' | while IFS= read -r exp_host; do
    curl -sS -m15 "${ES_AUTH_EXP[@]}" -H 'Content-Type: application/json' \
      -X POST "${ES_URL:-http://127.0.0.1:9200}/${INDEX_NAME:-recon_alive}/_update/$exp_host" \
      -d "$(jq -nc --arg n "$exp_now" '{"doc":{"exposure_scan_at":$n}}')" \
      2>/dev/null > /dev/null || true
  done

  if [[ -s "$EXP_OUT" ]]; then
    nfindings="$(wc -l < "$EXP_OUT" | tr -d ' ')"
    log "[exposure] $nfindings finding(s) — appending to exposure_confirmed.jsonl"
    cat "$EXP_OUT" >> "$EXP_RESULTS"

    # Alert to #vulns channel for each finding
    exp_hook="$(discord_hook vulns)"
    if [[ -n "$exp_hook" ]]; then
      while IFS= read -r exp_f; do
        exp_host="$(printf '%s' "$exp_f" | jq -r '.host // empty')"
        exp_tmpl="$(printf '%s' "$exp_f" | jq -r '."template-id" // empty')"
        exp_sev="$(printf '%s' "$exp_f" | jq -r '.info.severity // "?"')"
        exp_name="$(printf '%s' "$exp_f" | jq -r '.info.name // $tmpl' --arg tmpl "$exp_tmpl")"
        exp_matched="$(printf '%s' "$exp_f" | jq -r '."matched-at" // empty')"
        [[ -z "$exp_host" || -z "$exp_tmpl" ]] && continue

        # Update ES with finding
        curl -sS -m15 "${ES_AUTH_EXP[@]}" -H 'Content-Type: application/json' \
          -X POST "${ES_URL:-http://127.0.0.1:9200}/${INDEX_NAME:-recon_alive}/_update/$exp_host" \
          -d "$(jq -nc \
            --arg tmpl "$exp_tmpl" --arg sev "$exp_sev" --arg n "$exp_now" \
            '{"doc":{"exposure_nuclei_template":$tmpl,"exposure_nuclei_severity":$sev,"exposure_scan_at":$n}}')" \
          2>/dev/null > /dev/null || true

        exp_payload="$(jq -nc \
          --arg host "$exp_host" \
          --arg tmpl "$exp_tmpl" \
          --arg sev "$exp_sev" \
          --arg name "$exp_name" \
          --arg matched "$exp_matched" \
          --arg ts "$exp_now" '{
            embeds: [{
              title: ("🧪 EXPOSURE FIND — " + $host),
              url: $matched,
              color: 16744272,
              fields: [
                {name: "Template",  value: $tmpl, inline: true},
                {name: "Severity",  value: $sev,  inline: true},
                {name: "Matched",   value: (if $matched != "" then $matched else "n/a" end), inline: false}
              ],
              footer: {text: "nuclei exposure scan"},
              timestamp: $ts
            }]
          }')"
        discord_post "$exp_hook" "$exp_payload" || true
      done < "$EXP_OUT"
    fi
  else
    log "[exposure] no findings this run"
  fi

  log "[exposure] cycle complete"
  exit 0
fi

CVE_DIR="$HOME/recon/cve"
SCOPE_CHECK="${SCOPE_CHECK:-$SCRIPT_DIR/recon_scope_check.sh}"
[[ -f "$SCOPE_CHECK" ]] || SCOPE_CHECK="$HOME/recon_scope_check.sh"
KILL_FILE="$HOME/recon/state/kill/v2_nuclei"
LOCK_FILE="$HOME/recon/state/nuclei.lock"

ES_URL="${ES_URL:-http://127.0.0.1:9200}"
INDEX_NAME="${INDEX_NAME:-recon_alive}"
setup_es_netrc
ES_AUTH=(--netrc-file "$HOME/.recon_es_netrc")

# Discord routing uses per-channel files via discord_hook() (recon_net.sh):
# confirmed CVE findings -> 'cve' channel; killswitch alerts -> 'health' channel.

# Tunable
MAX_CONCURRENT="${MAX_CONCURRENT:-5}"
RATE_LIMIT="${RATE_LIMIT:-10}"
TIMEOUT="${TIMEOUT:-60}"
COOLDOWN_HOURS="${COOLDOWN_HOURS:-24}"
MAX_HOSTS_PER_RUN="${MAX_HOSTS_PER_RUN:-50}"
PAYING_ONLY="${NUCLEI_PAYING_ONLY:-1}"

mkdir -p "$RESULTS_DIR" "$FP_DIR" "$NUCLEI_DIR/templates"

[[ -f "$KILL_FILE" ]] && { warn "nuclei killed: $(cat "$KILL_FILE")"; exit 0; }

exec 9>"$LOCK_FILE"
flock -n 9 || { log "nuclei already running"; exit 0; }

# Prune stale results dirs (run_* and bounty_*) older than NUCLEI_RESULTS_KEEP_DAYS (default 7).
# Individual per-host out_files live inside these dirs; confirmed findings are already
# appended to confirmed.jsonl so pruning run dirs loses nothing.
NUCLEI_RESULTS_KEEP_DAYS="${NUCLEI_RESULTS_KEEP_DAYS:-7}"
if [[ -d "$RESULTS_DIR" ]]; then
  _pruned_dirs=0
  while IFS= read -r -d '' _rdir; do
    rm -rf "$_rdir" && (( _pruned_dirs++ )) || true
  done < <(find "$RESULTS_DIR" -maxdepth 1 -type d \( -name 'run_*' -o -name 'bounty_*' \) \
    -mtime +"$NUCLEI_RESULTS_KEEP_DAYS" -print0 2>/dev/null)
  [[ "$_pruned_dirs" -gt 0 ]] && log "Pruned $_pruned_dirs stale results dirs (>${NUCLEI_RESULTS_KEEP_DAYS}d old)"
fi

# Prune cooldown markers older than 2x COOLDOWN_HOURS to avoid unbounded accumulation.
_cooldown_max_age_days=$(( (COOLDOWN_HOURS * 2 + 23) / 24 ))
_pruned_markers=0
while IFS= read -r -d '' _marker; do
  rm -f "$_marker" && (( _pruned_markers++ )) || true
done < <(find "$NUCLEI_DIR" -maxdepth 1 -name '.last_*' \
  -mtime +"$_cooldown_max_age_days" -print0 2>/dev/null)
[[ "$_pruned_markers" -gt 0 ]] && log "Pruned $_pruned_markers stale cooldown markers (>${_cooldown_max_age_days}d old)"

[[ -s "$CVE_DIR/kev_targets.jsonl" ]] || {
  log "No KEV targets to scan (run recon_cve_intel.sh match first)"
  exit 0
}

es_doc_count="$(curl -fsS -m 10 "${ES_AUTH[@]}" "$ES_URL/$INDEX_NAME/_count" 2>/dev/null | jq -r '.count // 0' 2>/dev/null || echo 0)"
if [[ "${es_doc_count:-0}" -eq 0 ]]; then
  warn "ES index $INDEX_NAME is empty; refusing to scan stale KEV target file"
  exit 0
fi

[[ -f "$SCOPE_CHECK" ]] || die "recon_scope_check.sh missing"

# =============================================================================
# Build target list — apply all gates (batch scope check)
# =============================================================================
log "Building scoped KEV target list (batch mode)"

TARGETS_TMP="$(mktemp)"
SCOPE_TMP="$(mktemp)"
HOSTS_TMP="$(mktemp)"
trap "rm -f '$TARGETS_TMP' '$SCOPE_TMP' '$HOSTS_TMP'" EXIT

# Tier filter: which signals to scan?
# Default = "high-value" (KEV-PROVEN tech with low FP rate).
# Override with NUCLEI_TIER=all to scan everything in kev_targets.
NUCLEI_TIER="${NUCLEI_TIER:-high-value}"

case "$NUCLEI_TIER" in
  all)
    SIGNAL_FILTER='.'  # accept all
    log "  tier: ALL (scanning every KEV-matched signal)"
    ;;
  high-value|*)
    # KEV-proven, low-FP tech only. Cuts WP/Drupal/AEM/Spring/Tomcat noise.
    SIGNAL_FILTER='select(.matched_signal | IN(
      "tech:moveit","tech:confluence","tech:jenkins","tech:magento",
      "tech:exchange-owa","tech:weblogic","tech:websphere","tech:fortinet",
      "tech:citrix","tech:vmware","tech:f5-bigip","tech:paloalto",
      "tech:ivanti-pulse","tech:manageengine","tech:gitlab","tech:solr",
      "tech:zabbix","tech:kibana","tech:jira","tech:nexus","tech:phpmyadmin",
      "tech:argocd","tech:rancher","tech:portainer","tech:thinkphp",
      "tech:coldfusion","tech:airflow","tech:joomla"))'
    log "  tier: high-value (skipping wordpress/drupal/aem/spring/tomcat)"
    ;;
esac

# 1. Filter kev_targets to selected tier, extract hosts
jq -c "$SIGNAL_FILTER" "$CVE_DIR/kev_targets.jsonl" > "${TARGETS_TMP}.tier"
TIER_COUNT="$(wc -l < "${TARGETS_TMP}.tier" | tr -d ' ')"
log "  after tier filter: $TIER_COUNT targets"

if [[ "$TIER_COUNT" -eq 0 ]]; then
  log "Nothing to scan after tier filter"
  exit 0
fi

# 2. Extract host list, batch scope-check (single awk pass)
jq -r '.host' "${TARGETS_TMP}.tier" > "$HOSTS_TMP"
bash "$SCOPE_CHECK" --batch "$HOSTS_TMP" > "$SCOPE_TMP"
SCOPE_OK_COUNT="$(jq -s 'map(select(.in_scope == true and .out_of_scope == false)) | length' "$SCOPE_TMP")"
log "  after scope check: $SCOPE_OK_COUNT in-scope (any pays/VDP)"

PAYING_OK_COUNT="$(jq -s 'map(select(.in_scope == true and .pays == true)) | length' "$SCOPE_TMP")"
log "  paying-only:        $PAYING_OK_COUNT in-scope on paying programs"
[[ "$PAYING_ONLY" == "1" ]] && log "  VDP/unknown-pay targets: excluded"

# 3. Build host→scope map for join, then merge with kev_targets
# Apply cooldown filter inline
NOW="$(date +%s)"
jq -s --slurpfile scope <(jq -s '.' "$SCOPE_TMP") \
   --argjson now "$NOW" \
   --argjson cooldown "$COOLDOWN_HOURS" \
   --argjson paying_only "$PAYING_ONLY" '
  ($scope[0] | map({(.host): .}) | add) as $sm |
  map(
    . as $t |
    ($sm[$t.host] // {}) as $s |
    if ($s.in_scope == true and $s.out_of_scope == false and ($paying_only == 0 or $s.pays == true)) then
      $t + {
        program: ($s.program // ""),
        platform: ($s.platform // ""),
        pays: ($s.pays // false),
        cves: ([.matched_cves[].id] | join(","))
      }
    else
      empty
    end
  )
' "${TARGETS_TMP}.tier" > "${TARGETS_TMP}.merged"

# 4. Cooldown filter + Fix 9: Cloudflare Bot Management pre-check
: > "$TARGETS_TMP"
jq -c '.[]' "${TARGETS_TMP}.merged" 2>/dev/null | while IFS= read -r line; do
  host="$(echo "$line" | jq -r '.host')"
  sig="$(echo "$line" | jq -r '.matched_signal // .signal')"

  # Fix 9: Cloudflare Bot Management check — query ES for tech[] field
  # If host has "Cloudflare Bot Management" in tech[], skip nuclei and mark as manual-only
  es_tech="$(curl -fsS -m 8 "${ES_AUTH[@]}" \
    -H 'Content-Type: application/json' \
    -X GET "$ES_URL/$INDEX_NAME/_doc/$host" 2>/dev/null \
    | jq -r '(.["_source"].tech // []) | map(ascii_downcase) | join(",")' 2>/dev/null || echo "")"
  if printf '%s' "$es_tech" | grep -qi 'cloudflare bot management' 2>/dev/null; then
    log "SKIP (CF Bot Management) $host — marking waf_blocks_scanners=true, manual-only"
    # ES update: waf_blocks_scanners=true
    curl -fsS -m 10 "${ES_AUTH[@]}" -H 'Content-Type: application/json' \
      -X POST "$ES_URL/$INDEX_NAME/_update/$host" \
      -d '{"doc":{"waf_blocks_scanners":true,"nuclei_skip_reason":"cloudflare_bot_management"}}' \
      >/dev/null 2>&1 || true
    continue
  fi

  cooldown_marker="$NUCLEI_DIR/.last_$(echo "${host}_${sig}" | sha256sum | cut -c1-16)"
  if [[ -f "$cooldown_marker" ]]; then
    last="$(cat "$cooldown_marker")"
    age_h=$(( (NOW - last) / 3600 ))
    [[ "$age_h" -lt "$COOLDOWN_HOURS" ]] && continue
  fi
  # Renormalize field names for downstream scan_one
  echo "$line" | jq -c '{
    host:.host,
    url:(.url // ("https://" + .host)),
    signal:(.matched_signal // .signal),
    cves:.cves,
    program:.program,
    platform:.platform,
    pays:.pays
  }' >> "$TARGETS_TMP"
done

rm -f "${TARGETS_TMP}.tier" "${TARGETS_TMP}.merged"

TOTAL_TARGETS="$(wc -l < "$TARGETS_TMP" | tr -d ' ')"
log "Scoped KEV targets: $TOTAL_TARGETS"

if [[ "$TOTAL_TARGETS" -eq 0 ]]; then
  log "Nothing to scan after gating"
  exit 0
fi

# Cap targets per run
head -n "$MAX_HOSTS_PER_RUN" "$TARGETS_TMP" > "${TARGETS_TMP}.capped"
mv "${TARGETS_TMP}.capped" "$TARGETS_TMP"
TO_SCAN="$(wc -l < "$TARGETS_TMP" | tr -d ' ')"
log "Scanning $TO_SCAN this run (cap: $MAX_HOSTS_PER_RUN)"

# =============================================================================
# Scan loop
# =============================================================================
RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="$RESULTS_DIR/run_$RUN_TS"
mkdir -p "$RUN_DIR"

CONFIRMED_FILE="$NUCLEI_DIR/confirmed.jsonl"
CONFIRMED_SEEN_FILE="$NUCLEI_DIR/.confirmed_seen"
FP_LIST="$FP_DIR/known_fp.txt"
touch "$CONFIRMED_FILE" "$FP_LIST"
if ! (touch "$CONFIRMED_SEEN_FILE" 2>/dev/null && [[ -w "$CONFIRMED_SEEN_FILE" ]]); then
  warn "$CONFIRMED_SEEN_FILE not writable by uid $(id -u); using per-uid seen file"
  CONFIRMED_SEEN_FILE="$NUCLEI_DIR/.confirmed_seen.$(id -u)"
  touch "$CONFIRMED_SEEN_FILE" 2>/dev/null || CONFIRMED_SEEN_FILE="/tmp/.recon_nuclei_confirmed_seen.$(id -u)"
  touch "$CONFIRMED_SEEN_FILE" 2>/dev/null || true
fi
if [[ ! -s "$CONFIRMED_SEEN_FILE" && -s "$CONFIRMED_FILE" ]]; then
  jq -r '[.host // "", ."template-id" // ""] | @tsv' "$CONFIRMED_FILE" 2>/dev/null \
    | awk -F'\t' '$1 != "" && $2 != "" {print $1 "|" $2}' \
    | sort -u > "$CONFIRMED_SEEN_FILE" 2>/dev/null || true
fi

scan_one() {
  local target_json="$1"
  local host url cves matched_signal program platform pays
  host="$(echo "$target_json" | jq -r '.host')"
  url="$(echo "$target_json" | jq -r '.url')"
  cves="$(echo "$target_json" | jq -r '.cves')"
  matched_signal="$(echo "$target_json" | jq -r '.signal')"
  program="$(echo "$target_json" | jq -r '.program')"
  platform="$(echo "$target_json" | jq -r '.platform')"
  pays="$(echo "$target_json" | jq -r '.pays')"

  local out_file="$RUN_DIR/$(echo "$host" | tr '/:' '__').jsonl"

  # Build template selector — only the specific KEV CVEs
  local templates=()
  IFS=',' read -ra cve_arr <<< "$cves"
  for cve in "${cve_arr[@]}"; do
    [[ -z "$cve" ]] && continue
    # Nuclei templates are typically named cves/<year>/<id>.yaml
    templates+=("-id" "$cve")
  done

  [[ ${#templates[@]} -eq 0 ]] && return 0

  # Run nuclei with strict params
  log "  scanning $host (CVEs: $cves)"
  timeout 300 nuclei \
    -target "$url" \
    "${templates[@]}" \
    -severity critical,high \
    -rate-limit "$RATE_LIMIT" \
    -timeout "$TIMEOUT" \
    -retries 1 \
    -no-color -silent -nc \
    -jsonl -o "$out_file" 2>/dev/null || true

  # Mark scanned
  cooldown_marker="$NUCLEI_DIR/.last_$(echo "${host}_${matched_signal}" | sha256sum | cut -c1-16)"
  date +%s > "$cooldown_marker"

  # Filter false positives (known FP list)
  if [[ -s "$out_file" ]]; then
    jq -c --slurpfile fp <(jq -R -s 'split("\n") | map(select(. != ""))' "$FP_LIST" 2>/dev/null || echo '[]') '
      . | select((($fp[0] // []) | index((.host // "") + "|" + (."template-id" // ""))) | not)
    ' "$out_file" > "${out_file}.filtered" 2>/dev/null || cp "$out_file" "${out_file}.filtered"
    mv "${out_file}.filtered" "$out_file"
  fi

  # Emit confirmed findings
  if [[ -s "$out_file" ]]; then
    while IFS= read -r finding; do
      [[ -z "$finding" ]] && continue
      local template key
      template="$(echo "$finding" | jq -r '."template-id" // empty')"
      [[ -z "$template" ]] && continue
      key="${host}|${template}"
      if grep -qxF "$key" "$CONFIRMED_SEEN_FILE" 2>/dev/null; then
        continue
      fi
      enriched="$(echo "$finding" | jq -c \
        --arg program "$program" \
        --arg platform "$platform" \
        --argjson pays "$pays" \
        --arg signal "$matched_signal" \
        '. + {scope: {program: $program, platform: $platform, pays: $pays}, matched_signal: $signal}')"
      echo "$enriched" >> "$CONFIRMED_FILE"
      echo "$key" >> "$CONFIRMED_SEEN_FILE"

      # Update ES doc with confirmation
      es_update_confirmed "$host" "$enriched"

      # Discord alert
      notify_discord_confirmed "$enriched"
    done < "$out_file"
  fi
}

es_update_confirmed() {
  local host="$1" finding="$2"
  local template severity
  template="$(echo "$finding" | jq -r '."template-id"')"
  severity="$(echo "$finding" | jq -r '.info.severity // "unknown"')"

  curl -fsS --netrc-file "$HOME/.recon_es_netrc" -H 'Content-Type: application/json' \
    -X POST "$ES_URL/$INDEX_NAME/_update/$host" \
    -d "$(jq -n --arg t "$template" --arg s "$severity" \
         --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '
         {doc: {
           v2_nuclei_status: "confirmed",
           v2_nuclei_template: $t,
           v2_nuclei_severity: $s,
           v2_nuclei_run_at: $ts
         }}')" >/dev/null 2>&1 || true
}

notify_discord_confirmed() {
  local finding="$1"
  local hook; hook="$(discord_hook cve)"
  [[ -z "$hook" ]] && return 0

  local payload
  payload="$(echo "$finding" | jq '{
    content: "🚨 **CONFIRMED FINDING — KEV CVE matched**",
    embeds: [{
      title: ("[CONFIRMED] " + (.host // "unknown")),
      url: (."matched-at" // .url // .host),
      color: 10038562,
      fields: [
        {name:"Template",  value:."template-id", inline:true},
        {name:"Severity",  value:(.info.severity // "unknown"), inline:true},
        {name:"Matched",   value:(."matched-at" // "n/a"), inline:false},
        {name:"Program",   value:((.scope.program // "?") + " (" + (.scope.platform // "?") + ")"), inline:true},
        {name:"Pays",      value:(if .scope.pays then "✅" else "❌ VDP" end), inline:true},
        {name:"Description", value:((.info.description // .info.name // "")[0:600]), inline:false},
        {name:"Reference", value:(.info.reference // [] | join("\n") | .[0:500]), inline:false}
      ],
      footer:{text:"recon_v2 nuclei · KEV"},
      timestamp:(now | strftime("%Y-%m-%dT%H:%M:%SZ"))
    }]
  }')"
  discord_post "$(discord_hook cve)" "$payload" || true   # → #cve-kev (CVE/KEV template confirmations)
}

# =============================================================================
# Run
# =============================================================================
log "Starting nuclei scan (max concurrent: $MAX_CONCURRENT)"

count=0
pids=()
while IFS= read -r target_json; do
  [[ -z "$target_json" ]] && continue
  scan_one "$target_json" &
  pids+=($!)
  count=$((count + 1))

  # Throttle concurrency
  if [[ ${#pids[@]} -ge "$MAX_CONCURRENT" ]]; then
    wait "${pids[0]}" 2>/dev/null || true
    pids=("${pids[@]:1}")
  fi
done < "$TARGETS_TMP"

wait 2>/dev/null || true

CONFIRMED_THIS_RUN=0
if compgen -G "$RUN_DIR"/*.jsonl >/dev/null; then
  CONFIRMED_THIS_RUN="$(cat "$RUN_DIR"/*.jsonl 2>/dev/null | wc -l | tr -d ' ')"
fi
log "Scan complete: $count hosts scanned, $CONFIRMED_THIS_RUN findings confirmed"

# Sanity check — too many confirmed findings = likely false positive flood
if [[ "$CONFIRMED_THIS_RUN" -gt 10 ]]; then
  warn "More than 10 confirmed findings in single run — engaging killswitch (likely FP flood)"
  echo "auto-disable: $CONFIRMED_THIS_RUN findings in single run ($(date -u))" \
    > "$HOME/recon/state/kill/v2_nuclei"

  # Send alert
  discord_post "$(discord_hook ops)" "{\"content\":\"⚠️ Nuclei auto-disabled: $CONFIRMED_THIS_RUN findings in one run (likely false positive). Investigate before re-enabling.\"}" || true
fi

log "Nuclei cycle complete"

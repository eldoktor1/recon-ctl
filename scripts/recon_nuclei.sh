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

# Network command wrapper.
# If USE_PROXYCHAINS=1, target-facing tools MUST run through proxychains4.
# Fail closed if proxychains/Tor is not available.
proxy_required() { [[ "${USE_PROXYCHAINS:-1}" == "1" ]]; }

ensure_proxy_ready() {
  proxy_required || return 0
  command -v proxychains4 >/dev/null 2>&1 || die "USE_PROXYCHAINS=1 but proxychains4 is missing"
  ss -ltn 2>/dev/null | grep -q '127\.0\.0\.1:9050' || die "USE_PROXYCHAINS=1 but Tor SOCKS listener 127.0.0.1:9050 is not up"
}

run_net() {
  ensure_proxy_ready
  if proxy_required; then
    proxychains4 -q "$@"
  else
    "$@"
  fi
}


for c in jq curl; do command -v "$c" >/dev/null || die "missing: $c"; done
command -v nuclei >/dev/null || die "nuclei not installed"

NUCLEI_DIR="${NUCLEI_DIR:-$HOME/recon/nuclei}"
RESULTS_DIR="$NUCLEI_DIR/results"
FP_DIR="$NUCLEI_DIR/fp"
CVE_DIR="$HOME/recon/cve"
SCOPE_CHECK="$HOME/recon_scope_check.sh"
KILL_FILE="$HOME/recon/state/kill/v2_nuclei"
LOCK_FILE="$HOME/recon/state/nuclei.lock"

ES_URL="${ES_URL:-http://127.0.0.1:9200}"
INDEX_NAME="${INDEX_NAME:-recon_alive}"
ES_USER="${ES_USER:-elastic}"
ES_PASS="${ES_PASS:-$(cat "$HOME/.recon_es_pass" 2>/dev/null)}"

DISCORD_KEV_WEBHOOK="${DISCORD_KEV_WEBHOOK:-$(cat "$HOME/.recon_discord_kev" 2>/dev/null || true)}"
DISCORD_WEBHOOK="${DISCORD_WEBHOOK:-$(cat "$HOME/.recon_discord" 2>/dev/null || true)}"

# Tunable
MAX_CONCURRENT="${MAX_CONCURRENT:-5}"
RATE_LIMIT="${RATE_LIMIT:-10}"
TIMEOUT="${TIMEOUT:-60}"
COOLDOWN_HOURS="${COOLDOWN_HOURS:-24}"
MAX_HOSTS_PER_RUN="${MAX_HOSTS_PER_RUN:-50}"

mkdir -p "$RESULTS_DIR" "$FP_DIR" "$NUCLEI_DIR/templates"

[[ -f "$KILL_FILE" ]] && { warn "nuclei killed: $(cat "$KILL_FILE")"; exit 0; }

exec 9>"$LOCK_FILE"
flock -n 9 || { log "nuclei already running"; exit 0; }

[[ -s "$CVE_DIR/kev_targets.jsonl" ]] || {
  log "No KEV targets to scan (run recon_cve_intel.sh match first)"
  exit 0
}

[[ -x "$SCOPE_CHECK" ]] || die "recon_scope_check.sh missing"

# =============================================================================
# Build target list — apply all gates (v2.1.2: batch scope check)
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
"$SCOPE_CHECK" --batch "$HOSTS_TMP" > "$SCOPE_TMP"
SCOPE_OK_COUNT="$(jq -s 'map(select(.in_scope == true and .out_of_scope == false)) | length' "$SCOPE_TMP")"
log "  after scope check: $SCOPE_OK_COUNT in-scope (any pays/VDP)"

PAYING_OK_COUNT="$(jq -s 'map(select(.in_scope == true and .pays == true)) | length' "$SCOPE_TMP")"
log "  paying-only:        $PAYING_OK_COUNT in-scope on paying programs"

# 3. Build host→scope map for join, then merge with kev_targets
# Apply cooldown filter inline
NOW="$(date +%s)"
jq -s --slurpfile scope <(jq -s '.' "$SCOPE_TMP") \
   --argjson now "$NOW" \
   --argjson cooldown "$COOLDOWN_HOURS" '
  ($scope[0] | map({(.host): .}) | add) as $sm |
  map(
    . as $t |
    ($sm[$t.host] // {}) as $s |
    if ($s.in_scope == true and $s.out_of_scope == false) then
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

# 4. Cooldown filter (file-system based — same as before)
: > "$TARGETS_TMP"
jq -c '.[]' "${TARGETS_TMP}.merged" 2>/dev/null | while IFS= read -r line; do
  host="$(echo "$line" | jq -r '.host')"
  sig="$(echo "$line" | jq -r '.matched_signal // .signal')"
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
FP_LIST="$FP_DIR/known_fp.txt"
touch "$FP_LIST"

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
    -proxy "$PROXY_URL" \
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
      enriched="$(echo "$finding" | jq -c \
        --arg program "$program" \
        --arg platform "$platform" \
        --argjson pays "$pays" \
        --arg signal "$matched_signal" \
        '. + {scope: {program: $program, platform: $platform, pays: $pays}, matched_signal: $signal}')"
      echo "$enriched" >> "$CONFIRMED_FILE"

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

  curl -fsS -u "$ES_USER:$ES_PASS" -H 'Content-Type: application/json' \
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
  local hook="${DISCORD_KEV_WEBHOOK:-$DISCORD_WEBHOOK}"
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
  curl -fsS -m 10 -H 'Content-Type: application/json' \
    -X POST -d "$payload" "$hook" >/dev/null 2>&1 || true
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
  hook="${DISCORD_KEV_WEBHOOK:-$DISCORD_WEBHOOK}"
  [[ -n "$hook" ]] && curl -fsS -m 10 -H 'Content-Type: application/json' \
    -X POST -d "{\"content\":\"⚠️ Nuclei auto-disabled: $CONFIRMED_THIS_RUN findings in one run (likely false positive). Investigate before re-enabling.\"}" \
    "$hook" >/dev/null 2>&1 || true
fi

log "Nuclei cycle complete"

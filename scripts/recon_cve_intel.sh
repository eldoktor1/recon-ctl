#!/usr/bin/env bash
# =============================================================================
# recon_cve_intel.sh v2.1.1
#
# Fixes from v2.1:
#   1. NVD curl: %{http_code} returned concatenated codes (200000) on retries.
#      Now uses --no-keepalive + tail -n1 + tr/head to extract clean code.
#   2. KEV→ES match: was case-sensitive wildcard against capitalized "Jenkins".
#      Now uses case_insensitive: true (ES 7.10+).
#   3. SIG_TO_TECH: trimmed to terms that exist in real data, expanded coverage
#      to 37 signals (was 24).
#   4. kev_targets.jsonl deduped on host (was duplicating when one host had
#      multiple matching tech entries).
# =============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

log()  { printf '[%s CVE] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s CVE WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
die()  { printf '[%s CVE ERROR] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; exit 1; }

for c in curl jq python3; do command -v "$c" >/dev/null || die "missing: $c"; done
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/recon_net.sh"

CVE_DIR="${CVE_DIR:-$HOME/recon/cve}"
RAW_DIR="$CVE_DIR/raw"
KILL_FILE="$HOME/recon/state/kill/v2_cve"
LOCK_FILE="$HOME/recon/state/cve_intel.lock"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"
INDEX_NAME="${INDEX_NAME:-recon_alive}"
ES_USER="${ES_USER:-elastic}"
ES_PASS="${ES_PASS:-$(cat "$HOME/.recon_es_pass" 2>/dev/null)}"

mkdir -p "$CVE_DIR" "$RAW_DIR" "$(dirname "$LOCK_FILE")"

[[ -f "$KILL_FILE" ]] && { warn "killed: $(cat "$KILL_FILE")"; exit 0; }

exec 9>"$LOCK_FILE"
flock -n 9 || { log "already running"; exit 0; }

KEV_URL="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API="https://services.nvd.nist.gov/rest/json/cves/2.0"

# =============================================================================
# KEV catalog fetch
# =============================================================================
fetch_kev() {
  log "Fetching CISA KEV"
  if curl_net -fsSL -m 30 "$KEV_URL" -o "$CVE_DIR/kev.json.tmp"; then
    if jq -e '.vulnerabilities | length > 0' "$CVE_DIR/kev.json.tmp" >/dev/null 2>&1; then
      mv "$CVE_DIR/kev.json.tmp" "$CVE_DIR/kev.json"
      log "KEV: $(jq '.vulnerabilities | length' "$CVE_DIR/kev.json") CVEs"
    else
      warn "KEV response invalid"; rm -f "$CVE_DIR/kev.json.tmp"
    fi
  else
    warn "KEV fetch failed (will retry next cycle)"; rm -f "$CVE_DIR/kev.json.tmp"
  fi
}

# =============================================================================
# NVD fetch (FIXED — proper rate-limit pacing + retry)
#
# NVD limits: 5 requests / 30 seconds without API key.
# Strategy: 7s sleep between pages, 3 retries per page with exp backoff,
# and bail gracefully if first page fails (NVD is sometimes flaky).
# =============================================================================
fetch_nvd() {
  log "Fetching NVD recent CVEs (last 30d)"
  local pub_start pub_end
  pub_end="$(date -u +%Y-%m-%dT%H:%M:%S.000)"
  pub_start="$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%S.000 2>/dev/null \
              || date -u -v-30d +%Y-%m-%dT%H:%M:%S.000 2>/dev/null \
              || python3 -c 'import datetime; print((datetime.datetime.utcnow()-datetime.timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S.000"))')"

  local out="$CVE_DIR/nvd_recent.json.tmp"
  echo '{"vulnerabilities":[]}' > "$out"

  local start_idx=0 page_size=2000 total=0 pages=0 keep=true

  # Initial backoff before first call (NVD often 429s if hit cold)
  sleep 2

  while $keep; do
    pages=$((pages + 1))

    # Hard cap pages — if NVD is returning 30k+ CVEs in 30d, something's wrong
    if [[ "$pages" -gt 30 ]]; then
      warn "NVD: hit page cap (30), stopping"
      break
    fi

    local resp http_code attempt=0 ok=false
    while [[ "$attempt" -lt 3 ]]; do
      attempt=$((attempt + 1))
      # FIXED: -w '%{http_code}' returned concatenated codes when redirects happened.
      # Use --no-keepalive + only show http_code at end-of-final-request.
      # Also pipe stdin to avoid any inherited fd weirdness.
      http_code="$(curl_net -sS -G -m 60 \
        --no-keepalive \
        --output "$RAW_DIR/.nvd_page.json" \
        --write-out '%{http_code}\n' \
        --data-urlencode "pubStartDate=$pub_start" \
        --data-urlencode "pubEndDate=$pub_end" \
        --data-urlencode "startIndex=$start_idx" \
        --data-urlencode "resultsPerPage=$page_size" \
        "$NVD_API" 2>/dev/null </dev/null | tail -n1 | tr -dc '0-9' | head -c 3)"
      [[ -z "$http_code" ]] && http_code="000"

      if [[ "$http_code" == "200" ]]; then
        if jq -e '.vulnerabilities' "$RAW_DIR/.nvd_page.json" >/dev/null 2>&1; then
          ok=true; break
        fi
      elif [[ "$http_code" == "429" || "$http_code" == "503" ]]; then
        warn "NVD page $start_idx: HTTP $http_code (attempt $attempt) — backoff"
        sleep $((10 * attempt))
      else
        warn "NVD page $start_idx: HTTP $http_code (attempt $attempt)"
        sleep 5
      fi
    done

    if [[ "$ok" != true ]]; then
      warn "NVD page $start_idx failed after retries — aborting fetch"
      break
    fi

    local got
    got="$(jq '.vulnerabilities | length' "$RAW_DIR/.nvd_page.json")"
    total="$(jq '.totalResults // 0' "$RAW_DIR/.nvd_page.json")"

    # Merge into output (use slurpfile to avoid arg-list issues)
    jq --slurpfile new "$RAW_DIR/.nvd_page.json" \
      '.vulnerabilities += $new[0].vulnerabilities' "$out" > "${out}.merged"
    mv "${out}.merged" "$out"

    log "  NVD page $pages: +${got} (cumulative: $(jq '.vulnerabilities | length' "$out"))"

    start_idx=$((start_idx + page_size))
    [[ "$start_idx" -ge "$total" || "$got" -lt "$page_size" ]] && keep=false

    # Rate-limit polite (5/30s = 6s minimum, use 7s)
    $keep && sleep 7
  done

  rm -f "$RAW_DIR/.nvd_page.json"

  if jq -e '.vulnerabilities | length > 0' "$out" >/dev/null 2>&1; then
    mv "$out" "$CVE_DIR/nvd_recent.json"
    log "NVD: $(jq '.vulnerabilities | length' "$CVE_DIR/nvd_recent.json") CVEs"
  else
    warn "NVD result empty — keeping previous if exists"
    rm -f "$out"
  fi
}

# =============================================================================
# Build tech → CVE map (FIXED — pure python, no shell→jq arg-list issue)
# =============================================================================
build_tech_map() {
  log "Building tech → CVE map (python, file-based — no arg-list issues)"

  local kev_path="$CVE_DIR/kev.json"
  local nvd_path="$CVE_DIR/nvd_recent.json"
  local out_all="$CVE_DIR/all_cves.json"
  local out_map="$CVE_DIR/tech_cve_map.json"

  python3 - <<PYEOF
import json, datetime, pathlib, sys

CVE_DIR = pathlib.Path("${CVE_DIR}")
kev_path = CVE_DIR / "kev.json"
nvd_path = CVE_DIR / "nvd_recent.json"

# Load KEV
kev_list = []
if kev_path.exists():
    try:
        kev_list = json.loads(kev_path.read_text()).get("vulnerabilities", [])
    except Exception as e:
        print(f"  KEV load failed: {e}", file=sys.stderr)

kev_set = {v["cveID"] for v in kev_list if v.get("cveID")}

# Load NVD
nvd_list = []
if nvd_path.exists():
    try:
        nvd_list = json.loads(nvd_path.read_text()).get("vulnerabilities", [])
    except Exception as e:
        print(f"  NVD load failed: {e}", file=sys.stderr)

# Combine + de-duplicate
def get_cvss(c):
    metrics = c.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        m = metrics.get(key)
        if m and isinstance(m, list) and m:
            return m[0].get("cvssData", {}).get("baseScore", 0) or 0
    return 0

def get_desc(c):
    for d in c.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""

def get_product(c):
    try:
        return c.get("configurations", [{}])[0].get("nodes", [{}])[0].get("cpeMatch", [{}])[0].get("criteria", "")
    except Exception:
        return ""

all_cves = []

for v in kev_list:
    all_cves.append({
        "id": v.get("cveID", ""),
        "kev": True,
        "cvss": 9.8,  # KEV implies critical — assume high for scoring
        "product": v.get("product", ""),
        "vendor": v.get("vendorProject", ""),
        "description": v.get("shortDescription", ""),
        "published": v.get("dateAdded", ""),
        "ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
    })

for v in nvd_list:
    c = v.get("cve", {})
    cve_id = c.get("id", "")
    if not cve_id or cve_id in kev_set:
        continue  # skip dupes — already added from KEV
    all_cves.append({
        "id": cve_id,
        "kev": False,
        "cvss": get_cvss(c),
        "product": get_product(c),
        "vendor": "",
        "description": get_desc(c),
        "published": c.get("published", ""),
        "ransomware": "Unknown",
    })

(CVE_DIR / "all_cves.json").write_text(json.dumps(all_cves, indent=2))

# Tech keyword → triage signal mapping (matches triage.sh signals)
TECH_KEYWORDS = {
    "tech:jenkins":         ["jenkins"],
    "tech:teamcity":        ["teamcity"],
    "tech:gitlab":          ["gitlab"],
    "tech:gitea":           ["gitea", "gogs"],
    "tech:confluence":      ["confluence"],
    "tech:jira":            ["jira"],
    "tech:grafana":         ["grafana"],
    "tech:kibana":          ["kibana"],
    "tech:prometheus":      ["prometheus"],
    "tech:zabbix":          ["zabbix"],
    "tech:phpmyadmin":      ["phpmyadmin"],
    "tech:adminer":         ["adminer"],
    "tech:es-exposed":      ["elasticsearch"],
    "tech:minio":           ["minio"],
    "tech:docker-registry": ["docker registry", "docker_registry"],
    "tech:k8s-dashboard":   ["kubernetes", "kube-"],
    "tech:argocd":          ["argo cd", "argocd"],
    "tech:rancher":         ["rancher"],
    "tech:portainer":       ["portainer"],
    "tech:struts":          ["struts"],
    "tech:weblogic":        ["weblogic"],
    "tech:websphere":       ["websphere"],
    "tech:tomcat-manager":  ["tomcat"],
    "tech:coldfusion":      ["coldfusion"],
    "tech:thinkphp":        ["thinkphp"],
    "tech:citrix":          ["citrix", "netscaler"],
    "tech:fortinet":        ["fortinet", "fortios", "fortigate", "fortiweb"],
    "tech:ivanti-pulse":    ["ivanti", "pulse secure", "pulse connect"],
    "tech:vmware":          ["vmware", "vcenter", "vsphere", "esxi"],
    "tech:f5-bigip":        ["f5", "big-ip", "bigip"],
    "tech:paloalto":        ["palo alto", "pan-os", "globalprotect"],
    "tech:wordpress":       ["wordpress"],
    "tech:drupal":          ["drupal"],
    "tech:joomla":          ["joomla"],
    "tech:magento":         ["magento"],
    "tech:sitecore":        ["sitecore"],
    "tech:aem":             ["adobe experience manager", "aem"],
    "tech:liferay":         ["liferay"],
    "tech:laravel-debug":   ["laravel"],
    "tech:laravel-telescope":["telescope"],
    "tech:django-debug":    ["django"],
    "tech:spring-actuator": ["spring boot", "spring-boot", "actuator"],
    "tech:rails":           ["ruby on rails"],
    "tech:nextjs":          ["next.js", "nextjs"],
    "tech:graphql":         ["graphql"],
    "tech:swagger":         ["swagger"],
    "tech:manageengine":    ["manageengine", "servicedesk plus", "desktop central", "endpoint central"],
    "tech:solr":            ["apache solr"],
    "tech:airflow":         ["airflow"],
    "tech:moveit":          ["moveit"],
    "tech:nexus":           ["sonatype nexus", "nexus repository"],
    "tech:artifactory":     ["artifactory", "jfrog"],
    "tech:glpi":            ["glpi"],
    "tech:exchange-owa":    ["exchange server", "outlook web", "owa"],
}

def age_days(pub):
    if not pub:
        return 999
    try:
        d = datetime.datetime.fromisoformat(pub.replace("Z", "+00:00"))
        return (datetime.datetime.now(datetime.timezone.utc) - d).days
    except Exception:
        return 999

# Filter to high-relevance: KEV OR CVSS >= 7.0
filtered = [c for c in all_cves if c.get("kev") or (c.get("cvss") or 0) >= 7.0]

mapping = {sig: [] for sig in TECH_KEYWORDS}
for cve in filtered:
    text = " ".join([
        cve.get("description") or "",
        cve.get("product") or "",
        cve.get("vendor") or "",
    ]).lower()
    for sig, keywords in TECH_KEYWORDS.items():
        if any(kw in text for kw in keywords):
            mapping[sig].append({
                "id": cve["id"],
                "cvss": cve.get("cvss") or 0,
                "kev": cve.get("kev", False),
                "age_days": age_days(cve.get("published")),
                "ransomware": cve.get("ransomware", "Unknown"),
                "summary": (cve.get("description") or "")[:200],
            })

# Sort: KEV first, then CVSS desc, then newest first
for sig in mapping:
    mapping[sig].sort(key=lambda c: (not c["kev"], -c["cvss"], c["age_days"]))
    mapping[sig] = mapping[sig][:50]

(CVE_DIR / "tech_cve_map.json").write_text(json.dumps(mapping, indent=2))

total = sum(len(v) for v in mapping.values())
techs_with = sum(1 for v in mapping.values() if v)
kev_techs = sum(1 for v in mapping.values() if any(c["kev"] for c in v))
print(f"  tech_cve_map: {techs_with}/{len(mapping)} signals have CVEs")
print(f"  KEV-tagged signals: {kev_techs}")
print(f"  total CVE entries (across all signals): {total}")
PYEOF
}

# =============================================================================
# Match KEV CVEs against ES hosts
# =============================================================================
match_kev_targets() {
  log "Matching KEV CVEs against indexed hosts"
  [[ -s "$CVE_DIR/tech_cve_map.json" ]] || { warn "tech_cve_map missing"; return 1; }

  # Find tech signals with at least one KEV CVE
  local kev_techs
  kev_techs="$(jq -r 'to_entries | map(select(.value | any(.kev == true))) | map(.key) | .[]' \
              "$CVE_DIR/tech_cve_map.json")"

  if [[ -z "$kev_techs" ]]; then
    log "No tech signals have KEV CVEs"
    : > "$CVE_DIR/kev_targets.jsonl"
    return 0
  fi

  # Tech terms verified against actual ES data (case-insensitive substring match).
  # Filtered out terms that don't exist in user's ES (cassandra, etc.).
  # Order matters for first-match — high-value KEV-prone tech first.
  declare -A SIG_TO_TECH=(
    [tech:jenkins]=jenkins
    [tech:gitlab]=gitlab
    [tech:confluence]=confluence
    [tech:jira]=jira
    [tech:grafana]=grafana
    [tech:kibana]=kibana
    [tech:struts]=struts
    [tech:weblogic]=weblogic
    [tech:websphere]=websphere
    [tech:citrix]=citrix
    [tech:fortinet]=fortinet
    [tech:vmware]=vmware
    [tech:f5-bigip]="big-ip"
    [tech:paloalto]="palo alto"
    [tech:exchange-owa]=exchange
    [tech:moveit]=moveit
    [tech:manageengine]=manageengine
    [tech:wordpress]=wordpress
    [tech:drupal]=drupal
    [tech:magento]=magento
    [tech:spring-actuator]=spring
    [tech:ivanti-pulse]=ivanti
    [tech:thinkphp]=thinkphp
    [tech:coldfusion]=coldfusion
    [tech:airflow]=airflow
    [tech:laravel-debug]=laravel
    [tech:tomcat-manager]=tomcat
    [tech:zabbix]=zabbix
    [tech:solr]=solr
    [tech:phpmyadmin]=phpmyadmin
    [tech:nexus]=nexus
    [tech:joomla]=joomla
    [tech:aem]="adobe experience manager"
    [tech:liferay]=liferay
    [tech:argocd]=argocd
    [tech:portainer]=portainer
    [tech:rancher]=rancher
  )

  : > "$CVE_DIR/kev_targets.jsonl"

  for sig in $kev_techs; do
    tech_term="${SIG_TO_TECH[$sig]:-}"
    [[ -z "$tech_term" ]] && continue

    local cves_for_sig
    cves_for_sig="$(jq -c --arg s "$sig" '.[$s] | map(select(.kev == true))' \
                  "$CVE_DIR/tech_cve_map.json")"

    local query
    # FIXED v2.1.1: case_insensitive: true — ES tech values are capitalized
    # (e.g. "Jenkins", "Microsoft SharePoint") but our terms are lowercase.
    # Without this, every match returned 0.
    # Also: size 5000 (was 1000) since some tech has many hosts.
    query="$(jq -n --arg tech "$tech_term" '{
      size: 5000,
      _source: ["host","url","tech","status_code","port","title","root_domain"],
      query: { bool: { filter: [
        {wildcard: {tech: {value: ("*" + $tech + "*"), case_insensitive: true}}}
      ] } }
    }')"

    local resp
    resp="$(curl -sS -u "$ES_USER:$ES_PASS" -H 'Content-Type: application/json' \
           -X POST "$ES_URL/$INDEX_NAME/_search" -d "$query" 2>/dev/null)" || continue

    echo "$resp" | jq -c --argjson cves "$cves_for_sig" --arg sig "$sig" '
      .hits.hits[]._source | . + {matched_signal: $sig, matched_cves: $cves}
    ' >> "$CVE_DIR/kev_targets.jsonl" 2>/dev/null || true
  done

  log "KEV targets (raw): $(wc -l < "$CVE_DIR/kev_targets.jsonl") matches"

  # Dedupe by host — keep first occurrence (signals processed in declared order,
  # so highest-priority tech gets retained when one host matches multiple).
  if [[ -s "$CVE_DIR/kev_targets.jsonl" ]]; then
    awk '!seen[$0]' "$CVE_DIR/kev_targets.jsonl" \
      | jq -s 'unique_by(.host) | .[]' -c > "$CVE_DIR/kev_targets.jsonl.tmp"
    mv "$CVE_DIR/kev_targets.jsonl.tmp" "$CVE_DIR/kev_targets.jsonl"
    log "KEV targets (deduped): $(wc -l < "$CVE_DIR/kev_targets.jsonl") unique hosts"
  fi
}

# =============================================================================
# Main
# =============================================================================
case "${1:-all}" in
  kev)   fetch_kev; build_tech_map; match_kev_targets ;;
  nvd)   fetch_nvd; build_tech_map ;;
  map)   build_tech_map ;;
  match) match_kev_targets ;;
  all|*) fetch_kev; fetch_nvd; build_tech_map; match_kev_targets ;;
esac

log "CVE intel cycle complete"

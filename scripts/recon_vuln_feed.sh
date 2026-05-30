#!/usr/bin/env bash
# =============================================================================
# recon_vuln_feed.sh
#
# Passive "fresh vuln race" intelligence layer.
#
# This does not scan targets. It normalizes vulnerability intelligence from
# several sources, then matches that intelligence against already-indexed ES
# assets using local tech fingerprints. The output becomes a fast review queue
# for safe verification after normal scope/scoring.
# =============================================================================
set -Eeuo pipefail
IFS=$'\n\t'

log()  { printf '[%s VULN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s VULN WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
die()  { printf '[%s VULN ERROR] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; exit 1; }

for c in curl jq python3; do command -v "$c" >/dev/null || die "missing: $c"; done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/recon_net.sh"

BASE_DIR="${BASE_DIR:-$HOME/recon}"
CVE_DIR="${CVE_DIR:-$BASE_DIR/cve}"
VULN_DIR="${VULN_DIR:-$BASE_DIR/vuln}"
RAW_DIR="$VULN_DIR/raw"
STATE_DIR="$BASE_DIR/state"
LOCK_FILE="$STATE_DIR/vuln_feed.lock"
KILL_FILE="$STATE_DIR/kill/v2_vuln_feed"

ES_URL="${ES_URL:-http://127.0.0.1:9200}"
INDEX_NAME="${INDEX_NAME:-recon_alive}"
setup_es_netrc
ES_AUTH=(--netrc-file "$HOME/.recon_es_netrc")
RECON_OWNER_USER="${RECON_OWNER_USER:-d0k}"

FEED_JSONL="$VULN_DIR/vuln_feed.jsonl"
TARGETS_JSONL="$VULN_DIR/vuln_targets.jsonl"
SUMMARY_JSON="$VULN_DIR/summary.json"

EPSS_URL="${EPSS_URL:-https://epss.empiricalsecurity.com/epss_scores-current.csv.gz}"
NUCLEI_CVES_URL="${NUCLEI_CVES_URL:-https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json}"
NUCLEI_RELEASES_URL="${NUCLEI_RELEASES_URL:-https://api.github.com/repos/projectdiscovery/nuclei-templates/releases/latest}"
VULNRICHMENT_COMMITS_URL="${VULNRICHMENT_COMMITS_URL:-https://api.github.com/repos/cisagov/vulnrichment/commits?per_page=100}"
# GitHub Security Advisories GraphQL — free, no token needed for public advisories.
# Returns the 100 most recently published critical/high advisories with PoC availability.
GHSA_URL="${GHSA_URL:-https://api.github.com/advisories?per_page=100&sort=published&direction=desc&severity=critical,high}"

mkdir -p "$VULN_DIR" "$RAW_DIR" "$STATE_DIR" "$STATE_DIR/kill"

grant_owner_access() {
  command -v setfacl >/dev/null 2>&1 || return 0
  id "$RECON_OWNER_USER" >/dev/null 2>&1 || return 0
  setfacl -m "u:${RECON_OWNER_USER}:rwx" -m "d:u:${RECON_OWNER_USER}:rwx" "$VULN_DIR" "$RAW_DIR" 2>/dev/null || true
  local f
  for f in "$FEED_JSONL" "$TARGETS_JSONL" "$SUMMARY_JSON"; do
    [[ -e "$f" ]] && setfacl -m "u:${RECON_OWNER_USER}:rw-" "$f" 2>/dev/null || true
  done
}

[[ -f "$KILL_FILE" ]] && { warn "vuln feed killed: $(cat "$KILL_FILE")"; exit 0; }

exec 9>"$LOCK_FILE"
flock -n 9 || { log "already running"; exit 0; }

fetch_optional() {
  local name="$1" url="$2" out="$3"
  log "Fetching $name"
  if curl_net -fsSL -m 60 "$url" -o "${out}.tmp"; then
    mv "${out}.tmp" "$out"
    log "  ok $name"
  else
    warn "  failed $name; keeping previous if present"
    rm -f "${out}.tmp"
  fi
}

fetch_feeds() {
  fetch_optional "EPSS current" "$EPSS_URL" "$RAW_DIR/epss_scores-current.csv.gz"
  fetch_optional "ProjectDiscovery nuclei CVE index" "$NUCLEI_CVES_URL" "$RAW_DIR/nuclei_cves.json"
  fetch_optional "ProjectDiscovery latest release" "$NUCLEI_RELEASES_URL" "$RAW_DIR/nuclei_latest_release.json"
  fetch_optional "CISA Vulnrichment recent commits" "$VULNRICHMENT_COMMITS_URL" "$RAW_DIR/vulnrichment_commits.json"
  fetch_optional "GitHub Security Advisories (critical+high)" "$GHSA_URL" "$RAW_DIR/ghsa_recent.json"
}

normalize_feed() {
  log "Normalizing vulnerability feed"
  python3 - "$CVE_DIR" "$RAW_DIR" "$FEED_JSONL" "$SUMMARY_JSON" <<'PYEOF'
import csv
import gzip
import json
import pathlib
import re
import sys
from datetime import datetime, timezone

cve_dir = pathlib.Path(sys.argv[1])
raw_dir = pathlib.Path(sys.argv[2])
feed_out = pathlib.Path(sys.argv[3])
summary_out = pathlib.Path(sys.argv[4])

now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def load_json(path, default):
    try:
        if path.exists() and path.stat().st_size:
            return json.loads(path.read_text(errors="replace"))
    except Exception:
        return default
    return default

def cve_id_from_text(text):
    if not text:
        return None
    m = re.search(r"CVE-\d{4}-\d{4,}", text, re.I)
    return m.group(0).upper() if m else None

def age_days(value):
    if not value:
        return 9999
    try:
        v = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(v)
        if not dt.tzinfo:
            dt = dt.replace(tzinfo=timezone.utc)
        return max(0, (datetime.now(timezone.utc) - dt).days)
    except Exception:
        return 9999

def cvss_from_nvd(cve):
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        vals = metrics.get(key)
        if isinstance(vals, list) and vals:
            data = vals[0].get("cvssData", {})
            score = data.get("baseScore")
            if isinstance(score, (int, float)):
                return float(score)
    return 0.0

def desc_from_nvd(cve):
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""

def product_from_nvd(cve):
    parts = []
    for cfg in cve.get("configurations", []) or []:
        for node in cfg.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or []:
                criteria = match.get("criteria") or ""
                fields = criteria.split(":")
                if len(fields) > 5:
                    vendor = fields[3].replace("_", " ")
                    product = fields[4].replace("_", " ")
                    if vendor not in ("*", "-") or product not in ("*", "-"):
                        parts.append(" ".join([vendor, product]).strip())
    return sorted(set(p for p in parts if p))[:8]

def severity(score):
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"

def default_record(cve_id):
    return {
        "id": cve_id,
        "sources": [],
        "source_count": 0,
        "kev": False,
        "epss": None,
        "epss_percentile": None,
        "cvss": 0.0,
        "severity": "unknown",
        "title": "",
        "summary": "",
        "vendor": "",
        "product": "",
        "products": [],
        "published": "",
        "modified": "",
        "template_available": False,
        "template_ids": [],
        "template_tags": [],
        "vulnrichment_recent": False,
        "risk_tier": "T3",
        "race_reason": "",
        "normalized_at": now,
    }

records = {}

def get(cve_id):
    cve_id = cve_id.upper()
    records.setdefault(cve_id, default_record(cve_id))
    return records[cve_id]

def add_source(rec, source):
    if source not in rec["sources"]:
        rec["sources"].append(source)
        rec["source_count"] = len(rec["sources"])

# Existing KEV and NVD outputs are treated as first-class inputs so this layer
# improves the current pipeline instead of replacing it.
kev = load_json(cve_dir / "kev.json", {}).get("vulnerabilities", [])
for v in kev:
    cid = v.get("cveID")
    if not cid:
        continue
    rec = get(cid)
    add_source(rec, "cisa_kev")
    rec["kev"] = True
    rec["cvss"] = max(float(rec.get("cvss") or 0), 9.8)
    rec["severity"] = severity(rec["cvss"])
    rec["vendor"] = rec["vendor"] or v.get("vendorProject", "")
    rec["product"] = rec["product"] or v.get("product", "")
    rec["products"] = sorted(set(rec["products"] + [p for p in [rec["vendor"], rec["product"], f'{rec["vendor"]} {rec["product"]}'.strip()] if p]))
    rec["summary"] = rec["summary"] or v.get("shortDescription", "")
    rec["title"] = rec["title"] or rec["summary"][:120]
    rec["published"] = rec["published"] or v.get("dateAdded", "")

nvd = load_json(cve_dir / "nvd_recent.json", {}).get("vulnerabilities", [])
for item in nvd:
    cve = item.get("cve", {})
    cid = cve.get("id")
    if not cid:
        continue
    rec = get(cid)
    add_source(rec, "nvd_recent")
    score = cvss_from_nvd(cve)
    if score > (rec.get("cvss") or 0):
        rec["cvss"] = score
        rec["severity"] = severity(score)
    rec["summary"] = rec["summary"] or desc_from_nvd(cve)
    rec["title"] = rec["title"] or rec["summary"][:120]
    rec["published"] = rec["published"] or cve.get("published", "")
    rec["modified"] = rec["modified"] or cve.get("lastModified", "")
    products = product_from_nvd(cve)
    rec["products"] = sorted(set(rec["products"] + products))
    if not rec["product"] and products:
        rec["product"] = products[0]

# EPSS is intentionally joined locally. High EPSS on a weakly enriched CVE is
# the key transcript-driven signal that keeps us from waiting on NVD metadata.
epss_path = raw_dir / "epss_scores-current.csv.gz"
if epss_path.exists():
    try:
        with gzip.open(epss_path, "rt", newline="") as fh:
            for row in csv.DictReader(filter(lambda line: not line.startswith("#"), fh)):
                cid = (row.get("cve") or "").upper()
                if not cid.startswith("CVE-"):
                    continue
                if cid not in records:
                    continue
                rec = get(cid)
                add_source(rec, "epss")
                try:
                    rec["epss"] = float(row.get("epss") or 0)
                    rec["epss_percentile"] = float(row.get("percentile") or 0)
                except Exception:
                    pass
    except Exception as e:
        print(f"EPSS parse failed: {e}", file=sys.stderr)

nuclei_cves = load_json(raw_dir / "nuclei_cves.json", {})
def walk_templates(obj):
    if isinstance(obj, dict):
        maybe_id = cve_id_from_text(" ".join(str(v) for v in obj.values() if isinstance(v, (str, int, float))))
        if maybe_id:
            yield maybe_id, obj
        for value in obj.values():
            yield from walk_templates(value)
    elif isinstance(obj, list):
        for item in obj:
            yield from walk_templates(item)

for cid, obj in walk_templates(nuclei_cves):
    rec = get(cid)
    add_source(rec, "nuclei_templates")
    rec["template_available"] = True
    template_id = obj.get("id") or obj.get("template-id") or obj.get("path") or obj.get("template")
    if template_id and str(template_id) not in rec["template_ids"]:
        rec["template_ids"].append(str(template_id))
    tags = obj.get("tags")
    if isinstance(tags, str):
        rec["template_tags"] = sorted(set(rec["template_tags"] + [t.strip() for t in tags.split(",") if t.strip()]))
    elif isinstance(tags, list):
        rec["template_tags"] = sorted(set(rec["template_tags"] + [str(t) for t in tags]))

release = load_json(raw_dir / "nuclei_latest_release.json", {})
release_text = "\n".join([release.get("name") or "", release.get("body") or ""])
for cid in sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", release_text, re.I))):
    rec = get(cid.upper())
    add_source(rec, "nuclei_latest_release")
    rec["template_available"] = True

commits = load_json(raw_dir / "vulnrichment_commits.json", [])
for c in commits if isinstance(commits, list) else []:
    msg = ((c.get("commit") or {}).get("message") or "")
    cid = cve_id_from_text(msg)
    if not cid:
        continue
    rec = get(cid)
    add_source(rec, "cisa_vulnrichment_recent")
    rec["vulnrichment_recent"] = True

# GitHub Security Advisories — provides PoC signal (references[] with exploit URLs)
# and frequently publishes before NVD completes enrichment, giving us a head start.
ghsa = load_json(raw_dir / "ghsa_recent.json", [])
if isinstance(ghsa, list):
    for advisory in ghsa:
        cids = [c for c in (advisory.get("cve_id") or "").split(",") if c.strip()]
        # GHSA advisories may also embed CVEs in identifiers[]
        for ident in advisory.get("identifiers") or []:
            if ident.get("type") == "CVE" and ident.get("value"):
                cids.append(ident["value"].strip())
        cids = [c for c in set(cids) if re.match(r"CVE-\d{4}-\d+", c, re.I)]
        for cid in cids:
            rec = get(cid.upper())
            add_source(rec, "github_advisory")
            # GHSA severity → CVSS floor if we don't have one
            ghsa_sev = (advisory.get("severity") or "").lower()
            if not rec.get("cvss") or rec["cvss"] == 0:
                rec["cvss"] = {"critical": 9.0, "high": 7.5, "medium": 5.0, "low": 2.0}.get(ghsa_sev, 0)
                rec["severity"] = severity(rec["cvss"])
            rec["title"] = rec["title"] or (advisory.get("summary") or "")[:120]
            rec["summary"] = rec["summary"] or (advisory.get("description") or "")[:500]
            rec["published"] = rec["published"] or (advisory.get("published_at") or "")
            # Check references for PoC/exploit indicators
            refs = advisory.get("references") or []
            poc_keywords = ("poc", "exploit", "proof-of-concept", "metasploit", "exploit-db", "edb.id")
            has_poc = any(any(kw in (r if isinstance(r, str) else "").lower() for kw in poc_keywords) for r in refs)
            if has_poc:
                rec["template_available"] = True  # treat known PoC as equivalent signal
                add_source(rec, "github_advisory_poc")

def infer_match_text(rec):
    parts = []
    parts.extend(rec.get("products") or [])
    parts.append(rec.get("vendor") or "")
    parts.append(rec.get("product") or "")
    parts.append(rec.get("title") or "")
    parts.append(rec.get("summary") or "")
    return " ".join(parts).lower()

TECH_ALIASES = {
    "tech:jenkins": ["jenkins"],
    "tech:teamcity": ["teamcity"],
    "tech:gitlab": ["gitlab"],
    "tech:gitea": ["gitea", "gogs"],
    "tech:confluence": ["confluence", "atlassian confluence"],
    "tech:jira": ["jira", "atlassian jira"],
    "tech:grafana": ["grafana"],
    "tech:kibana": ["kibana"],
    "tech:prometheus": ["prometheus"],
    "tech:zabbix": ["zabbix"],
    "tech:phpmyadmin": ["phpmyadmin", "phpmyadmin"],
    "tech:adminer": ["adminer"],
    "tech:es-exposed": ["elasticsearch", "elastic search"],
    "tech:minio": ["minio"],
    "tech:docker-registry": ["docker registry"],
    "tech:k8s-dashboard": ["kubernetes dashboard", "kubernetes"],
    "tech:argocd": ["argocd", "argo cd"],
    "tech:rancher": ["rancher"],
    "tech:portainer": ["portainer"],
    "tech:struts": ["struts", "apache struts"],
    "tech:weblogic": ["weblogic", "oracle weblogic"],
    "tech:websphere": ["websphere", "ibm websphere"],
    "tech:tomcat-manager": ["tomcat", "apache tomcat"],
    "tech:coldfusion": ["coldfusion", "cold fusion"],
    "tech:thinkphp": ["thinkphp"],
    "tech:citrix": ["citrix", "netscaler", "adc gateway"],
    "tech:fortinet": ["fortinet", "fortios", "fortigate", "fortiweb", "fortisandbox"],
    "tech:ivanti-pulse": ["ivanti", "pulse secure", "connect secure"],
    "tech:vmware": ["vmware", "vcenter", "vsphere", "esxi"],
    "tech:f5-bigip": ["f5", "big-ip", "bigip"],
    "tech:paloalto": ["palo alto", "pan-os", "globalprotect"],
    "tech:wordpress": ["wordpress"],
    "tech:drupal": ["drupal"],
    "tech:joomla": ["joomla"],
    "tech:magento": ["magento", "adobe commerce"],
    "tech:sitecore": ["sitecore"],
    "tech:aem": ["adobe experience manager", "aem"],
    "tech:liferay": ["liferay"],
    "tech:laravel-debug": ["laravel"],
    "tech:django-debug": ["django"],
    "tech:spring-actuator": ["spring boot", "spring framework"],
    "tech:rails": ["ruby on rails", "rails"],
    "tech:nextjs": ["next.js", "nextjs"],
    "tech:manageengine": ["manageengine", "servicedesk plus", "desktop central", "endpoint central"],
    "tech:solr": ["apache solr", "solr"],
    "tech:airflow": ["airflow", "apache airflow"],
    "tech:moveit": ["moveit"],
    "tech:nexus": ["sonatype nexus", "nexus repository"],
    "tech:artifactory": ["artifactory", "jfrog"],
    "tech:glpi": ["glpi"],
    "tech:exchange-owa": ["exchange server", "outlook web", "owa"],
    "tech:activemq": ["activemq", "active mq"],
    "tech:sharepoint": ["sharepoint", "microsoft sharepoint"],
    "tech:vite": ["vite"],
}

for rec in records.values():
    text = infer_match_text(rec)
    signals = []
    for sig, aliases in TECH_ALIASES.items():
        if any(alias in text for alias in aliases):
            signals.append(sig)
    rec["match_signals"] = sorted(set(signals))

    epss = rec.get("epss") or 0
    cvss = rec.get("cvss") or 0
    fresh = age_days(rec.get("published")) <= 14 or rec.get("vulnrichment_recent")
    if rec.get("kev"):
        rec["risk_tier"] = "T0"
        rec["race_reason"] = "CISA KEV; prioritize only when scoped asset evidence is strong"
    elif rec.get("template_available") and (epss >= 0.05 or cvss >= 9 or fresh):
        rec["risk_tier"] = "T1"
        rec["race_reason"] = "Fresh/public template or high-confidence public check exists"
    elif fresh or epss >= 0.02 or cvss >= 8:
        rec["risk_tier"] = "T2"
        rec["race_reason"] = "Fresh or high-risk advisory before complete enrichment"
    else:
        rec["risk_tier"] = "T3"
        rec["race_reason"] = "Weak or slow-lane signal; report-only until stronger evidence"

ordered = sorted(
    records.values(),
    key=lambda r: (
        {"T0": 0, "T1": 1, "T2": 2, "T3": 3}.get(r.get("risk_tier"), 9),
        -(r.get("epss") or 0),
        -(r.get("cvss") or 0),
        age_days(r.get("published")),
        r.get("id", ""),
    ),
)

feed_out.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in ordered))

summary = {
    "normalized_at": now,
    "total": len(ordered),
    "tiers": {},
    "sources": {},
    "template_available": sum(1 for r in ordered if r.get("template_available")),
    "with_match_signals": sum(1 for r in ordered if r.get("match_signals")),
}
for r in ordered:
    summary["tiers"][r.get("risk_tier", "unknown")] = summary["tiers"].get(r.get("risk_tier", "unknown"), 0) + 1
    for s in r.get("sources") or []:
        summary["sources"][s] = summary["sources"].get(s, 0) + 1
summary_out.write_text(json.dumps(summary, indent=2, sort_keys=True))

print(f"normalized={len(ordered)} template_available={summary['template_available']} with_match_signals={summary['with_match_signals']}")
print("tiers=" + ",".join(f"{k}:{v}" for k, v in sorted(summary["tiers"].items())))
PYEOF
  grant_owner_access
}

match_assets() {
  log "Matching normalized vuln feed against ES assets"
  [[ -s "$FEED_JSONL" ]] || { warn "feed missing: $FEED_JSONL"; return 0; }

  local count_resp doc_count
  count_resp="$(curl -fsS -m 10 "${ES_AUTH[@]}" "$ES_URL/$INDEX_NAME/_count" 2>/dev/null || true)"
  doc_count="$(jq -r '.count // 0' 2>/dev/null <<<"$count_resp" || echo 0)"
  if [[ "${doc_count:-0}" -eq 0 ]]; then
    warn "ES index $INDEX_NAME is empty; writing empty target queue"
    : > "$TARGETS_JSONL"
    return 0
  fi

  local sigs_file="$RAW_DIR/match_signals.txt"
  jq -r 'select(.risk_tier != "T3") | .match_signals[]?' "$FEED_JSONL" | sort -u > "$sigs_file"
  : > "$TARGETS_JSONL.tmp"

  while IFS= read -r sig; do
    [[ -n "$sig" ]] || continue
    local term
    case "$sig" in
      tech:jenkins) term="jenkins" ;;
      tech:teamcity) term="teamcity" ;;
      tech:gitlab) term="gitlab" ;;
      tech:gitea) term="gitea" ;;
      tech:confluence) term="confluence" ;;
      tech:jira) term="jira" ;;
      tech:grafana) term="grafana" ;;
      tech:kibana) term="kibana" ;;
      tech:prometheus) term="prometheus" ;;
      tech:zabbix) term="zabbix" ;;
      tech:phpmyadmin) term="phpmyadmin" ;;
      tech:adminer) term="adminer" ;;
      tech:es-exposed) term="elasticsearch" ;;
      tech:minio) term="minio" ;;
      tech:docker-registry) term="docker registry" ;;
      tech:k8s-dashboard) term="kubernetes" ;;
      tech:argocd) term="argocd" ;;
      tech:rancher) term="rancher" ;;
      tech:portainer) term="portainer" ;;
      tech:struts) term="struts" ;;
      tech:weblogic) term="weblogic" ;;
      tech:websphere) term="websphere" ;;
      tech:tomcat-manager) term="tomcat" ;;
      tech:coldfusion) term="coldfusion" ;;
      tech:thinkphp) term="thinkphp" ;;
      tech:citrix) term="citrix" ;;
      tech:fortinet) term="fortinet" ;;
      tech:ivanti-pulse) term="ivanti" ;;
      tech:vmware) term="vmware" ;;
      tech:f5-bigip) term="big-ip" ;;
      tech:paloalto) term="palo alto" ;;
      tech:wordpress) term="wordpress" ;;
      tech:drupal) term="drupal" ;;
      tech:joomla) term="joomla" ;;
      tech:magento) term="magento" ;;
      tech:sitecore) term="sitecore" ;;
      tech:aem) term="adobe experience manager" ;;
      tech:liferay) term="liferay" ;;
      tech:laravel-debug) term="laravel" ;;
      tech:django-debug) term="django" ;;
      tech:spring-actuator) term="spring" ;;
      tech:rails) term="rails" ;;
      tech:nextjs) term="next" ;;
      tech:manageengine) term="manageengine" ;;
      tech:solr) term="solr" ;;
      tech:airflow) term="airflow" ;;
      tech:moveit) term="moveit" ;;
      tech:nexus) term="nexus" ;;
      tech:artifactory) term="artifactory" ;;
      tech:glpi) term="glpi" ;;
      tech:exchange-owa) term="exchange" ;;
      tech:activemq) term="activemq" ;;
      tech:sharepoint) term="sharepoint" ;;
      tech:vite) term="vite" ;;
      *) continue ;;
    esac

    local vulns query resp
    vulns="$(jq -c --arg sig "$sig" 'select(.risk_tier != "T3" and ((.match_signals // []) | index($sig)))' "$FEED_JSONL" | jq -s 'sort_by({T0:0,T1:1,T2:2,T3:3}[.risk_tier] // 9, -(.epss // 0), -(.cvss // 0)) | .[:20]')"
    query="$(jq -n --arg tech "$term" '{
      size: 1000,
      _source: ["host","url","tech","status_code","port","title","root_domain","triage_pays","triage_payout_tier","triage_in_scope","triage_out_of_scope","triage_score","triage_priority"],
      query: { bool: { filter: [
        {wildcard: {tech: {value: ("*" + $tech + "*"), case_insensitive: true}}}
      ] } }
    }')"
    resp="$(curl -sS -m 30 "${ES_AUTH[@]}" -H 'Content-Type: application/json' -X POST "$ES_URL/$INDEX_NAME/_search" -d "$query" 2>/dev/null || true)"
    jq -c --arg sig "$sig" --argjson vulns "$vulns" '
      .hits.hits[]._source
      | . + {
          matched_signal: $sig,
          matched_vulns: $vulns,
          best_vuln_tier: (($vulns[0].risk_tier) // "T3"),
          best_vuln_id: (($vulns[0].id) // null),
          matched_at: (now | strftime("%Y-%m-%dT%H:%M:%SZ"))
        }
    ' <<<"$resp" >> "$TARGETS_JSONL.tmp" 2>/dev/null || true
  done < "$sigs_file"

  if [[ -s "$TARGETS_JSONL.tmp" ]]; then
    jq -s 'unique_by(.host + "|" + .matched_signal) | sort_by({T0:0,T1:1,T2:2,T3:3}[.best_vuln_tier] // 9, -(.triage_score // 0)) | .[]' -c \
      "$TARGETS_JSONL.tmp" > "$TARGETS_JSONL"
  else
    : > "$TARGETS_JSONL"
  fi
  rm -f "$TARGETS_JSONL.tmp"
  grant_owner_access
  log "Vuln asset matches: $(wc -l < "$TARGETS_JSONL" | tr -d ' ')"
}

status() {
  log "===== Vuln feed status ====="
  if [[ -s "$SUMMARY_JSON" ]]; then
    jq -r '
      "normalized_at: \(.normalized_at)",
      "total: \(.total)",
      "tiers: " + ((.tiers // {}) | to_entries | map(.key + "=" + (.value|tostring)) | join(" ")),
      "sources: " + ((.sources // {}) | to_entries | map(.key + "=" + (.value|tostring)) | join(" ")),
      "template_available: \(.template_available)",
      "with_match_signals: \(.with_match_signals)"
    ' "$SUMMARY_JSON"
  else
    warn "no summary yet"
  fi

  if [[ -s "$TARGETS_JSONL" ]]; then
    log "targets: $(wc -l < "$TARGETS_JSONL" | tr -d ' ') matches"
    jq -sr '.[:15][] | [.best_vuln_tier,.best_vuln_id,.triage_payout_tier,.triage_score,.host,.matched_signal] | @tsv' "$TARGETS_JSONL" 2>/dev/null || true
  else
    warn "targets: no vuln_targets.jsonl yet"
  fi
}

case "${1:-all}" in
  fetch) fetch_feeds ;;
  normalize) normalize_feed ;;
  match) match_assets ;;
  status) status ;;
  all|*) fetch_feeds; normalize_feed; match_assets; status ;;
esac

log "Vuln feed cycle complete"

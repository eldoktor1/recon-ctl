#!/usr/bin/env python3
"""
recon_ndayrace.py — race the window between "a detection exists" and "everyone has run it".

The old n-day lane matched a TECH CLASS to a CVE ("this host runs Spring, Spring has CVEs")
and produced nothing, because a tech-class match is not a vulnerability and every scanner
reports it. This lane races something real instead.

WHY NEW NUCLEI TEMPLATES ARE THE BEST FRESHNESS SIGNAL AVAILABLE:
A template appearing in the repository is not chatter — it is *code somebody wrote because
something is being exploited*, timestamped to the commit. Compare the alternatives: asking a
language model "what is trending" invents CVE ids (this pipeline's own doctrine already warns
about that), and a vendor advisory tells you a bug exists without telling you how to see it.
A template is authoritative, machine-readable, and arrives within hours of disclosure.

The money is in the gap between that commit and the moment every hunter has scanned their
estate with it. That gap is hours to days, and a daemon that pulls hourly is inside it while
its operator is at work.

    git diff since last run -> NEW CVE templates
      -> which of OUR in-scope hosts run that technology?
        -> is the template SAFE to fire unattended?
          -> fire it at only those hosts
            -> a match is the finding

TEMPLATE SAFETY (hard gate — the doctrine's template-safety rule, enforced in code):
We read every template body before firing it. Anything that executes code, reads files,
harvests cloud metadata, writes, or brute-forces is REFUSED regardless of how attractive the
CVE is. Only read-only matchers and OOB canaries run unattended. Destructive-capable
templates are listed in the report for the operator to run deliberately, never by the daemon.

KEV enrichment: a CVE in CISA's Known Exploited Vulnerabilities catalogue is being used in
the wild right now — those go first.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone

BASE_DIR = os.environ.get("BASE_DIR", os.path.expanduser("~/recon"))
STATE_DIR = os.environ.get("STATE_DIR", os.path.join(BASE_DIR, "state"))
REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATES = os.environ.get("NUCLEI_TEMPLATES_DIR", os.path.expanduser("~/nuclei-templates"))
CURSOR = os.path.join(STATE_DIR, "ndayrace_cursor.json")
AUDIT = os.path.join(STATE_DIR, "ndayrace_audit.jsonl")
KEV_CACHE = os.path.join(STATE_DIR, "kev_catalog.json")
OUT_DIR = os.path.join(BASE_DIR, "briefings")
ES = os.environ.get("ES_URL", "http://127.0.0.1:9200")
IDX = os.environ.get("INDEX_NAME", "recon_alive")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# --- template safety --------------------------------------------------------
# Anything here means the template can do more than LOOK. Never fired unattended.
UNSAFE = [
    (re.compile(r"^\s*-?\s*(code|javascript)\s*:", re.M | re.I), "executes code"),
    (re.compile(r"\b(exec|cmd|command|payload)\s*:\s*\|", re.I), "runs a command payload"),
    (re.compile(r"(file:///|/etc/passwd|/etc/shadow|win\.ini|boot\.ini)", re.I), "reads local files"),
    (re.compile(r"(169\.254\.169\.254|metadata\.google|/latest/meta-data)", re.I), "harvests cloud metadata"),
    (re.compile(r"^\s*method\s*:\s*(PUT|POST|DELETE|PATCH)\s*$", re.M | re.I), "writes / changes state"),
    (re.compile(r"\battack\s*:\s*(clusterbomb|pitchfork|batteringram)\b", re.I), "brute-forces"),
    (re.compile(r"\b(fuzz|wordlist|payloads)\s*:", re.I), "fuzzes with a wordlist"),
    (re.compile(r"\b(rce|command-injection|sqli-dump|deserialization)\b", re.I), "tagged as an exploitation primitive"),
]
SAFE_HINT = re.compile(r"\b(detect|detection|exposure|disclosure|misconfig|default-login|panel)\b", re.I)


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(m: str) -> None:
    print(f"[nday] {m}", file=sys.stderr, flush=True)


def audit(rec: dict) -> None:
    os.makedirs(STATE_DIR, exist_ok=True)
    rec.setdefault("at", utc())
    with open(AUDIT, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")


def git(*args: str) -> str:
    try:
        return subprocess.run(["git", "-C", TEMPLATES, *args], capture_output=True,
                              text=True, timeout=600).stdout.strip()
    except Exception:
        return ""


def load_cursor() -> str:
    try:
        return json.load(open(CURSOR)).get("commit", "")
    except Exception:
        return ""


def save_cursor(commit: str) -> None:
    json.dump({"commit": commit, "updated_at": utc()}, open(CURSOR, "w"))


def refresh_templates() -> tuple[str, str]:
    """Pull, returning (old_head, new_head). Direct git — never trust the updater's report."""
    old = git("rev-parse", "HEAD")
    git("stash", "push", "-u", "-m", f"ndayrace-{int(datetime.now().timestamp())}")
    for branch in ("main", "master"):
        if git("pull", "--ff-only", "origin", branch):
            break
    git("stash", "drop")
    return old, git("rev-parse", "HEAD")


def new_cve_templates(since: str) -> list[str]:
    if not since:
        return []
    out = git("diff", "--name-only", "--diff-filter=AM", f"{since}..HEAD")
    return [p for p in out.splitlines() if "/cves/" in p and p.endswith(".yaml")]


def kev_set() -> set[str]:
    """CISA Known Exploited Vulnerabilities — authoritative, machine-readable, free."""
    try:
        if os.path.exists(KEV_CACHE) and \
                (datetime.now().timestamp() - os.path.getmtime(KEV_CACHE)) < 86400:
            data = json.load(open(KEV_CACHE))
        else:
            req = urllib.request.Request(KEV_URL, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=60) as r:
                data = json.loads(r.read())
            json.dump(data, open(KEV_CACHE, "w"))
        return {v["cveID"].upper() for v in data.get("vulnerabilities", [])}
    except Exception as e:
        log(f"KEV fetch failed ({str(e)[:80]}) — continuing without it")
        return set()


def parse_template(path: str) -> dict | None:
    full = os.path.join(TEMPLATES, path)
    try:
        body = open(full, encoding="utf-8", errors="replace").read()
    except Exception:
        return None
    cve = ""
    m = re.search(r"(CVE-\d{4}-\d{4,7})", path + " " + body, re.I)
    if m:
        cve = m.group(1).upper()
    sev = ""
    m = re.search(r"^\s*severity\s*:\s*(\w+)", body, re.M | re.I)
    if m:
        sev = m.group(1).lower()
    name = ""
    m = re.search(r"^\s*name\s*:\s*(.+)$", body, re.M)
    if m:
        name = m.group(1).strip().strip('"\'')
    tags = ""
    m = re.search(r"^\s*tags\s*:\s*(.+)$", body, re.M)
    if m:
        tags = m.group(1).strip()

    unsafe = [why for rx, why in UNSAFE if rx.search(body)]
    return {"path": path, "cve": cve, "severity": sev, "name": name, "tags": tags,
            "safe": not unsafe, "unsafe_reasons": unsafe,
            "product_terms": product_terms(name, tags, path)}


# Scanner vocabulary and grammar — never a product name, so never a useful fingerprint.
# NOTE: product words like "spring" or "jenkins" are deliberately NOT here. The earlier
# tumblr-blog mis-targeting came from match_phrase against the free-text `title` field,
# not from the term itself; `tech` is a Wappalyzer controlled vocabulary, so an exact
# term match on it is precise. The fix was to stop matching `title`, not to blind the
# product terms.
STOP = {"cve", "http", "network", "javascript", "detect", "detection", "rce", "lfi", "xss",
        "sqli", "ssrf", "auth", "bypass", "unauth", "disclosure", "exposure", "misconfig",
        "instance", "panel", "default", "login", "file", "read", "remote", "code", "execution",
        "the", "and", "for", "via", "with", "in", "of", "a", "an", "to",
        "unauthenticated", "improper", "arbitrary", "injection", "traversal", "upload",
        "authorization", "authentication", "vulnerability", "vulnerable", "affected"}

# CVE advisories name products the way vendors do; ES records them the way Wappalyzer
# fingerprints them. Bridge the two, or a Spring Boot CVE finds nothing because the
# estate is tagged "Spring".
TECH_ALIAS = {
    "springboot": ["Spring", "Spring Boot", "Java"],
    "spring_boot": ["Spring", "Spring Boot", "Java"],
    "spring": ["Spring", "Spring Boot"],
    "actuator": ["Spring", "Spring Boot"],
    "wordpress": ["WordPress"], "drupal": ["Drupal"], "joomla": ["Joomla"],
    "jenkins": ["Jenkins"], "gitlab": ["GitLab"], "grafana": ["Grafana"],
    "confluence": ["Confluence"], "jira": ["Jira"], "tomcat": ["Apache Tomcat"],
    "nginx": ["Nginx"], "apache": ["Apache HTTP Server"], "iis": ["IIS"],
    "elasticsearch": ["Elasticsearch"], "kibana": ["Kibana"], "mongodb": ["MongoDB"],
    "redis": ["Redis"], "rabbitmq": ["RabbitMQ"], "kubernetes": ["Kubernetes"],
    "docker": ["Docker"], "django": ["Django"], "laravel": ["Laravel"],
    "rails": ["Ruby on Rails"], "express": ["Express"], "nextjs": ["Next.js"],
    "next.js": ["Next.js"], "nodejs": ["Node.js"], "node.js": ["Node.js"],
    "php": ["PHP"], "magento": ["Magento"], "shopify": ["Shopify"],
    "sharepoint": ["Microsoft SharePoint"], "exchange": ["Microsoft Exchange Server"],
    "fortinet": ["Fortinet"], "citrix": ["Citrix"], "vmware": ["VMware"],
    "zimbra": ["Zimbra"], "moveit": ["MOVEit"], "aem": ["Adobe Experience Manager"],
    "keycloak": ["Keycloak"], "solr": ["Apache Solr"], "struts": ["Apache Struts"],
    "weblogic": ["Oracle WebLogic Server"], "websphere": ["IBM WebSphere"],
}


def expand_terms(terms: list[str]) -> list[str]:
    """Map CVE product vocabulary onto the fingerprints ES actually stores."""
    out: list[str] = []
    for t in terms:
        for alias in TECH_ALIAS.get(t.lower(), []):
            if alias not in out:
                out.append(alias)
    for t in terms:
        if len(t) >= 5 and t.lower() not in TECH_ALIAS:
            for v in (t, t.title(), t.capitalize()):
                if v not in out:
                    out.append(v)
    return out


def product_terms(name: str, tags: str, path: str) -> list[str]:
    """The technology words worth matching against what we actually run."""
    words = re.findall(r"[a-zA-Z][a-zA-Z0-9_.-]{2,}", f"{name} {tags}")
    out = []
    for w in words:
        lw = w.lower().strip(".-_")
        if lw in STOP or len(lw) < 3 or re.fullmatch(r"\d+", lw):
            continue
        out.append(lw)
    seen, uniq = set(), []
    for w in out:
        if w not in seen:
            seen.add(w)
            uniq.append(w)
    return uniq[:6]


def es_hosts_for(terms: list[str], limit: int = 40) -> list[dict]:
    """In-scope, paying, not-benched hosts whose TECH FINGERPRINT matches this product.

    Returns nothing when the terms are too generic to identify a product — firing a
    template at a target list assembled from a vague word is worse than not firing."""
    terms = expand_terms([t for t in terms if len(t) >= 4])
    if not terms:
        return []
    import base64
    pw = ""
    pf = os.path.expanduser("~/.recon_es_pass")
    if os.path.exists(pf):
        pw = open(pf).read().strip()
    auth = base64.b64encode(f"elastic:{pw}".encode()).decode()
    # `tech` is a KEYWORD field, so a term query is an exact fingerprint match. The old
    # query also match_phrase'd `title`, which is free text — that is how a Spring Boot
    # template acquired a target list of tumblr blogs. Fingerprint only.
    should = [{"term": {"tech": t}} for t in terms]
    body = {"size": limit, "_source": ["host", "triage_program", "tech"],
            "query": {"bool": {
                "must": [{"bool": {"should": should, "minimum_should_match": 1}}],
                "filter": [{"term": {"triage_in_scope": True}}, {"term": {"triage_pays": True}}],
                "must_not": [{"range": {"ignore_expires_at": {"gt": "now"}}}]}}}
    req = urllib.request.Request(f"{ES}/{IDX}/_search", data=json.dumps(body).encode(),
                                 method="POST",
                                 headers={"Content-Type": "application/json",
                                          "Authorization": f"Basic {auth}"})
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            hits = json.loads(r.read()).get("hits", {}).get("hits", [])
    except Exception as e:
        log(f"  ES query failed: {str(e)[:90]}")
        return []
    return [{"host": h["_source"].get("host"), "program": h["_source"].get("triage_program"),
             "tech": h["_source"].get("tech")} for h in hits if h["_source"].get("host")]


def fire(template: str, hosts: list[str], rate: int = 20) -> list[dict]:
    """Run ONE vetted template against ONLY the matching hosts. Rate-limited, no interactsh
    unless the template needs it, and nuclei's own -duc is off because we manage the repo."""
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("\n".join(f"https://{h}" for h in hosts))
        target_file = f.name
    cmd = ["nuclei", "-t", os.path.join(TEMPLATES, template), "-l", target_file,
           "-jsonl", "-silent", "-duc", "-rate-limit", str(rate), "-timeout", "10",
           "-retries", "1", "-no-color"]
    out = []
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        for line in (r.stdout or "").splitlines():
            try:
                out.append(json.loads(line))
            except Exception:
                pass
    except subprocess.TimeoutExpired:
        log(f"  template timed out: {template}")
    except Exception as e:
        log(f"  nuclei error: {str(e)[:100]}")
    finally:
        try:
            os.unlink(target_file)
        except Exception:
            pass
    return out


def mint(hit: dict, tpl: dict, program: str) -> int | None:
    sys.path.insert(0, REPO_DIR)
    from engine import state
    host = (hit.get("host") or hit.get("matched-at") or "").split("/")[0]
    ev = {
        "chain": "new nuclei CVE template -> tech match on our estate -> template fired -> matched",
        "cve": tpl["cve"], "template": tpl["path"], "template_name": tpl["name"],
        "severity": tpl["severity"], "kev": tpl.get("kev", False),
        "matched_at": hit.get("matched-at"), "matcher": hit.get("matcher-name"),
        "extracted": hit.get("extracted-results"),
        "impact": f"{tpl['cve']} — {tpl['name']}",
        "method": ("template body reviewed and confirmed read-only before firing; run only "
                   "against hosts whose fingerprint matched the affected technology"),
        "at": utc(),
    }
    sev_score = {"critical": 20, "high": 17, "medium": 12, "low": 8}.get(tpl["severity"], 8)
    if tpl.get("kev"):
        sev_score = max(sev_score, 19)
    conn = state.connect()
    state.init_db(conn)
    fid = state.record_confirmed(
        conn, host, url=hit.get("matched-at") or f"https://{host}", program=program or None,
        signal_class="n-day", vuln_class=f"{tpl['cve'] or 'cve'}-confirmed",
        score=sev_score, evidence=ev, confidence=0.9)
    conn.close()
    return fid


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Race newly-published CVE detections against our own estate.")
    ap.add_argument("--max-templates", type=int, default=25)
    ap.add_argument("--max-hosts", type=int, default=40)
    ap.add_argument("--since", default=None, help="git ref to diff from (default: saved cursor)")
    ap.add_argument("--no-pull", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    if os.path.exists(os.path.join(STATE_DIR, "vpn_down")):
        log("vpn_down — refusing (fail-closed)")
        return 2
    if not os.path.isdir(os.path.join(TEMPLATES, ".git")):
        log(f"{TEMPLATES} is not a git checkout — cannot diff for new templates")
        return 2

    since = a.since or load_cursor()
    if not a.no_pull:
        old, new = refresh_templates()
        log(f"templates {old[:8]} -> {new[:8]}")
        since = since or old
    head = git("rev-parse", "HEAD")

    paths = new_cve_templates(since)
    if not paths:
        log(f"no new CVE templates since {since[:8] or '(no cursor)'} — nothing to race")
        save_cursor(head)
        return 0
    log(f"{len(paths)} new/changed CVE template(s) since {since[:8]}")

    kev = kev_set()
    tpls = [t for t in (parse_template(p) for p in paths) if t]
    for t in tpls:
        t["kev"] = t["cve"] in kev
    # KEV first, then severity — being exploited in the wild outranks everything.
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "": 5}
    tpls.sort(key=lambda t: (not t["kev"], order.get(t["severity"], 5)))

    fired, findings, skipped = 0, [], []
    for t in tpls[:a.max_templates]:
        tag = "KEV " if t["kev"] else ""
        if not t["safe"]:
            log(f"  REFUSED {tag}{t['cve'] or t['path']} — {', '.join(t['unsafe_reasons'])}")
            skipped.append(t)
            continue
        hosts = es_hosts_for(t["product_terms"], a.max_hosts)
        if not hosts:
            continue
        log(f"  {tag}{t['cve']} [{t['severity']}] {t['name'][:56]} -> {len(hosts)} matching host(s)")
        if a.dry_run:
            fired += 1
            continue
        hits = fire(t["path"], [h["host"] for h in hosts])
        fired += 1
        prog = {h["host"]: h["program"] for h in hosts}
        for hit in hits:
            host = (hit.get("host") or "").replace("https://", "").replace("http://", "").split("/")[0]
            log(f"    *** MATCH {t['cve']} on {host}")
            fid = mint(hit, t, prog.get(host, ""))
            findings.append({"cve": t["cve"], "host": host, "severity": t["severity"],
                             "kev": t["kev"], "finding_id": fid})

    save_cursor(head)
    audit({"since": since, "head": head, "new_templates": len(paths),
           "fired": fired, "refused": len(skipped), "matches": len(findings)})

    os.makedirs(OUT_DIR, exist_ok=True)
    out = os.path.join(OUT_DIR, f"ndayrace_{datetime.now().strftime('%Y-%m-%d')}.md")
    L = [f"# n-day race — {utc()}", "",
         f"{len(paths)} new CVE template(s) since `{since[:8]}`. "
         f"{fired} fired, {len(skipped)} refused as unsafe, **{len(findings)} match(es)**.", ""]
    if findings:
        L += ["## Matches", ""]
        for f in findings:
            L.append(f"- **{f['cve']}** [{f['severity']}]{' **KEV**' if f['kev'] else ''} "
                     f"on `{f['host']}` — finding #{f['finding_id']}")
        L.append("")
    if skipped:
        L += ["## Refused (operator-only — these can do more than look)", ""]
        for t in skipped[:25]:
            L.append(f"- `{t['cve'] or t['path']}` — {', '.join(t['unsafe_reasons'])}")
    open(out, "w", encoding="utf-8").write("\n".join(L))
    log(f"report → {out}")
    log(f"DONE — {fired} template(s) fired, {len(findings)} match(es)")
    print(json.dumps({"new_templates": len(paths), "fired": fired,
                      "refused": len(skipped), "matches": len(findings)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())

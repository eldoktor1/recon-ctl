#!/usr/bin/env python3
"""
recon_intel.py — CONFIRM threat intel against authoritative online sources before we act on it.

A Claude agent reading the web is a good scout and an unreliable witness. This pipeline's own
doctrine already records the failure mode: "the CVE IDs LLM-search returns can be hallucinated."
That is precisely why the research routine has only ever produced digests nobody reads — nothing
downstream could safely trust it.

The fix is not to stop using agents. It is to put the agent where being wrong is FREE:

    agent PROPOSES  ->  this module CONFIRMS ONLINE  ->  the machine ACTS

A proposal that fails confirmation costs nothing. An unconfirmed claim that becomes a finding
costs the operator's signal, and that is what has been happening.

Every claim is checked against sources that cannot hallucinate:

  NVD      does this CVE actually exist? what are its REAL affected version ranges (CPE)?
           https://services.nvd.nist.gov/rest/json/cves/2.0     (NIST, authoritative)
  CISA KEV is it being exploited in the wild right now?
  nuclei   does a detection already exist, or must we author one?
  ES       do WE actually run the affected technology, and on which in-scope hosts?

Only a claim that survives all four becomes actionable. The output is a queue for
recon_ndayrace.py, never a finding.

No target traffic — NVD, CISA and our own index only.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

BASE_DIR = os.environ.get("BASE_DIR", os.path.expanduser("~/recon"))
STATE_DIR = os.environ.get("STATE_DIR", os.path.join(BASE_DIR, "state"))
REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATES = os.environ.get("NUCLEI_TEMPLATES_DIR", os.path.expanduser("~/nuclei-templates"))
QUEUE = os.path.join(STATE_DIR, "intel_queue.jsonl")
AUDIT = os.path.join(STATE_DIR, "intel_audit.jsonl")
KEV_CACHE = os.path.join(STATE_DIR, "kev_catalog.json")
NVD_CACHE = os.path.join(STATE_DIR, "nvd_cache.json")
OUT_DIR = os.path.join(BASE_DIR, "briefings")
ES = os.environ.get("ES_URL", "http://127.0.0.1:9200")
IDX = os.environ.get("INDEX_NAME", "recon_alive")

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# NVD allows 5 requests / 30s unauthenticated, 50 / 30s with a key. Be a good citizen.
NVD_KEY = os.environ.get("NVD_API_KEY", "")
NVD_GAP = 1.5 if NVD_KEY else 6.5

CVE_RX = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(m: str) -> None:
    print(f"[intel] {m}", file=sys.stderr, flush=True)


def audit(rec: dict) -> None:
    os.makedirs(STATE_DIR, exist_ok=True)
    rec.setdefault("at", utc())
    with open(AUDIT, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")


def _get(url: str, timeout: int = 45, headers: dict | None = None) -> tuple[int, bytes]:
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, b""
    except Exception:
        return 0, b""


# ---------------------------------------------------------------- NVD (truth)
_nvd_last = [0.0]


def _cache(path: str) -> dict:
    try:
        return json.load(open(path))
    except Exception:
        return {}


def nvd_confirm(cve: str, cache: dict) -> dict:
    """Does this CVE exist, and what does NIST say it affects? The hallucination killer."""
    cve = cve.upper()
    if cve in cache:
        return cache[cve]

    gap = time.time() - _nvd_last[0]
    if gap < NVD_GAP:
        time.sleep(NVD_GAP - gap)
    _nvd_last[0] = time.time()

    hdrs = {"User-Agent": "recon-ctl/intel"}
    if NVD_KEY:
        hdrs["apiKey"] = NVD_KEY
    code, body = _get(f"{NVD_API}?cveId={urllib.parse.quote(cve)}", headers=hdrs)
    if code != 200 or not body:
        # Do NOT cache a transport failure as "does not exist" — that would silently
        # turn an outage into a stream of false rejections.
        return {"exists": None, "error": f"nvd http {code}"}

    try:
        data = json.loads(body)
    except Exception:
        return {"exists": None, "error": "nvd unparseable"}

    vulns = data.get("vulnerabilities") or []
    if not vulns:
        res = {"exists": False, "reason": "NVD has no record of this CVE id"}
        cache[cve] = res
        return res

    c = vulns[0].get("cve") or {}
    desc = ""
    for d in c.get("descriptions") or []:
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break

    cvss, vector, sev = 0.0, "", ""
    metrics = c.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            m = metrics[key][0].get("cvssData") or {}
            cvss = m.get("baseScore") or 0.0
            vector = m.get("vectorString") or ""
            sev = (m.get("baseSeverity") or metrics[key][0].get("baseSeverity") or "").lower()
            break

    # The affected version ranges — this is what turns a tech-class guess into a real match.
    ranges, products = [], set()
    for cfg in c.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for cpe in node.get("cpeMatch") or []:
                if not cpe.get("vulnerable"):
                    continue
                crit = cpe.get("criteria", "")
                parts = crit.split(":")
                if len(parts) > 5:
                    products.add(f"{parts[3]}:{parts[4]}".lower())
                ranges.append({
                    "cpe": crit,
                    "start_incl": cpe.get("versionStartIncluding"),
                    "start_excl": cpe.get("versionStartExcluding"),
                    "end_incl": cpe.get("versionEndIncluding"),
                    "end_excl": cpe.get("versionEndExcluding"),
                })

    res = {"exists": True, "cve": cve, "description": desc[:400], "cvss": cvss,
           "severity": sev, "vector": vector, "products": sorted(products)[:12],
           "version_ranges": ranges[:20],
           "published": c.get("published", "")[:10],
           "unauth": "AV:N" in vector and "PR:N" in vector}
    cache[cve] = res
    return res


def kev_set() -> set[str]:
    try:
        if os.path.exists(KEV_CACHE) and (time.time() - os.path.getmtime(KEV_CACHE)) < 86400:
            data = json.load(open(KEV_CACHE))
        else:
            code, body = _get(KEV_URL, timeout=60)
            if code != 200:
                return set()
            data = json.loads(body)
            json.dump(data, open(KEV_CACHE, "w"))
        return {v["cveID"].upper() for v in data.get("vulnerabilities", [])}
    except Exception:
        return set()


def template_for(cve: str) -> str:
    hits = glob.glob(os.path.join(TEMPLATES, "**", f"{cve.upper()}.yaml"), recursive=True)
    if not hits:
        hits = glob.glob(os.path.join(TEMPLATES, "**", f"{cve.lower()}.yaml"), recursive=True)
    return os.path.relpath(hits[0], TEMPLATES) if hits else ""


def es_exposure(products: list[str], limit: int = 25) -> list[dict]:
    """Do WE run this? A CVE we have no exposure to is not intel, it is noise."""
    terms = set()
    for p in products:
        for part in p.split(":"):
            part = part.replace("_", " ").strip()
            for w in part.split():
                if len(w) >= 4:
                    terms.add(w.lower())
    if not terms:
        return []
    import base64
    pw = ""
    pf = os.path.expanduser("~/.recon_es_pass")
    if os.path.exists(pf):
        pw = open(pf).read().strip()
    auth = base64.b64encode(f"elastic:{pw}".encode()).decode()
    should = []
    for t in sorted(terms)[:10]:
        should.append({"term": {"tech": t}})
        should.append({"match_phrase": {"title": t}})
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
    except Exception:
        return []
    return [{"host": h["_source"].get("host"), "program": h["_source"].get("triage_program")}
            for h in hits if h["_source"].get("host")]


def confirm(claim: str, kev: set[str], nvd_cache: dict, check_es: bool = True) -> dict:
    """One claim in, a fully-confirmed verdict out."""
    m = CVE_RX.search(claim)
    if not m:
        return {"claim": claim, "actionable": False,
                "reason": "no CVE id in the claim — cannot be confirmed against NVD"}
    cve = m.group(0).upper()

    nvd = nvd_confirm(cve, nvd_cache)
    if nvd.get("exists") is None:
        return {"claim": claim, "cve": cve, "actionable": False,
                "reason": f"NVD unreachable ({nvd.get('error')}) — NOT treating as confirmed"}
    if nvd["exists"] is False:
        return {"claim": claim, "cve": cve, "actionable": False,
                "reason": "REJECTED — NVD has no record of this CVE. Likely hallucinated."}

    in_kev = cve in kev
    tpl = template_for(cve)
    hosts = es_exposure(nvd.get("products") or []) if check_es else []

    actionable = bool(hosts)
    reason = ("we run the affected product" if hosts
              else "no in-scope host fingerprints the affected product — no exposure")

    return {"claim": claim, "cve": cve, "actionable": actionable, "reason": reason,
            "confirmed_by": "nvd", "cvss": nvd["cvss"], "severity": nvd["severity"],
            "unauth_network": nvd["unauth"], "published": nvd["published"],
            "description": nvd["description"], "products": nvd["products"],
            "version_ranges_count": len(nvd["version_ranges"]),
            "kev": in_kev, "nuclei_template": tpl,
            "needs_template": not tpl,
            "exposed_hosts": hosts[:25], "exposure_count": len(hosts)}


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Confirm threat-intel claims against NVD/KEV/our estate before acting.")
    ap.add_argument("claim", nargs="*", help="claims (CVE ids or text containing them)")
    ap.add_argument("--file", help="file of claims, one per line (e.g. a research digest)")
    ap.add_argument("--no-es", action="store_true", help="skip the exposure check")
    a = ap.parse_args()

    claims = list(a.claim)
    if a.file and os.path.exists(a.file):
        claims += [l.strip() for l in open(a.file, encoding="utf-8", errors="replace")
                   if l.strip()]
    if not claims:
        log("no claims given")
        return 2

    kev = kev_set()
    log(f"KEV catalogue: {len(kev)} known-exploited CVEs")
    nvd_cache = _cache(NVD_CACHE)

    results = []
    try:
        for c in claims:
            r = confirm(c, kev, nvd_cache, check_es=not a.no_es)
            results.append(r)
            if not r.get("cve"):
                log(f"  SKIP  {c[:60]} — {r['reason']}")
            elif r["actionable"]:
                flag = " KEV" if r["kev"] else ""
                tpl = r["nuclei_template"] or "NO TEMPLATE — needs authoring"
                log(f"  ACTIONABLE{flag}  {r['cve']} cvss={r['cvss']} "
                    f"exposure={r['exposure_count']} host(s)  [{tpl}]")
            else:
                log(f"  no-action  {r['cve']} — {r['reason']}")
    finally:
        json.dump(nvd_cache, open(NVD_CACHE, "w"))

    act = [r for r in results if r.get("actionable")]
    with open(QUEUE, "a", encoding="utf-8") as f:
        for r in act:
            f.write(json.dumps(r) + "\n")
    audit({"claims": len(claims), "actionable": len(act),
           "rejected": sum(1 for r in results if r.get("cve") and not r["actionable"])})

    os.makedirs(OUT_DIR, exist_ok=True)
    out = os.path.join(OUT_DIR, f"intel_{datetime.now().strftime('%Y-%m-%d')}.md")
    L = [f"# Confirmed intel — {utc()}", "",
         f"{len(claims)} claim(s) checked against NVD, CISA KEV, the template repo and our "
         f"own estate. **{len(act)} actionable.**", ""]
    for r in sorted(act, key=lambda x: (-x["kev"], -(x["cvss"] or 0))):
        L += [f"## {r['cve']}{'  **KEV — exploited in the wild**' if r['kev'] else ''}",
              f"- CVSS {r['cvss']} ({r['severity']}) · published {r['published']}"
              + (" · **unauthenticated, network**" if r["unauth_network"] else ""),
              f"- {r['description'][:280]}",
              f"- affected: {', '.join(r['products'][:6])}",
              f"- **our exposure: {r['exposure_count']} in-scope host(s)** — "
              + ", ".join(f"`{h['host']}`" for h in r["exposed_hosts"][:8]),
              f"- detection: {'`' + r['nuclei_template'] + '`' if r['nuclei_template'] else '**none — author one**'}",
              ""]
    rejected = [r for r in results if r.get("cve") and not r["actionable"]]
    if rejected:
        L += ["---", "", "## Not actionable", ""]
        for r in rejected[:30]:
            L.append(f"- {r['cve']} — {r['reason']}")
    open(out, "w", encoding="utf-8").write("\n".join(L))
    log(f"report → {out}")
    log(f"queue  → {QUEUE} ({len(act)} actionable)")
    print(json.dumps({"checked": len(claims), "actionable": len(act)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())

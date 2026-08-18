#!/usr/bin/env python3
"""
recon_feed.py — mine ES for what each impact lane actually needs.

The chain-to-impact lanes were built correctly and then starved. The bucket lane was
reading `endpoints.jsonl` (162k rows) and finding 11 buckets; ES holds 2.84M documents and
the same question asked properly returns four times as many, with better provenance. The
actuator lane had ZERO candidates because actuator fingerprints live in response headers and
error pages, not in a list of JS-extracted paths.

That is the "internet research for enumeration" rule turned inward: when a lane looks thin,
the surface is usually there and the QUERY is wrong.

This produces one target file per lane, gated to in-scope + paying + not-benched:

    state/feed_buckets.txt    bucket names, provenance-confirmed via host/CNAME
    state/feed_actuator.txt   hosts with a real Spring/actuator fingerprint
    state/feed_ports.txt      hosts with 1-5 critical ports, CDN-fronted excluded
    state/feed_graphql.txt    hosts exposing a GraphQL endpoint
    state/feed_<lane>.json    the same with provenance attached, for --provenance

Read-only against our own index. Issues NO target traffic.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime

BASE_DIR = os.environ.get("BASE_DIR", os.path.expanduser("~/recon"))
STATE_DIR = os.environ.get("STATE_DIR", os.path.join(BASE_DIR, "state"))
ES = os.environ.get("ES_URL", "http://127.0.0.1:9200")
IDX = os.environ.get("INDEX_NAME", "recon_alive")
PASS_FILE = os.path.expanduser("~/.recon_es_pass")

SCROLL_SIZE = 500
MAX_DOCS = int(os.environ.get("FEED_MAX_DOCS", "4000"))


def log(m: str) -> None:
    print(f"[feed] {m}", file=sys.stderr, flush=True)


def _auth() -> str:
    pw = open(PASS_FILE).read().strip() if os.path.exists(PASS_FILE) else ""
    return base64.b64encode(f"elastic:{pw}".encode()).decode()


def search(body: dict, size: int = SCROLL_SIZE) -> list[dict]:
    """Paged search_after so a lane feed is not capped at one page of hits."""
    out: list[dict] = []
    after = None
    body = dict(body)
    body["size"] = size
    body["sort"] = [{"_doc": "asc"}] if "sort" not in body else body["sort"]
    while len(out) < MAX_DOCS:
        b = dict(body)
        if after:
            b["search_after"] = after
        req = urllib.request.Request(
            f"{ES}/{IDX}/_search", data=json.dumps(b).encode(), method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Basic {_auth()}"})
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                res = json.loads(r.read())
        except urllib.error.HTTPError as e:
            log(f"ES error {e.code}: {e.read()[:200]!r}")
            break
        except Exception as e:
            log(f"ES unreachable: {str(e)[:160]}")
            break
        hits = res.get("hits", {}).get("hits", [])
        if not hits:
            break
        out.extend(h.get("_source", {}) for h in hits)
        after = hits[-1].get("sort")
        if not after or len(hits) < size:
            break
    return out


# in-scope + pays + not actively benched. `ignore_expires_at` is the authoritative bench
# signal — `ignore_active` is only a write-time snapshot, so trust the date range.
GATE = {
    "filter": [{"term": {"triage_in_scope": True}}, {"term": {"triage_pays": True}}],
    "must_not": [{"range": {"ignore_expires_at": {"gt": "now"}}}],
}

CDN = re.compile(r"(cloudflare|akamai|fastly|cloudfront|incapsula|sucuri|azureedge|"
                 r"edgekey|edgesuite|stackpath|bunnycdn|imperva)", re.I)

BUCKET_RX = [
    re.compile(r"^([a-z0-9][a-z0-9.\-]{1,61})\.s3([.\-][a-z0-9\-]+)*\.amazonaws\.com$", re.I),
    re.compile(r"^([a-z0-9][a-z0-9.\-]{1,61})\.s3-website[.\-][a-z0-9\-]+\.amazonaws\.com$", re.I),
    re.compile(r"^([a-z0-9][a-z0-9.\-]{1,61})\.storage\.googleapis\.com$", re.I),
    re.compile(r"^([a-z0-9][a-z0-9\-]{1,61})\.blob\.core\.windows\.net$", re.I),
    re.compile(r"^([a-z0-9][a-z0-9.\-]{1,61})\.[a-z0-9\-]+\.digitaloceanspaces\.com$", re.I),
]


def _cnames(src: dict) -> list[str]:
    c = src.get("cname") or src.get("cnames") or []
    if isinstance(c, str):
        c = [c]
    return [str(x).lower().rstrip(".") for x in c if x]


def feed_buckets() -> tuple[list[str], dict]:
    docs = search({"_source": ["host", "triage_program", "cname", "cnames"],
                   "query": {"bool": dict(GATE, must=[{"query_string": {
                       "query": "(*s3.amazonaws.com* OR *s3-website* OR *storage.googleapis.com* "
                                "OR *blob.core.windows.net* OR *digitaloceanspaces*)",
                       "analyze_wildcard": True}}])}})
    prov: dict[str, dict] = {}
    for s in docs:
        host = (s.get("host") or "").lower()
        program = s.get("triage_program") or ""
        for cand in [host] + _cnames(s):
            for rx in BUCKET_RX:
                m = rx.match(cand)
                if m:
                    b = m.group(1).lower()
                    prov.setdefault(b, {
                        "program": program,
                        "provenance": f"CNAME/host of in-scope paying asset {host} ({cand})",
                        "host": host})
    log(f"buckets: {len(docs)} docs -> {len(prov)} provenance-confirmed bucket names")
    return sorted(prov), prov


def feed_actuator() -> tuple[list[str], dict]:
    """Field-scoped, not full-text guessing. `tech` is a KEYWORD field, so a term query on
    'Spring' is exact; a wildcard query_string across every field matched tumblr blogs and
    hubspot landing pages with empty tech and empty title — 3,999 hosts of pure noise."""
    docs = search({"_source": ["host", "triage_program", "tech", "title", "js_endpoint_hit"],
                   "query": {"bool": dict(
                       GATE,
                       must=[{"bool": {"minimum_should_match": 1, "should": [
                           {"terms": {"tech": ["Spring", "Spring Boot", "Spring Framework"]}},
                           {"match_phrase": {"title": "Whitelabel Error Page"}},
                           {"match_phrase": {"host_notes_text": "actuator"}},
                       ]}}])}})
    prov: dict[str, dict] = {}
    for s in docs:
        host = (s.get("host") or "").lower()
        if not host:
            continue
        tech = [str(t) for t in (s.get("tech") or [])]
        title = str(s.get("title") or "")
        why = []
        if any("spring" in t.lower() for t in tech):
            why.append(f"tech={','.join(t for t in tech if 'spring' in t.lower())}")
        if "whitelabel" in title.lower():
            why.append("Whitelabel Error Page (Spring Boot default)")
        prov[host] = {"program": s.get("triage_program") or "",
                      "provenance": "; ".join(why) or "actuator noted"}
    log(f"actuator: {len(docs)} docs -> {len(prov)} candidate hosts")
    return sorted(prov), prov


def feed_ports() -> tuple[list[str], dict]:
    """`cdn_name` is an indexed keyword, so CDN exclusion is a filter rather than a regex
    guess against hostnames. >5 critical ports on one host is a scan artefact, not a host."""
    docs = search({"_source": ["host", "triage_program", "portscan_critical",
                               "portscan_open_ports", "cdn_name", "cdn_type", "tech", "cname"],
                   "query": {"bool": dict(
                       GATE,
                       must=[{"range": {"portscan_critical": {"gte": 1, "lte": 5}}}],
                       must_not=GATE["must_not"] + [{"exists": {"field": "cdn_name"}}])}})
    prov: dict[str, dict] = {}
    skipped = 0
    for s in docs:
        host = (s.get("host") or "").lower()
        if not host:
            continue
        # belt-and-braces: some CDN-fronted hosts predate the cdn_name field
        blob = f"{host} {' '.join(map(str, s.get('tech') or []))} {' '.join(_cnames(s))}"
        if CDN.search(blob):
            skipped += 1
            continue
        ports = s.get("portscan_open_ports") or []
        prov[host] = {"program": s.get("triage_program") or "",
                      "ports": ports if isinstance(ports, list) else [ports],
                      "provenance": f"{s.get('portscan_critical')} critical port(s), no CDN"}
    log(f"ports: {len(docs)} docs -> {len(prov)} hosts ({skipped} CDN-fronted skipped by name)")
    return sorted(prov), prov


GQL_WORKLIST = os.path.join(BASE_DIR, "graphql", "graphql_worklist.jsonl")


def feed_graphql() -> tuple[list[str], dict]:
    """The GraphQL lane's OWN worklist is authoritative — it records the endpoint URL it
    actually found. ES only carries booleans, and `final_url` is the host's landing page
    (for one host, a browser-upgrade interstitial). Guessing paths from the hostname missed
    every real endpoint here: Atlassian serves `/gateway/api/graphql`, OpenAI's store serves
    `/api/2026-04/graphql.json`, SEEK uses a dedicated `graphql.seek.com` host."""
    if os.path.exists(GQL_WORKLIST):
        prov: dict[str, dict] = {}
        for line in open(GQL_WORKLIST, encoding="utf-8", errors="replace"):
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except Exception:
                continue
            ep = (r.get("endpoint") or "").strip()
            if not ep or str(r.get("introspection_enabled")) != "True":
                continue
            n = int(r.get("n_sensitive") or 0)
            host = (r.get("host") or "").lower()
            # keep the richest observation per endpoint (the lane re-scans over time)
            cur = prov.get(ep)
            if cur and cur["sensitive_ops"] >= n:
                continue
            prov[ep] = {"program": (r.get("program") or "").strip(),
                        "host": host, "endpoint": ep, "sensitive_ops": n,
                        "provenance": f"introspection enabled; {n} sensitive op(s) in schema"}
        ranked = sorted(prov, key=lambda e: -prov[e]["sensitive_ops"])
        log(f"graphql: {len(prov)} endpoints with introspection ON "
            f"({sum(1 for v in prov.values() if v['sensitive_ops'])} with sensitive ops) "
            f"— from the lane worklist, not ES")
        return ranked, prov
    log("graphql: worklist missing, falling back to ES flags (endpoint URL unknown)")
    return _feed_graphql_es()


def _feed_graphql_es() -> tuple[list[str], dict]:
    """Fallback only: ES knows THAT a host has GraphQL, not WHERE."""
    docs = search({"_source": ["host", "triage_program", "graphql_endpoint",
                               "graphql_introspection", "graphql_sensitive_ops",
                               "final_url", "scheme", "port"],
                   "query": {"bool": dict(GATE, must=[{"bool": {
                       "minimum_should_match": 1,
                       "should": [{"term": {"graphql_endpoint": True}},
                                  {"term": {"graphql_introspection": True}},
                                  {"range": {"graphql_sensitive_ops": {"gte": 1}}}]}}])}})
    prov: dict[str, dict] = {}
    for s in docs:
        host = (s.get("host") or "").lower()
        if not host:
            continue
        bits = []
        if s.get("graphql_introspection"):
            bits.append("introspection enabled")
        if s.get("graphql_sensitive_ops"):
            bits.append(f"{s['graphql_sensitive_ops']} sensitive op(s) in schema")
        if s.get("graphql_endpoint"):
            bits.append("GraphQL endpoint confirmed")
        # Carry the URL ES already resolved. Path-guessing missed real endpoints that ES
        # had flagged — the scanner found them once, so don't rediscover them badly.
        prov[host] = {"program": s.get("triage_program") or "",
                      "sensitive_ops": s.get("graphql_sensitive_ops") or 0,
                      "final_url": s.get("final_url") or "",
                      "provenance": "; ".join(bits)}
    ranked = sorted(prov, key=lambda h: -prov[h]["sensitive_ops"])
    log(f"graphql: {len(docs)} docs -> {len(prov)} hosts "
        f"({sum(1 for v in prov.values() if v['sensitive_ops'])} with sensitive ops)")
    return ranked, prov


def feed_openbuckets() -> tuple[list[str], dict]:
    """Buckets the bucket-scanner already graded. `bucket_access` records what it found, so
    anything already known to be readable goes straight to the loot chain."""
    docs = search({"_source": ["host", "triage_program", "bucket_name", "bucket_access",
                               "bucket_severity"],
                   "query": {"bool": dict(GATE, must=[{"exists": {"field": "bucket_name"}}])}})
    prov: dict[str, dict] = {}
    for s in docs:
        names = s.get("bucket_name")
        names = names if isinstance(names, list) else ([names] if names else [])
        for n in names:
            n = str(n).strip().lower()
            if not n:
                continue
            prov[n] = {"program": s.get("triage_program") or "",
                       "access": s.get("bucket_access"),
                       "provenance": f"graded by bucket scanner on {s.get('host')} "
                                     f"(access={s.get('bucket_access')}, sev={s.get('bucket_severity')})"}
    log(f"openbuckets: {len(docs)} docs -> {len(prov)} already-graded bucket names")
    return sorted(prov), prov


FEEDS = {"buckets": feed_buckets, "actuator": feed_actuator,
         "ports": feed_ports, "graphql": feed_graphql, "openbuckets": feed_openbuckets}


def main() -> int:
    ap = argparse.ArgumentParser(description="Mine ES for impact-lane targets. No target traffic.")
    ap.add_argument("lane", nargs="*", choices=sorted(FEEDS) + [], default=None)
    ap.add_argument("--out-dir", default=STATE_DIR)
    a = ap.parse_args()
    lanes = a.lane or sorted(FEEDS)

    os.makedirs(a.out_dir, exist_ok=True)
    summary = {}
    for lane in lanes:
        names, prov = FEEDS[lane]()
        txt = os.path.join(a.out_dir, f"feed_{lane}.txt")
        js = os.path.join(a.out_dir, f"feed_{lane}.json")
        open(txt, "w").write("\n".join(names) + ("\n" if names else ""))
        json.dump(prov, open(js, "w"), indent=2)
        summary[lane] = len(names)
        log(f"{lane}: -> {txt}")

    print(json.dumps({"generated_at": datetime.now().isoformat(timespec="seconds"),
                      "counts": summary}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

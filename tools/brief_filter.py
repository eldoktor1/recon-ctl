#!/usr/bin/env python3
# =============================================================================
# brief_filter.py — dup-risk + shared-tenant safety triage for IDOR/BAC leads.
#
# The briefing pipes the ranked lead list in on stdin (JSON array). For each lead
# we compute two signals and classify PROMOTE / HOLD / SUPPRESS so the part-time
# operator sees winnable, SAFE leads first and never wades through product-class
# repeats or third-party-tenant landmines.
#
#   1. endpoint fan-out  — distinct hosts sharing the SAME endpoint path (from the
#      JS endpoint store). High fan-out = a product-standard API that appears on
#      every instance of a shipped product => near-certain DUPLICATE (e.g. the
#      UniFi-OS /proxy/users/... routes on 27+ consoles), not a per-target bug.
#   2. shared-tenant     — the host's leftmost label is a high-entropy UUID/hash
#      AND it has many siblings under one wildcard apex (e.g. <uuid>.unifi-hosting.
#      ui.com, 4600+ of them). Those siblings are DIFFERENT OWNERS, so any
#      cross-tenant test (enumerate users / transfer ownership) on one you don't
#      own = accessing third-party data = over the hard line. SUPPRESS unless the
#      operator owns two instances. A named label (admin, api, sonar) is a service,
#      not a tenant => kept.
#
# Output (stdout JSON): {"promote":[...], "hold":[...], "suppressed":[...],
#   "suppressed_count":N, "suppressed_reasons":{reason:count}}
# Pure-stdlib. ES is optional (sibling count); degrades to fan-out+entropy only.
# Read-only; issues NO target traffic.
# =============================================================================
import os, sys, json, re, math, urllib.request, urllib.error, base64

EP_STORE   = os.environ.get("EP_STORE",   os.path.expanduser("~/recon/js_recon/endpoints.jsonl"))
ES_URL     = os.environ.get("ES_URL",     "http://127.0.0.1:9200")
INDEX_NAME = os.environ.get("INDEX_NAME", "recon_alive")
ES_PASS_F  = os.path.expanduser("~/.recon_es_pass")
FANOUT_DUP   = int(os.environ.get("FANOUT_DUP",   "5"))    # endpoint on >=N hosts => product-class dup
TENANT_MANY  = int(os.environ.get("TENANT_MANY",  "40"))   # >=N siblings under one apex => mass-tenant wildcard
ENTROPY_MIN  = float(os.environ.get("ENTROPY_MIN","3.2"))  # Shannon bits/char over the leftmost label

UUID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
# tests whose PoC reaches across tenants/orgs — these are the unsafe ones on a shared-tenant host
CROSS_TENANT_RE = re.compile(r'\b(other|another|cross|enumerat|transfer|tenant|org|different\s+(agency|org|account)|not\s+in\s+\w+\'?s)\b', re.I)


def shannon(s):
    if not s:
        return 0.0
    from collections import Counter
    n = len(s)
    return -sum((c/n) * math.log2(c/n) for c in Counter(s).values())


def label_is_random(label):
    """leftmost label looks machine-generated (UUID / long high-entropy hex-ish)?"""
    if UUID_RE.match(label):
        return True
    core = label.replace("-", "")
    if len(core) >= 20 and shannon(label) >= ENTROPY_MIN:
        return True
    return False


def load_fanout():
    """endpoint-path -> set(distinct hosts) from the JS endpoint store."""
    fan = {}
    try:
        with open(EP_STORE, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    o = json.loads(line)
                except Exception:
                    continue
                host = o.get("host") or ""
                ep = o.get("endpoint") or o.get("url") or o.get("path") or ""
                ep = re.sub(r'^https?://[^/]+', '', ep)          # normalise to path
                ep = ep.split("?")[0].rstrip("/")                 # drop query + trailing slash
                if ep and host:
                    fan.setdefault(ep, set()).add(host)
    except FileNotFoundError:
        pass
    return fan


def es_auth_header():
    try:
        with open(ES_PASS_F) as f:
            pw = f.read().strip()
        tok = base64.b64encode(f"elastic:{pw}".encode()).decode()
        return {"Authorization": "Basic " + tok}
    except Exception:
        return {}


def es_sibling_count(apex):
    """count hosts matching *.apex in ES (cardinality of the wildcard apex)."""
    body = json.dumps({"query": {"wildcard": {"host": f"*.{apex}"}}}).encode()
    req = urllib.request.Request(f"{ES_URL}/{INDEX_NAME}/_count", data=body,
                                 headers={"Content-Type": "application/json", **es_auth_header()})
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return int(json.load(r).get("count", 0))
    except Exception:
        return -1   # ES unavailable -> unknown


def endpoint_path(lead):
    ep = lead.get("endpoint") or ""
    ep = ep.split("?")[0].rstrip("/")
    return ep


def classify(leads):
    fan = load_fanout()
    sib_cache = {}
    promote, hold, suppressed = [], [], []
    reasons = {}

    for ld in leads:
        host = (ld.get("host") or "").strip().lower()
        ep = endpoint_path(ld)
        labels = host.split(".")
        leftmost = labels[0] if labels else ""
        apex = ".".join(labels[1:]) if len(labels) > 2 else host

        fanout = len(fan.get(ep, set()))
        if apex not in sib_cache:
            sib_cache[apex] = es_sibling_count(apex)
        siblings = sib_cache[apex]
        random_label = label_is_random(leftmost)
        cross_tenant_test = bool(CROSS_TENANT_RE.search((ld.get("test", "") + " " + ld.get("why", ""))))

        ld = dict(ld)
        ld["dup_fanout"] = fanout
        ld["siblings"] = siblings
        ld["shared_tenant"] = bool(random_label and siblings >= TENANT_MANY)

        # ---- classification ----
        if ld["shared_tenant"] and cross_tenant_test:
            ld["verdict"] = "suppress"
            ld["suppress_reason"] = (f"shared-tenant: {leftmost[:8]}… is 1 of ~{siblings} per-customer "
                                     f"consoles under {apex}; cross-tenant test = third-party data "
                                     f"(only safe on TWO instances you own)")
            reasons["shared-tenant (third-party data)"] = reasons.get("shared-tenant (third-party data)", 0) + 1
            suppressed.append(ld)
        elif fanout >= FANOUT_DUP:
            ld["verdict"] = "suppress"
            ld["suppress_reason"] = (f"product-class: {ep} appears on {fanout} distinct hosts = "
                                     f"standard shipped API, near-certain duplicate")
            reasons["product-class duplicate"] = reasons.get("product-class duplicate", 0) + 1
            suppressed.append(ld)
        elif fanout >= 2 or (siblings >= TENANT_MANY and random_label):
            ld["verdict"] = "hold"
            ld["hold_reason"] = (f"medium dup-risk (endpoint on {fanout} hosts" +
                                 (f", {siblings} siblings" if siblings >= TENANT_MANY else "") + ")")
            hold.append(ld)
        else:
            ld["verdict"] = "promote"
            promote.append(ld)

    promote.sort(key=lambda x: -x.get("rank", 0))
    hold.sort(key=lambda x: -x.get("rank", 0))
    return {
        "promote": promote,
        "hold": hold,
        "suppressed": suppressed,
        "suppressed_count": len(suppressed),
        "suppressed_reasons": reasons,
    }


def main():
    try:
        leads = json.load(sys.stdin)
    except Exception:
        leads = []
    if not isinstance(leads, list):
        leads = []
    print(json.dumps(classify(leads)))


if __name__ == "__main__":
    main()

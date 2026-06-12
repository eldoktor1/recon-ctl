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


# ---- structural FP-CLASS rules (generalize past the host+class fp-signature table) ---
# The state.py false_positive_signatures table is keyed on host+signal+vuln, so a BRAND-NEW
# host exhibiting an OLD noise class is not auto-suppressed. These rules promote the stable,
# documented FP classes from CLAUDE.md ("Documented false-positive patterns") into structural
# checks that fire on ANY host with zero prior host-specific signature. Conservative by design
# (fires only on clear signals — a wrong suppression is worse than one extra lead). Each rule
# returns (class, action, reason): action 'suppress' = kill at render; 'downgrade' = keep but
# relabel as an unverified LEAD (never present it as "verified").
_NOISE_TEXT_FIELDS = ("cls", "vuln_class", "vuln_type", "signal_class", "what", "check",
                      "why", "test", "reason", "title", "note")

def _noise_text(ld):
    return " ".join(str(ld.get(k, "")) for k in _NOISE_TEXT_FIELDS if ld.get(k) is not None).lower()

_PUBLIC_TOKEN_RE = re.compile(
    r'(supabase\s*anon|anon[\s_-]*key|\bpk_(live|test)_|stripe\s+publishable|publishable\s+key|'
    r'firebase\s*(web\s*)?config|\bAIza[0-9A-Za-z_\-]{10,}|oauth\s*client[\s_-]*id|google\s*(browser\s*)?api\s*key)', re.I)
# third-party / unowned-repo markers — covers the real adjudication phrasing seen in the
# verified-secret-github stream: "THIRD-PARTY", "3rd-party", "NOT FanDuel's own repo",
# "not Statuspage repo", "public OSS repo", "Trickest ... NOT Personios own repo/surface".
_THIRD_PARTY_RE = re.compile(
    r"(third[\s-]*party|\b3rd[\s-]*party\b|not\s+owned|unaffiliated|fork(ed)?\s+(of|repo)|"
    r"someone\s+else.?s\s+repo|public\s+oss\s+repo|not\s+[\w'’]+(\s+own)?\s+(repo|surface))", re.I)
_SECRETISH_RE   = re.compile(r'(secret|token|leak|trufflehog|credential|api[\s_-]?key|password)', re.I)
_SPA_SHELL_RE   = re.compile(r'(spa[\s-]*shell|index\.html|returns?\s+the\s+app|app\s+shell|client[\s-]*side\s+route|same\s+as\s+/)', re.I)
_KEV_RE         = re.compile(r'\b(kev|cve-\d{4}-\d+|n-?day)\b', re.I)
_VERSION_OK_RE  = re.compile(r'(version\s+confirmed|confirmed\s+in[\s-]*range|running\s+version\s+\d|in-?range\s+version)', re.I)
_PORTS_RE       = re.compile(r'(>?\s*[6-9]\d*\+?\s*(open\s*)?critical\s*ports|scan\s*artifact|every\s*port\s*(open|acks|responds))', re.I)


def noise_class(ld):
    """Detect a documented recurring FP/noise class. Returns (klass, action, reason) or None."""
    t = _noise_text(ld)

    # 1) public-by-design token — a "secret" that is MEANT to be public
    if _PUBLIC_TOKEN_RE.search(t):
        return ("public-by-design-token", "suppress",
                "public-by-design token (Supabase anon / Stripe pk_ / Firebase web config / "
                "OAuth client_id / Google browser API key) — not a secret")

    # 2) third-party-repo secret — leaked in a repo the program does not own
    if _THIRD_PARTY_RE.search(t) and _SECRETISH_RE.search(t):
        return ("third-party-repo-secret", "suppress",
                "secret found in a third-party / unowned repo — not the program's asset")

    # 3) >6 "critical" ports on one host = CDN/scan artifact (CDNs ACK every port)
    pc = ld.get("portscan_critical")
    if pc is None:
        pc = ld.get("critical_ports", ld.get("open_critical"))
    try:
        pc = int(pc)
    except (TypeError, ValueError):
        pc = 0
    if pc > 6 or _PORTS_RE.search(t):
        return (">6-critical-ports-scan-artifact", "suppress",
                f"{pc if pc > 6 else '>6'} 'open' critical ports on one host = CDN/scan artifact, not real exposure")

    # 4) SPA-shell 200 on all routes — route returns the app index.html, same as /
    if ld.get("spa_shell") is True or _SPA_SHELL_RE.search(t):
        return ("spa-shell-200-all-routes", "suppress",
                "SPA-shell 200 (route returns the app index.html, same as /) — not an unauth leak")

    # 5) tech-class KEV/CVE without a CONFIRMED in-range version -> LEAD, never "verified"
    is_kev = bool(ld.get("cves") or ld.get("cve")) or bool(_KEV_RE.search(t))
    version_confirmed = bool(ld.get("version_confirmed") or ld.get("kev_verified")) or bool(_VERSION_OK_RE.search(t))
    if is_kev and not version_confirmed:
        return ("tech-class-kev-no-version", "downgrade",
                "KEV/CVE tech-class match without a confirmed in-range version — LEAD, not verified")

    return None


def filter_noise(leads):
    """Batch any briefing stream through the class rules. Returns keep / suppressed split;
    'downgrade' leads stay in keep but carry _noise_* annotations so the renderer relabels
    them as unverified LEADs. Used by recon_briefing.sh at render across ALL streams."""
    keep, suppressed, reasons = [], [], {}
    for ld in leads:
        nc = noise_class(ld)
        if nc is None:
            keep.append(ld)
            continue
        klass, action, reason = nc
        ld = dict(ld)
        ld["_noise_class"], ld["_noise_action"], ld["_noise_reason"] = klass, action, reason
        if action == "suppress":
            reasons[klass] = reasons.get(klass, 0) + 1
            suppressed.append(ld)
        else:  # downgrade -> kept, relabeled by the renderer
            keep.append(ld)
    return {"keep": keep, "suppressed": suppressed,
            "suppressed_count": len(suppressed), "suppressed_reasons": reasons}


def classify(leads):
    fan = load_fanout()
    sib_cache = {}
    promote, hold, suppressed = [], [], []
    reasons = {}

    for ld in leads:
        # structural FP-class first: a documented noise class kills/downgrades on ANY host
        # before the per-host fan-out/tenant logic even runs (zero prior signature needed).
        nc = noise_class(ld)
        if nc is not None and nc[1] == "suppress":
            ld = dict(ld); ld["verdict"] = "suppress"
            ld["_noise_class"] = nc[0]; ld["suppress_reason"] = nc[2]
            reasons[nc[0]] = reasons.get(nc[0], 0) + 1
            suppressed.append(ld)
            continue

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


def classify_host(host):
    """Host-level verdict (no endpoint needed) — used by the idor analyzer to skip
    per-customer tenant consoles BEFORE spending Claude tokens. A host is a
    shared-tenant console when its leftmost label is a machine-generated UUID/hash
    AND it has many siblings under one wildcard apex (=> each sibling is a different
    owner; cross-tenant testing = third-party data, over the hard line)."""
    host = (host or "").strip().lower()
    labels = host.split(".")
    leftmost = labels[0] if labels else ""
    apex = ".".join(labels[1:]) if len(labels) > 2 else host
    random_label = label_is_random(leftmost)
    siblings = es_sibling_count(apex) if random_label else 0
    shared = bool(random_label and siblings >= TENANT_MANY)
    return {"host": host, "shared_tenant": shared, "siblings": siblings,
            "apex": apex, "random_label": random_label}


def main():
    # host-classification mode: `brief_filter.py --host <fqdn>` -> JSON verdict
    if len(sys.argv) >= 3 and sys.argv[1] == "--host":
        print(json.dumps(classify_host(sys.argv[2])))
        return
    # FP-class mode: `brief_filter.py --noise` reads a JSON array on stdin and returns
    # {keep, suppressed, suppressed_count, suppressed_reasons} using the structural class
    # rules only (no ES/fan-out). The briefing pipes its submit/needs-human/vuln-lead
    # streams through this so a known noise class is killed/relabeled on a brand-new host.
    if len(sys.argv) >= 2 and sys.argv[1] == "--noise":
        try:
            leads = json.load(sys.stdin)
        except Exception:
            leads = []
        if not isinstance(leads, list):
            leads = []
        print(json.dumps(filter_noise(leads)))
        return
    try:
        leads = json.load(sys.stdin)
    except Exception:
        leads = []
    if not isinstance(leads, list):
        leads = []
    print(json.dumps(classify(leads)))


if __name__ == "__main__":
    main()

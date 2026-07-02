#!/usr/bin/env python3
"""recon_wcd.py — SAFE, unauthenticated, detect-only Web-Cache-Deception/Poisoning surfacer.

Detects the *cacheability discrepancy* (the LEAD), never the impact. THE SAFETY PRIMITIVE:
every probe carries a UNIQUE cache-buster (?cb=<rand>) so we test under OUR OWN cache key and
NEVER poison the real shared cache that serves other users (PortSwigger/Param-Miner discipline).
GET-only, no creds, no redirect-follow. Impact PoC (private data lands in cache / poison persists
in a real sink) is HUMAN-IN-THE-LOOP with an owned account — this only mints LEADs.

  scan   (stdin: host<TAB>url per line) -> LEAD JSONL on stdout

See docs/knowledge/class-cache-deception.md.
"""
import hashlib
import json
import sys
import time
from urllib.parse import urlsplit, urlunsplit

try:
    import requests
    requests.packages.urllib3.disable_warnings()  # type: ignore
except Exception:
    requests = None

TIMEOUT = 12
DELAY = 0.3                      # polite inter-request gap
UA = "Mozilla/5.0 (compatible; recon-wcd/1.0)"
_NONCE = [1000]                  # deterministic per-process nonce (no Math.random need)


def nonce():
    _NONCE[0] += 7
    return "wcd%dx" % _NONCE[0]


def add_cb(url, val):
    s = urlsplit(url)
    q = s.query
    q = (q + "&" if q else "") + "cb=" + val
    return urlunsplit((s.scheme, s.netloc, s.path or "/", q, ""))


def get(url, extra_headers=None):
    if requests is None:
        return None
    h = {"User-Agent": UA, "Accept": "*/*"}
    if extra_headers:
        h.update(extra_headers)
    try:
        r = requests.get(url, headers=h, timeout=TIMEOUT, verify=False, allow_redirects=False)
        return r
    except Exception:
        return None


def cache_state(r):
    """Return 'hit' | 'miss' | 'dynamic' | 'none' from cache headers."""
    if r is None:
        return "none"
    h = {k.lower(): v for k, v in r.headers.items()}
    xc = (h.get("x-cache", "") + " " + h.get("x-cache-status", "")).lower()
    cf = h.get("cf-cache-status", "").upper()
    age = h.get("age", "")
    cc = h.get("cache-control", "").lower()
    if "hit" in xc or cf == "HIT" or (age.isdigit() and int(age) > 0):
        return "hit"
    if cf in ("DYNAMIC", "BYPASS") or "dynamic" in xc or "no-store" in cc or "private" in cc:
        return "dynamic"
    if "miss" in xc or cf in ("MISS", "EXPIRED", "REVALIDATED", "UPDATING", "STALE"):
        return "miss"
    return "none"


def has_cache(r):
    if r is None:
        return False
    h = {k.lower() for k in r.headers.keys()}
    return bool(h & {"x-cache", "cf-cache-status", "age", "x-cache-status", "x-served-by", "via"})


def cached_twice(url, extra_headers=None):
    """GET the SAME (cache-buster) url twice; return (is_cached, status, body_len, second_resp)."""
    r1 = get(url, extra_headers); time.sleep(DELAY)
    r2 = get(url, extra_headers); time.sleep(DELAY)
    if r2 is None:
        return False, None, 0, None
    st = cache_state(r2)
    is_c = st == "hit"
    return is_c, r2.status_code, len(r2.content or b""), r2


WCD_SUFFIXES = ["/{n}.css", "/{n}.js", ";{n}.css", "%23{n}.css"]
WCP_HEADERS = ["X-Forwarded-Host", "X-Forwarded-Scheme", "X-Host",
               "X-Forwarded-Server", "X-Original-URL", "X-Forwarded-Prefix"]


def probe(host, url):
    leads = []
    # baseline (cache-busted) — is there a cache here at all, and is the base dynamic/private?
    base = get(add_cb(url, nonce()))
    if base is None or not has_cache(base):
        return leads                      # no cache fronting this host → no WCD/WCP
    base_state = cache_state(base)
    base_len = len(base.content or b"")
    base_cached = base_state == "hit"

    # ---- Varnish unauth-PURGE CANDIDATE (detect-only; the PURGE itself is operator-on-demand) ----
    # X-Varnish header (two ints = HIT) or Via/Server=varnish ⇒ Varnish fronting. An unauth HTTP PURGE
    # returning 200/204 is a reportable bug on its own, but PURGE is state-changing (not GET/HEAD/OPTIONS)
    # so the autonomous loop only FLAGS it — `recon-wcd purge <host>` fires the single confirm (operator).
    bh = {k.lower(): v for k, v in base.headers.items()}
    if "x-varnish" in bh or "varnish" in (bh.get("via", "") + " " + bh.get("server", "")).lower():
        ev_hdr = ("X-Varnish: " + bh["x-varnish"]) if "x-varnish" in bh else ("Via: " + bh.get("via", "")).strip()
        leads.append({
            "host": host, "url": url, "class": "cache-purge",
            "kind": "varnish-purge-candidate", "severity": "medium",
            "evidence": "Varnish cache detected (%s) — test unauth HTTP PURGE (200/204=reportable, 403/405=secure)" % ev_hdr,
            "probe": "PURGE " + (urlsplit(url).path or "/"), "base_state": base_state,
        })

    # ---- WCD: path-confusion variant of a NON-cached base becomes cacheable + same body ----
    if not base_cached:
        s = urlsplit(url)
        path = s.path or "/"
        for suf in WCD_SUFFIXES:
            n = nonce()
            vpath = path.rstrip("/") + suf.format(n=n)
            vurl = add_cb(urlunsplit((s.scheme, s.netloc, vpath, "", "")), nonce())
            is_c, st, vlen, r2 = cached_twice(vurl)
            if is_c and st and 200 <= st < 300 and base_len > 0 \
                    and abs(vlen - base_len) <= max(64, base_len * 0.2):
                leads.append({
                    "host": host, "url": url, "class": "web-cache-deception",
                    "kind": "wcd-path-confusion", "severity": "medium",
                    "evidence": "base not-cached (%s) but %s is CACHED with ~same body (origin ignored suffix)" % (base_state, vpath),
                    "probe": vpath, "base_state": base_state,
                })
                break

    # ---- WCP: unkeyed header reflected into a cacheable response (under OUR cb key) ----
    for hdr in WCP_HEADERS:
        canary = "cnry%s.example.com" % nonce()
        purl = add_cb(url, nonce())
        is_c, st, _vlen, r2 = cached_twice(purl, {hdr: canary})
        if r2 is not None and canary in (r2.text or "") and is_c:
            leads.append({
                "host": host, "url": url, "class": "web-cache-poisoning",
                "kind": "wcp-unkeyed-header", "severity": "high",
                "evidence": "unkeyed header %s reflected into a CACHED response (under our cache-buster key)" % hdr,
                "probe": hdr, "base_state": base_state,
            })
            break
    return leads


def cmd_scan():
    ts = None
    for line in sys.stdin:
        line = line.rstrip("\n")
        if not line:
            continue
        parts = line.split("\t")
        host = parts[0].strip()
        url = parts[1].strip() if len(parts) > 1 and parts[1].strip() else "https://%s" % host
        if not host:
            continue
        try:
            for lead in probe(host, url):
                sys.stdout.write(json.dumps(lead) + "\n")
                sys.stdout.flush()
        except Exception:
            continue


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "scan":
        cmd_scan()
    else:
        sys.stderr.write("usage: recon_wcd.py scan   (host<TAB>url on stdin)\n")
        sys.exit(2)

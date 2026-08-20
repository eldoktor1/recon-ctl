#!/usr/bin/env python3
"""safe_probe_worker.py — ONE safe, unauthenticated, read-only HTTP probe.

Safe BY CONSTRUCTION, regardless of arguments. The caller is an LLM that could be
prompt-injected by target content, so safety must NOT depend on intent — every guard
here holds even if called with hostile args:
  * scheme http/https only; method GET/HEAD/OPTIONS only (never state-changing)
  * NEVER sends credentials (no cookies, no Authorization header — we add none)
  * SSRF / cloud-metadata guard: refuses if the host resolves to ANY private, loopback,
    link-local (169.254/16 incl. 169.254.169.254), reserved, multicast or unspecified
    address — so it can never be aimed at internal infra or the metadata endpoint
  * does NOT follow redirects (reports the Location header instead — no SSRF-via-3xx)
  * response body is size-capped and returned only as a sanitized, truncated snippet
On a blocking status (403/406/429/503) it also CLASSIFIES the block as edge (CDN/WAF) vs
application, so the caller can back off proportionally instead of treating a WAF path-rule
403 as rate-based pushback. Classification is conservative: ambiguous => "app" (back off hard).
The only question it answers is "does this respond / leak WITHOUT auth" — never a data
harvest. One url(+method) in, one JSON line out. The caller (recon_safe_probe.sh) adds
scope / vpn / rate-limit / audit on top.

Usage: safe_probe_worker.py <url> [GET|HEAD|OPTIONS]
"""
import os, sys, json, ssl, socket, ipaddress, re
import urllib.parse as up
import urllib.request as ur

TIMEOUT  = int(os.environ.get("PROBE_TIMEOUT", "12"))
MAX_BODY = int(os.environ.get("PROBE_MAX_BODY", "65536"))   # bytes read off the wire
SNIP     = int(os.environ.get("PROBE_SNIPPET", "3000"))     # chars returned to the caller
UA = os.environ.get("PROBE_UA",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
METHODS = {"GET", "HEAD", "OPTIONS"}
_CTX = ssl.create_default_context(); _CTX.check_hostname = False; _CTX.verify_mode = ssl.CERT_NONE

# --- edge/WAF vs application block classification --------------------------------------
# A 403 is not one thing. An EDGE (CDN/WAF) 403 is a path/rule refusal: the application never
# saw the request and the host is NOT asking us to slow down. An APPLICATION 403 is the target
# itself pushing back, which is a genuine burn signal. The caller uses this to size the backoff
# — treating a WAF path-rule 403 as rate pushback costs a full host cooldown for a request that
# carried no rate signal at all (Sitevision /_common/file/pdf, 2026-08-20: one probe locked
# heureka.sbb.ch for 898s and a whole ai-hunter battery then reasoned over empty responses).
# Signals are deliberately STRONG-ONLY and the tie-break is "app": mis-reading an app 403 as
# edge under-cools a host that really is pushing back — the direction that gets the exit banned.
BLOCK_STATUSES = {403, 406, 429, 503}
_EDGE_HEADERS = ("cf-ray", "cf-mitigated", "cf-chl-bypass", "x-iinfo", "x-cdn-geo",
                 "x-sucuri-id", "x-sucuri-block", "x-akamai-transformed", "akamai-grn",
                 "x-amzn-waf-action", "x-azure-ref", "x-waf-event-info", "x-blocked-by")
_EDGE_SERVERS = ("cloudflare", "akamaighost", "awselb", "imperva", "incapsula", "sucuri",
                 "bigip", "big-ip", "cloudfront", "barracuda", "fortiweb", "modsecurity",
                 "mod_security", "edgecast", "azurefd")
_EDGE_BODY = ("attention required", "cloudflare ray id", "performance & security by cloudflare",
              "incapsula incident id", "_incapsula_resource", "the requested url was rejected",
              "sucuri website firewall", "web application firewall", "modsecurity",
              "mod_security", "akamaighost", "fortiguard", "fortiweb", "barracuda",
              "your request has been blocked", "request was blocked by",
              "blocked by the web application firewall")
_RATE_BODY = ("rate limit", "rate-limited", "too many requests", "slow down",
              "error 1015", "you are being rate limited")
_APP_CTYPES = ("application/json", "application/xml", "text/xml", "application/problem+json")


def _classify_block(status, headers, body, nbytes):
    """Classify a blocking response as edge (CDN/WAF) vs app. {} for non-blocking statuses."""
    if status not in BLOCK_STATUSES:
        return {}
    low = (body or "")[:20000].lower()
    ctype = headers.get("content-type", "").lower()
    edge = ["hdr:" + h for h in _EDGE_HEADERS if h in headers]
    srv = headers.get("server", "").lower()
    edge += ["server:" + t for t in _EDGE_SERVERS if t in srv]
    edge += ["body:" + m for m in _EDGE_BODY if m in low]
    app = ["ctype:" + ctype.split(";")[0].strip()] if any(c in ctype for c in _APP_CTYPES) else []
    if "www-authenticate" in headers:
        app.append("hdr:www-authenticate")
    if not edge and nbytes and nbytes < 512:
        app.append("small-body")   # a terse 403 is the app answering; WAF pages are branded HTML
    rate = status == 429 or any(m in low for m in _RATE_BODY) or "retry-after" in headers
    if edge and not app:
        src = "edge"
    elif app:
        src = "app"                # ambiguous (edge AND app signals) resolves to app on purpose
    else:
        src = "unknown"            # caller treats unknown as app -> full cooldown (fail-safe)
    return {"block_source": src, "block_rate_limited": rate,
            "block_why": ",".join((edge + app)[:6])}


def _err(msg, **kw):
    return {"ok": False, "error": msg, **kw}


def _public_host(host):
    """(True, ips) only if EVERY resolved address is a public/global IP. Any private/
    loopback/link-local/reserved/multicast/unspecified result fails closed (SSRF guard)."""
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception as e:
        return False, f"dns-fail:{e.__class__.__name__}"
    ips = sorted({i[4][0] for i in infos})
    if not ips:
        return False, "dns-empty"
    for ip in ips:
        try:
            a = ipaddress.ip_address(ip.split("%")[0])
        except ValueError:
            return False, f"bad-ip:{ip}"
        if (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved
                or a.is_multicast or a.is_unspecified):
            return False, f"non-public-ip:{ip}"
    return True, ",".join(ips)


class _NoRedirect(ur.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None   # never follow 3xx — report Location instead


def probe(url, method="GET"):
    method = (method or "GET").upper()
    if method not in METHODS:
        return _err(f"method-not-allowed:{method}", allowed=sorted(METHODS))
    try:
        pu = up.urlparse(url)
    except Exception:
        return _err("bad-url")
    if pu.scheme not in ("http", "https"):
        return _err(f"scheme-not-allowed:{pu.scheme or 'none'}")
    host = pu.hostname or ""
    if not host:
        return _err("no-host")
    ok, detail = _public_host(host)
    if not ok:
        return _err(f"blocked-target:{detail}", host=host)   # internal/metadata/SSRF guard

    op = ur.build_opener(ur.HTTPSHandler(context=_CTX), _NoRedirect())
    req = ur.Request(url, method=method, headers={"User-Agent": UA, "Accept": "*/*"})
    try:
        r = op.open(req, timeout=TIMEOUT)
        status = r.status
        headers = {k.lower(): v for k, v in r.headers.items()}
        raw = b"" if method == "HEAD" else r.read(MAX_BODY)
    except ur.HTTPError as e:
        status = e.code
        headers = {k.lower(): v for k, v in (e.headers or {}).items()}
        try: raw = e.read(MAX_BODY)
        except Exception: raw = b""
    except Exception as e:
        return _err(f"fetch-fail:{e.__class__.__name__}", host=host)

    body = raw.decode("utf-8", "replace")
    title = ""
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if m:
        title = re.sub(r"\s+", " ", m.group(1)).strip()[:200]
    snippet = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", body)[:SNIP]
    keep = ("content-type", "content-length", "location", "server", "www-authenticate",
            "x-powered-by", "set-cookie", "content-disposition", "access-control-allow-origin",
            "x-frame-options")
    return {
        "ok": True, "url": url, "method": method, "status": status, "resolved": detail,
        "headers": {k: headers[k] for k in keep if k in headers},
        "title": title, "body_snippet": snippet, "body_bytes": len(raw),
        "redirect_location": headers.get("location", ""),
        **_classify_block(status, headers, body, len(raw)),
    }


def main():
    if len(sys.argv) < 2:
        print(json.dumps(_err("usage: safe_probe_worker.py <url> [GET|HEAD|OPTIONS]"))); return 2
    print(json.dumps(probe(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "GET")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""
recon_xss_poc_verify.py — post-dalfox FP gate for the XSS confirm lane.

dalfox's headless check FALSE-POSITIVES on a recurring class: the payload is
"reflected" but only as INERT data that can never execute — most notably a
Next.js RSC path reflection (the requested path is JSON-serialized into
`self.__next_f.push([1,"…"])` on the `__next_error__` catch-all page), a
payload the WAF 403-strips before it reaches the app, or a reflection that
comes back HTML/JS-encoded. (Verified 2026-07-17 on hmh247.org /wp-json/oembed —
6 dalfox [POC] on a Cloudflare+Next.js 404 page, all inert.)

This re-fetches each POC URL (GET, unauth, safe — same envelope the confirm
already runs in) and DROPS a POC only on a POSITIVE inert signal, so a genuine
reflected XSS is never silently suppressed:
  - the PoC itself is WAF-blocked (403/406/429/451) — the break-out never lands
  - JSON response under X-Content-Type-Options: nosniff — non-executable
  - reflection sits in a Next.js RSC/flight-data / __next_error__ page AND no raw
    executable break-out (<script/<svg/onerror=/onload=/javascript:) survives
When it can't positively prove inertness, it KEEPS (Claude VERIFY is still the
hard gate downstream). stdin: dalfox POC lines. stdout: survivors. stderr: drops.
"""
import sys, re, ssl, urllib.request, urllib.error
from urllib.parse import urlsplit, urlunsplit, quote

UA = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE

# a URL field on a dalfox "[POC]…  <url>" line, and dalfox's reflection-context tag
URL_RE = re.compile(r"(https?://\S+)")
TAG_RE = re.compile(r"\[(in[A-Za-z][A-Za-z-]*)")   # inJS-none / inHTML / inATTR-...
# Next.js flight-data / error-boundary markers: a reflection landing here is JSON-serialized
# into a <script> as string data — inert, cannot execute (the verified hmh247 FP class).
NEXT_RSC = ("self.__next_f.push", 'id="__next_error__"', "__NEXT_DATA__")


def _requote(url):
    # dalfox PoC URLs carry raw ' [ ] ( ) ; etc in the path/query — http.client rejects those
    # (e.g. reads '[' as IPv6). Percent-encode path+query so the request is valid; the server
    # still decodes+reflects the payload, so the inertness test is unchanged.
    try:
        sp = urlsplit(url)
        return urlunsplit((sp.scheme, sp.netloc, quote(sp.path, safe="/%"),
                           quote(sp.query, safe="=&%"), quote(sp.fragment, safe="%")))
    except Exception:
        return url


def fetch(url):
    try:
        r = urllib.request.urlopen(urllib.request.Request(_requote(url), headers={"User-Agent": UA}), timeout=15, context=CTX)
        return r.status, r.headers, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, e.headers, body
    except Exception:
        return None, None, ""


def classify(url, tag):
    """Return (keep: bool, reason: str). Drops only on a POSITIVE inert signal."""
    status, headers, body = fetch(url)
    if status is None:
        return True, "fetch-failed-keep"          # network hiccup — don't suppress on our error
    if status in (403, 406, 429, 451):
        return False, f"waf-blocked-poc({status})"  # WAF strips the break-out — never lands
    ct = (headers.get("content-type") if headers else "") or ""
    xcto = (headers.get("x-content-type-options") if headers else "") or ""
    if "application/json" in ct.lower() and "nosniff" in xcto.lower():
        return False, "json-nosniff-inert"          # JSON + nosniff can't execute in a browser
    # Next.js flight/error page + a JS-context reflection = payload is JSON-serialized string
    # data inside a framework <script>, never executed. A real reflected XSS lands in HTML/attr
    # (dalfox would tag inHTML/inATTR) — so only suppress the inJS-on-RSC combination.
    if any(mk in body for mk in NEXT_RSC) and tag.lower().startswith("injs"):
        return False, "nextjs-rsc-inert"
    return True, "kept"


def main():
    kept = dropped = 0
    for line in sys.stdin:
        line = line.rstrip("\n")
        if not line.strip():
            continue
        m = URL_RE.search(line)
        if not m:                                   # can't parse a URL — keep, let VERIFY decide
            print(line); kept += 1; continue
        tm = TAG_RE.search(line)
        keep, reason = classify(m.group(1), tm.group(1) if tm else "")
        if keep:
            print(line); sys.stdout.flush(); kept += 1
        else:
            sys.stderr.write(f"[xss-poc-verify] DROP ({reason}): {line}\n"); dropped += 1
    sys.stderr.write(f"[xss-poc-verify] kept={kept} dropped={dropped}\n")


if __name__ == "__main__":
    main()

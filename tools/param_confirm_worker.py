#!/usr/bin/env python3
"""param_confirm_worker.py — SAFE differential confirmation for SSTI / open-redirect /
SQLi on a single URL. "Detection != exploitation": these are precise, NON-DESTRUCTIVE,
UNAUTHENTICATED differential probes that prove *injectable/redirectable*, never a data
harvest or RCE (hard line). One URL+class in, one JSON line out. Caller is VPN-gated.

  ssti     inject {{a*b}} / ${a*b} / <%=a*b%> / #{a*b} with a unique product; CONFIRMED
           only if the response contains the PRODUCT and not the literal expression and
           the baseline did not already contain it (template actually evaluated math).
  redirect inject an arbitrary sentinel host into the param; CONFIRMED only if the 3xx
           Location header points at that sentinel host (we do NOT follow it).
  sqli     inject `'` vs `''`; CONFIRMED only if a DB error signature appears with the
           single quote and NOT with the doubled/baseline (classic error-based). No
           UNION/stacked/data extraction, no time-based load.

Usage: param_confirm_worker.py <url> <ssti|redirect|sqli>
Env:   PC_TIMEOUT(10) PC_MAX_PARAMS(4) PC_SENTINEL(canary-d0k-oob.example)
"""
import os, sys, json, ssl, random
import urllib.parse as up
import urllib.request as ur

TIMEOUT   = int(os.environ.get("PC_TIMEOUT", "10"))
MAX_PARAMS = int(os.environ.get("PC_MAX_PARAMS", "4"))
SENTINEL  = os.environ.get("PC_SENTINEL", "canary-d0k-oob.example")
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
_CTX = ssl.create_default_context(); _CTX.check_hostname = False; _CTX.verify_mode = ssl.CERT_NONE

SQL_ERRORS = [
    "you have an error in your sql syntax", "warning: mysql", "mysql_fetch",
    "unclosed quotation mark after the character string", "quoted string not properly terminated",
    "pg::syntaxerror", "postgresql", "ora-00933", "ora-01756", "sqlite3::", "sqlite_error",
    "odbc sql server driver", "microsoft ole db provider for sql server", "psqlexception",
    "sqlstate[", "syntax error at or near", "unterminated quoted string",
]


class _NoRedirect(ur.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _fetch(url, follow=True):
    """Returns (status, headers_dict, body_text). follow=False captures 3xx Location.
    NB: OpenerDirector.open() takes no context= kwarg — TLS context goes on HTTPSHandler."""
    handlers = [ur.HTTPSHandler(context=_CTX)]
    if not follow:
        handlers.append(_NoRedirect())
    op = ur.build_opener(*handlers)
    req = ur.Request(url, headers={"User-Agent": UA})
    try:
        r = op.open(req, timeout=TIMEOUT)
        return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(300000).decode("utf-8", "replace")
    except ur.HTTPError as e:
        try: body = e.read(300000).decode("utf-8", "replace")
        except Exception: body = ""
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, body
    except Exception:
        return 0, {}, ""


def _set_param(pu, q, idx, val):
    nq = list(q); nq[idx] = (q[idx][0], val)
    return up.urlunparse(pu._replace(query=up.urlencode(nq, doseq=True)))


def confirm(url, cls):
    res = {"url": url, "class": cls, "confirmed": False}
    pu = up.urlparse(url)
    q = up.parse_qsl(pu.query, keep_blank_values=True)
    if not q:
        res["skip"] = "no-query-params"; return res
    _, _, baseline = _fetch(url)

    for idx, (param, _v) in enumerate(q[:MAX_PARAMS]):
        if cls == "ssti":
            a, b = random.randint(1000, 9999), random.randint(1000, 9999)
            prod = str(a * b)
            for expr in (f"{{{{{a}*{b}}}}}", f"${{{a}*{b}}}", f"<%= {a}*{b} %>", f"#{{{a}*{b}}}"):
                if prod in baseline:
                    continue  # coincidental; skip
                _, _, body = _fetch(_set_param(pu, q, idx, expr))
                if prod in body and expr not in body:
                    res.update(confirmed=True, param=param, payload=expr,
                               evidence=f"template evaluated {a}*{b}={prod}", context="ssti-eval")
                    return res

        elif cls == "redirect":
            for inj in (f"https://{SENTINEL}/", f"//{SENTINEL}/", f"https:/{SENTINEL}/", f"/\\{SENTINEL}/"):
                st, hd, _ = _fetch(_set_param(pu, q, idx, inj), follow=False)
                loc = hd.get("location", "")
                if 300 <= st < 400 and loc:
                    lh = up.urlparse(loc if "//" in loc else "//" + loc).hostname or ""
                    if lh == SENTINEL:
                        res.update(confirmed=True, param=param, payload=inj,
                                   evidence=f"3xx Location -> {loc}", context="open-redirect")
                        return res

        elif cls == "sqli":
            _, _, b_single = _fetch(_set_param(pu, q, idx, (_v or "1") + "'"))
            _, _, b_double = _fetch(_set_param(pu, q, idx, (_v or "1") + "''"))
            lo_s, lo_d, lo_b = b_single.lower(), b_double.lower(), baseline.lower()
            hit = next((e for e in SQL_ERRORS if e in lo_s and e not in lo_d and e not in lo_b), None)
            if hit:
                res.update(confirmed=True, param=param, payload="' (single quote)",
                           evidence=f"DB error on ' not on '' : {hit}", context="sqli-error-diff")
                return res
    return res


def main():
    if len(sys.argv) < 3:
        print(json.dumps({"error": "usage: param_confirm_worker.py <url> <ssti|redirect|sqli>"})); return 2
    print(json.dumps(confirm(sys.argv[1], sys.argv[2])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

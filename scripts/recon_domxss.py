#!/usr/bin/env python3
# =============================================================================
# recon_domxss.py — DOM-XSS source->sink miner (the lane reflected-confirm is BLIND to).
#
# WHY: dalfox/reflected-confirm only catch SERVER-reflected XSS. DOM XSS lives in the
# CLIENT JS — a tainted SOURCE (location.hash/search/href, document.referrer, window.name,
# postMessage) flowing into a dangerous SINK (innerHTML, document.write, eval, jQuery .html(),
# dangerouslySetInnerHTML, location=) with no sanitization. Commodity scanners miss it; reading
# the JS is the edge (the MOTTO). This tool fetches a host's JS and surfaces the sink hits WITH
# CODE CONTEXT + nearby-source taint flag, so Claude can reason about real exploitable flows.
#
# Target-facing (fetches page + JS) -> OPERATOR runs it on Mullvad; Claude analyzes the output.
# Read-only GETs only; no injection, no execution. Just downloads + greps + prints context.
#
# Usage: recon_domxss.py <url-or-host> [--max-js N] [--ctx C]
#   webviews.monzo.com           -> https://webviews.monzo.com/
#   https://host/path?x=1        -> that exact page
# Output: per-JS, HIGH (sink with a SOURCE within the window = likely flow) then MED (sink only),
#   with a context snippet. Plus the source vectors seen (suggested PoC params).
# =============================================================================
import sys, re, subprocess, hashlib, os, argparse
from urllib.parse import urljoin, urlsplit

UA = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"

# DOM-XSS DANGEROUS SINKS (assignment/execution that renders/executes a string)
SINKS = [
    (r'\.innerHTML\s*=', 'innerHTML='), (r'\.outerHTML\s*=', 'outerHTML='),
    (r'\.insertAdjacentHTML\s*\(', 'insertAdjacentHTML'),
    (r'document\.write(?:ln)?\s*\(', 'document.write'),
    (r'\beval\s*\(', 'eval'), (r'\bFunction\s*\(', 'Function()'),
    (r'set(?:Timeout|Interval)\s*\(\s*["\'`]', 'setTimeout(str)'),
    (r'\.html\s*\(', 'jQuery.html()'), (r'\.(?:append|prepend|before|after|replaceWith)\s*\(', 'jQuery.append'),
    (r'dangerouslySetInnerHTML', 'React.dSIH'), (r'v-html', 'Vue.v-html'),
    (r'bypassSecurityTrust(?:Html|Script|Url|ResourceUrl)', 'Angular.bypass'),
    (r'\.(?:src|href|action)\s*=(?!=)', 'url-sink(src/href)'),
    (r'(?:window\.)?location\s*=(?!=)', 'location='),
    (r'location\.(?:href|assign|replace)\s*[=(]', 'location.assign'),
    (r'\.setAttribute\s*\(\s*["\'`](?:src|href|on\w+)', 'setAttribute(src/on*)'),
    (r'jQuery\s*\(|\$\s*\(', 'jQuery($)-selector'),
]
# TAINTED SOURCES (attacker-controllable, no auth needed)
SOURCES = [
    (r'location\.hash', 'location.hash'), (r'location\.search', 'location.search'),
    (r'location\.href', 'location.href'), (r'location\.pathname', 'location.pathname'),
    (r'document\.URL', 'document.URL'), (r'document\.documentURI', 'document.documentURI'),
    (r'document\.referrer', 'document.referrer'), (r'window\.name', 'window.name'),
    (r'\.postMessage|addEventListener\s*\(\s*["\'`]message', 'postMessage'),
    (r'URLSearchParams|getParameter|\bgetQuery|\bqs\.parse|parseQuery', 'queryparser'),
    (r'document\.cookie', 'document.cookie'),
]
SINK_RE = [(re.compile(p), n) for p, n in SINKS]
SRC_RE = [(re.compile(p), n) for p, n in SOURCES]
# vendor bundles where a hit is almost always framework-internal (deprioritize, don't drop)
VENDOR = re.compile(r'(jquery[.-]|react(?:-dom)?\.production|angular\.min|vue\.runtime|polyfill|'
                    r'chunk-vendors|runtime[.-]|bootstrap\.min|lodash|moment\.min)', re.I)

# TRUE HTML-injection / code-exec sinks (real DOM XSS) — vs mere navigation (open-redirect-ish, lower).
HTML_SINK = {'innerHTML=', 'outerHTML=', 'insertAdjacentHTML', 'document.write', 'eval', 'Function()',
             'setTimeout(str)', 'jQuery.html()', 'React.dSIH', 'Vue.v-html', 'Angular.bypass',
             'setAttribute(src/on*)'}
NAV_SINK = {'url-sink(src/href)', 'location=', 'location.assign'}
# library code-window signatures that produce the navigation/append FPs (FileSaver, router/history,
# URLSearchParams builder) — if the sink window matches, it's framework plumbing, not a taint flow.
LIB_FP = re.compile(r'createObjectURL|readAsDataURL|msSaveBlob|FileReader|saveAs|'
                    r'pushState|replaceState|confirmTransitionTo|history|popstate|'
                    r'URLSearchParams|\.append\([^)]{0,40}(?:date|id|page|sort|key|param)', re.I)


def curl(url, out=None):
    cmd = ["curl", "-sSkL", "-m", "20", "-A", UA, url]
    if out:
        cmd += ["-o", out]; subprocess.run(cmd, capture_output=True); return None
    r = subprocess.run(cmd, capture_output=True, text=True, errors="ignore")
    return r.stdout


def extract_js(html, base):
    urls = set()
    for m in re.finditer(r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']', html, re.I):
        urls.add(urljoin(base, m.group(1)))
    for m in re.finditer(r'["\']([^"\']+?\.js(?:\?[^"\']*)?)["\']', html):  # bundles referenced in inline JS
        u = m.group(1)
        if u.startswith(("http", "/", "./", "../")) or re.match(r'^[\w./-]+\.js', u):
            urls.add(urljoin(base, u))
    return sorted(urls)


def scan(js, ctx):
    hits = []
    for sre, sname in SINK_RE:
        for m in sre.finditer(js):
            a = max(0, m.start() - ctx); b = min(len(js), m.end() + ctx)
            window = js[a:b]
            srcs = sorted({sn for sr, sn in SRC_RE if sr.search(window)})
            snippet = re.sub(r'\s+', ' ', window).strip()
            hits.append({"sink": sname, "srcs": srcs, "pos": m.start(), "snippet": snippet})
    return hits


def main():
    ap = argparse.ArgumentParser(prog="recon-domxss")
    ap.add_argument("target")
    ap.add_argument("--max-js", type=int, default=40)
    ap.add_argument("--ctx", type=int, default=160)
    a = ap.parse_args()
    target = a.target if a.target.startswith("http") else "https://" + a.target
    base = target
    host = urlsplit(target).netloc
    print(f"[domxss] {target}")
    html = curl(target) or ""
    jsurls = extract_js(html, base)
    # same-site first, then others; cap
    same = [u for u in jsurls if urlsplit(u).netloc == host]
    other = [u for u in jsurls if urlsplit(u).netloc != host]
    jsurls = (same + other)[:a.max_js]
    print(f"[domxss] {len(jsurls)} JS bundle(s) ({len(same)} same-site)")
    # inline page scripts count too
    corpus = [("(inline-html)", html)]
    wd = "/tmp/domxss_" + hashlib.md5(host.encode()).hexdigest()[:8]
    os.makedirs(wd, exist_ok=True)
    for u in jsurls:
        f = os.path.join(wd, hashlib.md5(u.encode()).hexdigest()[:12] + ".js")
        curl(u, f)
        try:
            corpus.append((u, open(f, encoding="utf-8", errors="ignore").read()))
        except Exception:
            pass
    high, review, nav, libfp = [], [], [], 0
    src_seen = set()
    for name, body in corpus:
        if not body:
            continue
        for h in scan(body, a.ctx):
            if LIB_FP.search(h["snippet"]):       # FileSaver/router/URLSearchParams plumbing = drop
                libfp += 1; continue
            src_seen |= set(h["srcs"])
            rec = (name.split("/")[-1][:40], h)
            if h["sink"] in HTML_SINK:
                (high if h["srcs"] else review).append(rec)   # HTML sink: HIGH if tainted, else REVIEW
            elif h["sink"] in NAV_SINK and h["srcs"]:
                nav.append(rec)                                # navigation+source = open-redirect-ish
    print(f"\n===== HIGH — HTML/exec sink WITH a tainted source in-window (likely DOM-XSS): {len(high)} =====")
    for sn, h in high[:50]:
        print(f"\n[{h['sink']}]  src={','.join(h['srcs'])}  ({sn})")
        print("   …" + h["snippet"][:300] + "…")
    print(f"\n===== REVIEW — HTML/exec sinks, no source in ±{a.ctx} (minified spread; trace by hand): {len(review)} =====")
    # group by sink type so I can see what dangerous primitives exist + read a few
    from collections import Counter
    rc = Counter(h["sink"] for _, h in review)
    print("   sink types: " + (", ".join(f"{k}×{v}" for k, v in rc.most_common()) or "none"))
    for sn, h in review[:18]:
        print(f"[{h['sink']}] ({sn})  …{h['snippet'][:170]}…")
    print(f"\n===== sources seen (PoC vectors): {', '.join(sorted(src_seen)) or 'none'} =====")
    print(f"===== nav/open-redirect sinks w/source: {len(nav)} | library-FP filtered: {libfp} =====")
    print(f"[domxss] done. JS cached in {wd}")


if __name__ == "__main__":
    sys.exit(main())

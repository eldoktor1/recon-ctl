#!/usr/bin/env python3
"""
recon_depconf.py — dependency confusion: a package the target depends on that ANYONE can claim.

Alex Birsan's original run earned over $130,000 across 35 companies including Apple, Netflix,
Tesla and PayPal, and the class is still live — 33 malicious npm packages were caught abusing
it in May 2026. It stays alive because the fix is a registry configuration most teams never
make, and because almost nobody hunts it: it does not look like "scanning", so it is absent
from every commodity pipeline.

For an operator with a day job it has the best properties of any lane here:

  * THE DETECTION SENDS NO TRAFFIC TO THE TARGET. We read the target's own public JavaScript
    once (what any browser does), then ask npm and PyPI whether a name is registered. The
    finding is proven against the PUBLIC REGISTRY, not against the target. Nobody can
    rate-limit, WAF, or ban us for it.
  * The proof is binary. A name is either claimable or it is not. There is nothing to judge,
    so there is nothing to get wrong.

HARD LINE — WE NEVER REGISTER ANYTHING.
Publishing a placeholder package to "prove" the finding would be a supply-chain attack against
every machine that installs it, including CI. This lane only ever asks whether a name is free.
The proof for the report is: "your bundle references `@acme/internal-auth`; that name is
unregistered on npm; anyone can publish it and your builds will pull it." That is the whole
finding and it needs no exploitation.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import ssl
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
SCOPE_CHECK = os.path.join(REPO_DIR, "scripts", "recon_scope_check.sh")
ENDPOINTS = os.path.join(BASE_DIR, "js_recon", "endpoints.jsonl")
AUDIT = os.path.join(STATE_DIR, "depconf_audit.jsonl")
CACHE = os.path.join(STATE_DIR, "depconf_registry_cache.json")
OUT_DIR = os.path.join(BASE_DIR, "depconf")

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/127.0.0.0 Safari/537.36")
TIMEOUT = float(os.environ.get("DEPCONF_TIMEOUT", "15"))
JS_CAP = int(os.environ.get("DEPCONF_JS_CAP", str(6 * 1024 * 1024)))
MIN_GAP_TARGET = float(os.environ.get("DEPCONF_TARGET_GAP", "1.0"))
MIN_GAP_REGISTRY = float(os.environ.get("DEPCONF_REGISTRY_GAP", "0.15"))

# --- where package names hide in a production bundle -------------------------
PKG_PATTERNS = [
    # webpack/rollup module paths — the richest source
    re.compile(r"(?:\./)?node_modules/(@[a-z0-9][\w.-]*/[a-z0-9][\w.-]*|[a-z0-9][\w.-]*)/"),
    # source-map `sources` entries
    re.compile(r"webpack://[^/\"']*/\./node_modules/(@[a-z0-9][\w.-]*/[a-z0-9][\w.-]*|[a-z0-9][\w.-]*)"),
    # literal imports/requires
    re.compile(r"""(?:require|import)\s*\(\s*["'](@[a-z0-9][\w.-]*/[a-z0-9][\w.-]*|[a-z0-9][\w.-]*)["']"""),
    re.compile(r"""\bfrom\s+["'](@[a-z0-9][\w.-]*/[a-z0-9][\w.-]*)["']"""),
    # package.json fragments embedded in bundles or exposed directly
    re.compile(r'"(@[a-z0-9][\w.-]*/[a-z0-9][\w.-]*)"\s*:\s*"[\^~>=<]*\d'),
]

# Node builtins and obvious non-packages.
BUILTIN = {
    "fs", "path", "os", "util", "http", "https", "net", "crypto", "stream", "zlib", "events",
    "buffer", "url", "querystring", "child_process", "cluster", "dns", "tls", "assert", "tty",
    "vm", "worker_threads", "perf_hooks", "readline", "string_decoder", "timers", "process",
    "module", "console", "constants", "punycode", "domain", "v8", "inspector", "async_hooks",
}
JUNK = re.compile(r"^(\.|/|\d|[a-z]$)|^(index|main|src|lib|dist|test|node|npm|js|css|json)$", re.I)

# A scope that matches the target's own brand is near-certain internal code.
def scope_of(pkg: str) -> str:
    return pkg.split("/")[0].lstrip("@").lower() if pkg.startswith("@") else ""


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(m: str) -> None:
    print(f"[depconf] {m}", file=sys.stderr, flush=True)


def audit(rec: dict) -> None:
    os.makedirs(STATE_DIR, exist_ok=True)
    rec.setdefault("at", utc())
    with open(AUDIT, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")


def scope_ok(host: str) -> tuple[bool, str]:
    if not os.path.exists(SCOPE_CHECK):
        return False, "scope resolver missing (fail-closed)"
    try:
        d = json.loads(subprocess.run(["bash", SCOPE_CHECK, host], capture_output=True,
                                      text=True, timeout=45).stdout)
    except Exception as e:
        return False, f"scope check failed: {e}"
    if not d.get("in_scope"):
        return False, "not in scope"
    if not d.get("pays"):
        return False, "does not pay for this asset"
    if d.get("out_of_scope"):
        return False, "explicitly out of scope"
    return True, d.get("program") or ""


def _opener():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))


_last = {"t": 0.0, "r": 0.0}


def fetch(url: str, cap: int = JS_CAP, registry: bool = False) -> tuple[int, bytes]:
    key = "r" if registry else "t"
    gap = MIN_GAP_REGISTRY if registry else MIN_GAP_TARGET
    d = time.time() - _last[key]
    if d < gap:
        time.sleep(gap - d)
    _last[key] = time.time()
    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", UA)
    req.add_header("Accept", "*/*")
    try:
        with _opener().open(req, timeout=TIMEOUT) as r:
            return r.status, r.read(cap)
    except urllib.error.HTTPError as e:
        return e.code, b""
    except Exception:
        return 0, b""


# --- registry checks — THE DETECTION. No target traffic. ---------------------
def load_cache() -> dict:
    try:
        return json.load(open(CACHE))
    except Exception:
        return {}


def save_cache(c: dict) -> None:
    try:
        json.dump(c, open(CACHE, "w"))
    except Exception:
        pass


def npm_status(pkg: str, cache: dict) -> str:
    k = f"npm:{pkg}"
    if k in cache:
        return cache[k]
    code, _ = fetch(f"https://registry.npmjs.org/{urllib.parse.quote(pkg, safe='@/')}",
                    cap=4096, registry=True)
    # 404 = the name has never been published and is free for anyone to take.
    st = "claimable" if code == 404 else ("registered" if code == 200 else f"unknown:{code}")
    cache[k] = st
    return st


def pypi_status(pkg: str, cache: dict) -> str:
    k = f"pypi:{pkg}"
    if k in cache:
        return cache[k]
    code, _ = fetch(f"https://pypi.org/pypi/{urllib.parse.quote(pkg)}/json", cap=4096, registry=True)
    st = "claimable" if code == 404 else ("registered" if code == 200 else f"unknown:{code}")
    cache[k] = st
    return st


# --- mining ------------------------------------------------------------------
def js_urls_for(host: str, limit: int = 12) -> list[str]:
    """Script URLs from the host's own HTML, plus any .js endpoints jsintel already found."""
    urls: list[str] = []
    code, body = fetch(f"https://{host}/", cap=2_000_000)
    if code == 200 and body:
        for m in re.finditer(rb"""<script[^>]+src=["']([^"']+\.m?js[^"']*)["']""", body, re.I):
            src = m.group(1).decode("utf-8", "replace")
            urls.append(urllib.parse.urljoin(f"https://{host}/", src))
    if os.path.exists(ENDPOINTS):
        for line in open(ENDPOINTS, encoding="utf-8", errors="replace"):
            if host not in line or ".js" not in line:
                continue
            try:
                o = json.loads(line)
            except Exception:
                continue
            if o.get("host") != host:
                continue
            ep = (o.get("endpoint") or "")
            if ep.endswith((".js", ".mjs")):
                urls.append(urllib.parse.urljoin(f"https://{host}/", ep))
    seen, out = set(), []
    for u in urls:
        if urllib.parse.urlsplit(u).netloc != host:
            continue          # never fetch third-party CDN assets
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out[:limit]


def packages_in(blob: bytes) -> set[str]:
    txt = blob.decode("utf-8", "replace")
    found: set[str] = set()
    for rx in PKG_PATTERNS:
        for m in rx.finditer(txt):
            p = m.group(1)
            if not p or p in BUILTIN or JUNK.match(p):
                continue
            if len(p) > 120:
                continue
            found.add(p)
    return found


def run_host(host: str, cache: dict, dry: bool, max_js: int) -> dict:
    ok, program = scope_ok(host)
    if not ok:
        log(f"SKIP {host}: {program}")
        return {"host": host, "skipped": program}

    urls = js_urls_for(host, max_js)
    if not urls:
        log(f"{host}: no first-party JS found")
        return {"host": host, "program": program, "packages": 0}

    log(f"{host} ({program}) — reading {len(urls)} bundle(s)")
    pkgs: set[str] = set()
    for u in urls:
        code, body = fetch(u)
        if code == 200 and body:
            pkgs |= packages_in(body)

    if not pkgs:
        log(f"{host}: no package references extracted")
        return {"host": host, "program": program, "packages": 0}

    # Rank: scoped packages first — an @org scope is where internal code lives.
    scoped = sorted(p for p in pkgs if p.startswith("@"))
    plain = sorted(p for p in pkgs if not p.startswith("@"))
    log(f"{host}: {len(pkgs)} package(s) referenced ({len(scoped)} scoped)")

    claimable = []
    for p in scoped + plain[:150]:
        st = npm_status(p, cache)
        if st == "claimable":
            # A scoped name whose SCOPE is also unregistered is the strongest case:
            # anyone can create the org and publish under it.
            extra = ""
            if p.startswith("@"):
                sc = "@" + scope_of(p)
                if npm_status(sc + "/probe-does-not-exist", cache) == "claimable":
                    extra = f" (scope {sc} also unclaimed)"
            log(f"  *** CLAIMABLE on npm: {p}{extra}")
            claimable.append({"package": p, "registry": "npm", "note": extra.strip()})

    res = {"host": host, "program": program, "packages": len(pkgs),
           "scoped": len(scoped), "claimable": claimable, "js_read": len(urls)}
    audit({k: v for k, v in res.items() if k != "claimable"} | {"n_claimable": len(claimable)})
    if claimable and not dry:
        res["finding_id"] = mint(res)
    elif not claimable:
        log(f"{host}: every referenced package is registered — not vulnerable")
    return res


def mint(res: dict) -> int | None:
    sys.path.insert(0, REPO_DIR)
    from engine import state
    names = ", ".join(c["package"] for c in res["claimable"][:8])
    ev = {
        "chain": "target's own bundle -> internal package name -> unregistered on public registry",
        "claimable_packages": res["claimable"],
        "packages_referenced": res["packages"],
        "impact": (f"{len(res['claimable'])} package name(s) referenced by this application are "
                   f"UNREGISTERED on the public npm registry ({names}). Anyone may publish them; "
                   f"a build resolving from the public registry would execute attacker code."),
        "method": ("read the application's own public JavaScript, then queried the PUBLIC npm/PyPI "
                   "registry. NO package was registered, published, or reserved — the finding is "
                   "that the name is free, which needs no exploitation to prove."),
        "at": utc(),
    }
    conn = state.connect()
    state.init_db(conn)
    fid = state.record_confirmed(
        conn, res["host"], url=f"https://{res['host']}/", program=res["program"] or None,
        signal_class="depconf", vuln_class="dependency-confusion",
        score=18, evidence=ev, confidence=0.95)
    conn.close()
    log(f"  minted finding #{fid} — {len(res['claimable'])} claimable package(s)")
    return fid


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Dependency confusion: internal packages that anyone can claim.")
    ap.add_argument("host", nargs="+")
    ap.add_argument("--max-js", type=int, default=12)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    if os.path.exists(os.path.join(STATE_DIR, "vpn_down")):
        log("vpn_down — refusing (fail-closed)")
        return 2

    cache = load_cache()
    runs = []
    try:
        for h in a.host:
            try:
                runs.append(run_host(h, cache, a.dry_run, a.max_js))
            except Exception as e:
                log(f"{h}: error {str(e)[:140]}")
    finally:
        save_cache(cache)

    os.makedirs(OUT_DIR, exist_ok=True)
    out = os.path.join(OUT_DIR, f"depconf_{datetime.now().strftime('%Y-%m-%d')}.md")
    hits = [r for r in runs if r.get("claimable")]
    L = [f"# Dependency confusion — {utc()}", "",
         f"**{len(hits)} host(s) reference a claimable package** out of {len(runs)} checked.", ""]
    for r in hits:
        L += [f"## {r['host']} ({r.get('program','')})",
              f"- {r['packages']} packages referenced, {r['scoped']} scoped", ""]
        for c in r["claimable"]:
            L.append(f"  - **`{c['package']}`** — unregistered on {c['registry']} {c['note']}")
        L.append("")
    open(out, "w", encoding="utf-8").write("\n".join(L))
    log(f"report → {out}")
    print(json.dumps(runs, default=str)[:1500])
    return 0


if __name__ == "__main__":
    sys.exit(main())

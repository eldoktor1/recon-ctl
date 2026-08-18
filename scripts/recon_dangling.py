#!/usr/bin/env python3
"""
recon_dangling.py — a dead domain in a <script src> is stored XSS on every page load.

If a page loads JavaScript from a domain whose registration has lapsed, anyone who registers
that domain executes code in the target's origin — for every visitor, on every request, with
no interaction required. It is one of the highest-impact findings that requires no exploit at
all, and almost nobody looks for it because it is not what scanners scan.

The same applies to `script-src` entries in a Content-Security-Policy header: the CSP is an
allow-list of origins permitted to run code, so an expired domain in it is a standing licence
to inject.

    page + CSP -> external script origins -> is the domain unregistered / NXDOMAIN?

The proof is registrability, established at the DNS and WHOIS layer — not at the target. So
this lane cannot be rate-limited or blocked, and the evidence does not depend on catching the
target in a particular state.

HARD LINE: we NEVER register the domain. Demonstrating that a name resolves to nothing and is
available is the entire finding; buying it would be seizing control of the target's origin,
which is exploitation, not proof. The report says "this is claimable" and stops there.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
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
AUDIT = os.path.join(STATE_DIR, "dangling_audit.jsonl")
OUT_DIR = os.path.join(BASE_DIR, "dangling")

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/127.0.0.0 Safari/537.36"
TIMEOUT = float(os.environ.get("DANG_TIMEOUT", "15"))
MIN_GAP = float(os.environ.get("DANG_MIN_GAP", "1.0"))

SCRIPT_SRC = re.compile(rb"""<script[^>]+src\s*=\s*["']([^"']+)["']""", re.I)
LINK_HREF = re.compile(rb"""<link[^>]+href\s*=\s*["']([^"']+\.js[^"']*)["']""", re.I)
CSP_ORIGIN = re.compile(r"""(?:https?:)?//([a-z0-9][a-z0-9.\-]*\.[a-z]{2,})""", re.I)

# Never flag infrastructure that is obviously alive and owned by a major provider.
KNOWN_LIVE = re.compile(
    r"(google|gstatic|googleapis|gtag|doubleclick|facebook|fbcdn|twitter|twimg|apple|"
    r"cloudflare|cloudfront|akamai|fastly|jsdelivr|unpkg|cdnjs|bootstrapcdn|jquery|"
    r"microsoft|azure|amazonaws|youtube|vimeo|hotjar|sentry\.io|newrelic|segment|"
    r"googletagmanager|adobe|typekit|fontawesome)", re.I)


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(m: str) -> None:
    print(f"[dangling] {m}", file=sys.stderr, flush=True)


def audit(rec: dict) -> None:
    os.makedirs(STATE_DIR, exist_ok=True)
    rec.setdefault("at", utc())
    with open(AUDIT, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")


def scope_ok(host: str) -> tuple[bool, str]:
    if not os.path.exists(SCOPE_CHECK):
        return False, "scope resolver missing"
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


_last = [0.0]


def get(url: str, cap: int = 3_000_000) -> tuple[int, bytes, dict]:
    gap = time.time() - _last[0]
    if gap < MIN_GAP:
        time.sleep(MIN_GAP - gap)
    _last[0] = time.time()
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx)).open(
                req, timeout=TIMEOUT) as r:
            return r.status, r.read(cap), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, b"", dict(e.headers or {})
    except Exception:
        return 0, b"", {}


def registrable(domain: str) -> str:
    """The registrable name — the part somebody could actually buy."""
    parts = domain.strip(".").lower().split(".")
    if len(parts) < 2:
        return ""
    # crude but adequate for the common multi-part public suffixes
    two = {"co.uk", "org.uk", "ac.uk", "com.au", "co.nz", "co.jp", "com.br", "co.in",
           "com.cn", "co.za", "com.mx", "co.kr", "com.tr", "com.sg"}
    if len(parts) >= 3 and ".".join(parts[-2:]) in two:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def resolves(name: str) -> bool:
    try:
        socket.getaddrinfo(name, None)
        return True
    except Exception:
        return False


def whois_free(domain: str) -> tuple[bool, str]:
    """Is the registrable domain actually unregistered? NXDOMAIN alone is not enough —
    a registered domain can simply have no A record."""
    if not shutil_which("whois"):
        return False, "whois not installed — cannot confirm registrability"
    try:
        r = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=45)
        out = (r.stdout or "").lower()
    except Exception as e:
        return False, f"whois failed: {str(e)[:60]}"
    if not out.strip():
        return False, "whois returned nothing"
    free_markers = ["no match for", "not found", "no data found", "no entries found",
                    "domain not found", "status: free", "status: available",
                    "no object found", "nothing found"]
    for m in free_markers:
        if m in out:
            return True, f"whois says unregistered ({m!r})"
    return False, "whois shows an active registration"


def shutil_which(x: str) -> str:
    import shutil
    return shutil.which(x) or ""


def origins_for(host: str) -> tuple[set[str], set[str]]:
    """External script origins from the page body and from the CSP header."""
    scripts, csp = set(), set()
    code, body, headers = get(f"https://{host}/")
    if code == 0:
        return scripts, csp
    for rx in (SCRIPT_SRC, LINK_HREF):
        for m in rx.finditer(body):
            src = m.group(1).decode("utf-8", "replace")
            if src.startswith("//"):
                src = "https:" + src
            if not src.startswith("http"):
                continue
            net = urllib.parse.urlsplit(src).netloc.split(":")[0].lower()
            if net and net != host:
                scripts.add(net)
    policy = headers.get("Content-Security-Policy") or headers.get(
        "content-security-policy") or ""
    if policy:
        for m in re.finditer(r"script-src[^;]*", policy, re.I):
            for o in CSP_ORIGIN.finditer(m.group(0)):
                net = o.group(1).lower()
                if net != host:
                    csp.add(net)
    return scripts, csp


def run_host(host: str, dry: bool) -> dict:
    ok, program = scope_ok(host)
    if not ok:
        log(f"SKIP {host}: {program}")
        return {"host": host, "skipped": program}

    scripts, csp = origins_for(host)
    cands = {o for o in (scripts | csp) if not KNOWN_LIVE.search(o)}
    if not cands:
        log(f"{host}: no third-party script origins worth checking")
        return {"host": host, "program": program, "checked": 0}

    log(f"{host} ({program}) — {len(scripts)} script origin(s), {len(csp)} CSP origin(s); "
        f"{len(cands)} to check")
    dead = []
    for o in sorted(cands):
        if resolves(o):
            continue
        reg = registrable(o)
        free, why = whois_free(reg) if reg else (False, "no registrable name")
        where = "script-src" if o in scripts else "CSP"
        log(f"  {o} does NOT resolve — registrable={reg} free={free} ({why})")
        if free:
            log(f"  *** CLAIMABLE: {reg} — referenced in {where} on {host}")
            dead.append({"origin": o, "registrable": reg, "where": where, "why": why})

    res = {"host": host, "program": program, "checked": len(cands), "dead": dead}
    audit({"host": host, "program": program, "checked": len(cands), "claimable": len(dead)})
    if dead and not dry:
        res["finding_id"] = mint(res)
    elif not dead:
        log(f"{host}: every referenced origin still resolves — clean")
    return res


def mint(res: dict) -> int | None:
    sys.path.insert(0, REPO_DIR)
    from engine import state
    d = res["dead"][0]
    ev = {
        "chain": "page/CSP -> external script origin -> domain unregistered and claimable",
        "claimable_origins": res["dead"],
        "impact": (f"`{res['host']}` loads JavaScript from `{d['origin']}` (via {d['where']}), "
                   f"whose registrable domain `{d['registrable']}` is unregistered. Anyone who "
                   f"registers it executes arbitrary script in this origin for every visitor — "
                   f"persistent XSS requiring no user interaction."),
        "method": ("confirmed at the DNS and WHOIS layer. The domain was NOT registered — "
                   "demonstrating it is claimable is the finding; buying it would be seizing "
                   "control of the target's origin."),
        "at": utc(),
    }
    conn = state.connect()
    state.init_db(conn)
    fid = state.record_confirmed(
        conn, res["host"], url=f"https://{res['host']}/", program=res["program"] or None,
        signal_class="dangling-script", vuln_class="claimable-script-origin",
        score=19, evidence=ev, confidence=0.95)
    conn.close()
    log(f"  minted finding #{fid}")
    return fid


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Find claimable domains referenced in script-src / CSP.")
    ap.add_argument("host", nargs="+")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    if os.path.exists(os.path.join(STATE_DIR, "vpn_down")):
        log("vpn_down — refusing (fail-closed)")
        return 2
    if not shutil_which("whois"):
        log("NOTE: whois is not installed — NXDOMAIN can be detected but registrability "
            "cannot be confirmed, so nothing will be minted. `sudo apt install whois`")

    runs = []
    for h in a.host:
        try:
            runs.append(run_host(h, a.dry_run))
        except Exception as e:
            log(f"{h}: error {str(e)[:140]}")

    os.makedirs(OUT_DIR, exist_ok=True)
    out = os.path.join(OUT_DIR, f"dangling_{datetime.now().strftime('%Y-%m-%d')}.md")
    hits = [r for r in runs if r.get("dead")]
    L = [f"# Claimable script origins — {utc()}", "",
         f"**{len(hits)} host(s) load script from a claimable domain.**", ""]
    for r in hits:
        L.append(f"## {r['host']} ({r.get('program','')})")
        for d in r["dead"]:
            L.append(f"- `{d['origin']}` via {d['where']} — registrable "
                     f"**`{d['registrable']}`** is free ({d['why']})")
        L.append("")
    open(out, "w", encoding="utf-8").write("\n".join(L))
    log(f"report → {out}")
    print(json.dumps([{"host": r.get("host"), "claimable": len(r.get("dead", []))}
                      for r in runs])[:800])
    return 0


if __name__ == "__main__":
    sys.exit(main())

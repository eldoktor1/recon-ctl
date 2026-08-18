#!/usr/bin/env python3
"""
recon_firebase.py — Firebase databases readable (or writable) by anyone.

Repeatedly described as one of the most common findings in bug bounty, and it survives
because the Firebase web config is *meant* to be public — the API key in a bundle is not the
secret. The security boundary is the database RULES, and the default permissive rule set
(`".read": true`) ships in every tutorial. Teams copy it, launch, and never revisit it.

That makes it a perfect unattended lane:

    JS bundle -> firebase project id -> GET https://<project>.firebaseio.com/.json

The response IS the proof. Either the database hands its contents to an anonymous request or
it returns `Permission denied`. There is no judgement call, so there is nothing to get wrong.

WRITE TESTING IS OFF BY DEFAULT. A writable database is a higher-severity finding, but
proving it means writing to someone's production data. Behind `--writecheck` it PUTs a single
benign marker to a namespaced key we own (`/.__recon_probe_<id>`) and DELETEs it immediately —
never touching an existing path. Off unless the operator asks for it.

HARD LINE: we count and type what comes back, never copy it. A finding says "readable, ~3,400
records including email and phone", never the records.
"""
from __future__ import annotations

import argparse
import base64
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
AUDIT = os.path.join(STATE_DIR, "firebase_audit.jsonl")
OUT_DIR = os.path.join(BASE_DIR, "firebase")

sys.path.insert(0, REPO_DIR)
from engine import impact  # noqa: E402

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/127.0.0.0 Safari/537.36")
TIMEOUT = float(os.environ.get("FB_TIMEOUT", "15"))
CAP = int(os.environ.get("FB_CAP", str(4 * 1024 * 1024)))
MIN_GAP = float(os.environ.get("FB_MIN_GAP", "0.8"))

# Where a Firebase project id shows up in a bundle or page.
PROJ_PATTERNS = [
    re.compile(r"https?://([a-z0-9-]+)\.firebaseio\.com", re.I),
    re.compile(r"https?://([a-z0-9-]+)-default-rtdb\.[a-z0-9-]+\.firebasedatabase\.app", re.I),
    re.compile(r"""["']databaseURL["']\s*:\s*["']https?://([a-z0-9-]+)[.-]""", re.I),
    re.compile(r"""["']projectId["']\s*:\s*["']([a-z0-9-]{4,})["']""", re.I),
    re.compile(r"""["']storageBucket["']\s*:\s*["']([a-z0-9-]{4,})\.(?:appspot\.com|firebasestorage\.app)""", re.I),
]

# Regional RTDB hosts — a project may live in any of these.
DB_HOSTS = [
    "https://{p}.firebaseio.com/.json",
    "https://{p}-default-rtdb.firebaseio.com/.json",
    "https://{p}-default-rtdb.europe-west1.firebasedatabase.app/.json",
    "https://{p}-default-rtdb.asia-southeast1.firebasedatabase.app/.json",
]
# Cloud Storage bucket listing for the same project.
STORAGE = "https://firebasestorage.googleapis.com/v0/b/{p}.appspot.com/o?maxResults=50"


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(m: str) -> None:
    print(f"[firebase] {m}", file=sys.stderr, flush=True)


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


_last = [0.0]


def req(url: str, method: str = "GET", data: bytes | None = None) -> tuple[int, bytes]:
    gap = time.time() - _last[0]
    if gap < MIN_GAP:
        time.sleep(MIN_GAP - gap)
    _last[0] = time.time()
    r = urllib.request.Request(url, method=method, data=data)
    r.add_header("User-Agent", UA)
    if data is not None:
        r.add_header("Content-Type", "application/json")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx)).open(
                r, timeout=TIMEOUT) as resp:
            return resp.status, resp.read(CAP)
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(8192)
        except Exception:
            return e.code, b""
    except Exception:
        return 0, b""


def projects_for(host: str, max_js: int = 10) -> set[str]:
    """Firebase project ids referenced by this host's own pages and bundles."""
    found: set[str] = set()
    urls = [f"https://{host}/"]
    code, body = req(urls[0])
    if code == 200 and body:
        for m in re.finditer(rb"""<script[^>]+src=["']([^"']+\.m?js[^"']*)["']""", body, re.I):
            u = urllib.parse.urljoin(f"https://{host}/", m.group(1).decode("utf-8", "replace"))
            if urllib.parse.urlsplit(u).netloc == host:
                urls.append(u)
        for rx in PROJ_PATTERNS:
            for m in rx.finditer(body.decode("utf-8", "replace")):
                found.add(m.group(1).lower())
    if os.path.exists(ENDPOINTS):
        for line in open(ENDPOINTS, encoding="utf-8", errors="replace"):
            if host in line and "firebase" in line.lower():
                for rx in PROJ_PATTERNS:
                    for m in rx.finditer(line):
                        found.add(m.group(1).lower())

    for u in urls[1:max_js + 1]:
        code, body = req(u)
        if code != 200 or not body:
            continue
        txt = body.decode("utf-8", "replace")
        for rx in PROJ_PATTERNS:
            for m in rx.finditer(txt):
                found.add(m.group(1).lower())

    return {p for p in found if p and len(p) >= 4 and not p.startswith("your-")}


def test_project(proj: str, writecheck: bool) -> dict:
    res = {"project": proj, "readable": False, "writable": False, "db_url": "",
           "storage_objects": 0, "records": 0, "kinds": [], "bytes": 0}

    for tmpl in DB_HOSTS:
        url = tmpl.format(p=proj)
        code, body = req(url)
        if code == 200 and body and body.strip() not in (b"null", b"{}", b"[]"):
            res["readable"] = True
            res["db_url"] = url
            res["bytes"] = len(body)
            cls = impact.classify_data(body, source=f"firebase:{proj}")
            res["records"] = cls["records"]
            res["kinds"] = cls["kinds"]
            res["pii"] = cls
            res["secrets"] = impact.scan_secrets(body, f"firebase:{proj}")
            log(f"    READABLE {url} — {len(body)}B, {cls['reason']}")
            break
        if code == 401 or b"Permission denied" in body:
            log(f"    {url} -> permission denied (correct)")
            break

    # Storage bucket listing is a separate, equally common misconfiguration.
    code, body = req(STORAGE.format(p=proj))
    if code == 200 and b'"items"' in body:
        try:
            res["storage_objects"] = len(json.loads(body).get("items") or [])
        except Exception:
            pass
        if res["storage_objects"]:
            log(f"    storage bucket listable — {res['storage_objects']} object(s)")

    if writecheck and res["readable"]:
        # Namespaced key we own, written then immediately removed. Never touches an
        # existing path, and only ever runs when the operator explicitly asks.
        marker = "__recon_probe_" + base64.b32encode(os.urandom(5)).decode().strip("=").lower()
        wurl = res["db_url"].replace("/.json", f"/{marker}.json")
        code, _ = req(wurl, "PUT", json.dumps({"t": utc(), "by": "authorized-bbp-test"}).encode())
        if code == 200:
            res["writable"] = True
            log(f"    *** WRITABLE — marker accepted at {marker}, deleting")
            req(wurl, "DELETE")
    return res


def run_host(host: str, dry: bool, writecheck: bool) -> dict:
    ok, program = scope_ok(host)
    if not ok:
        log(f"SKIP {host}: {program}")
        return {"host": host, "skipped": program}

    projs = projects_for(host)
    if not projs:
        return {"host": host, "program": program, "projects": []}
    log(f"{host} ({program}) — {len(projs)} firebase project(s): {', '.join(sorted(projs))}")

    results = [test_project(p, writecheck) for p in sorted(projs)]
    hits = [r for r in results if r["readable"] or r["writable"] or r["storage_objects"]]
    res = {"host": host, "program": program, "projects": results, "hits": hits}
    audit({"host": host, "program": program,
           "projects": [r["project"] for r in results],
           "readable": [r["project"] for r in results if r["readable"]],
           "writable": [r["project"] for r in results if r["writable"]]})

    if hits and not dry:
        res["finding_id"] = mint(res)
    elif not hits:
        log(f"{host}: all {len(projs)} project(s) correctly locked down")
    return res


def mint(res: dict) -> int | None:
    from engine import state
    best = max(res["hits"], key=lambda r: (r["writable"], r["records"], r["storage_objects"]))
    secrets = best.get("secrets") or []
    pii = best.get("pii")
    score, conf, headline = impact.severity_for(secrets, pii)
    if best["writable"]:
        score = max(score, 19)
        headline = f"unauthenticated WRITE to the Firebase database; {headline}"
        conf = 0.95
    if not score:
        # Readable but nothing sensitive — still a real misconfiguration, but modest.
        if best["readable"] or best["storage_objects"]:
            score, conf = 10, 0.9
            headline = (f"Firebase database readable without authentication "
                        f"({best['bytes']} bytes)" if best["readable"] else
                        f"Firebase storage bucket listable ({best['storage_objects']} objects)")
        else:
            return None
    ev = {
        "chain": "JS bundle -> firebase project id -> anonymous database read",
        "projects": [{k: v for k, v in r.items() if k not in ("secrets", "pii")}
                     for r in res["projects"]],
        "credentials_redacted": secrets[:20],
        "personal_data": pii,
        "impact": headline,
        "method": ("anonymous GET of the project's .json endpoint; contents counted and typed, "
                   "never copied. Write test (if run) used a namespaced marker key that was "
                   "deleted immediately and never touched existing data."),
        "at": utc(),
    }
    conn = state.connect()
    state.init_db(conn)
    fid = state.record_confirmed(
        conn, res["host"], url=best.get("db_url") or f"https://{res['host']}/",
        program=res["program"] or None,
        signal_class="firebase", vuln_class="unauth-firebase-database",
        score=score, evidence=ev, confidence=conf)
    conn.close()
    log(f"  minted finding #{fid} — {headline}")
    return fid


def main() -> int:
    ap = argparse.ArgumentParser(description="Find Firebase databases open to anonymous access.")
    ap.add_argument("host", nargs="+")
    ap.add_argument("--writecheck", action="store_true",
                    help="also test WRITE with a namespaced marker (operator-authorised only)")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    if os.path.exists(os.path.join(STATE_DIR, "vpn_down")):
        log("vpn_down — refusing (fail-closed)")
        return 2

    runs = []
    for h in a.host:
        try:
            runs.append(run_host(h, a.dry_run, a.writecheck))
        except Exception as e:
            log(f"{h}: error {str(e)[:140]}")

    os.makedirs(OUT_DIR, exist_ok=True)
    out = os.path.join(OUT_DIR, f"firebase_{datetime.now().strftime('%Y-%m-%d')}.md")
    hits = [r for r in runs if r.get("hits")]
    L = [f"# Firebase exposure — {utc()}", "",
         f"**{len(hits)} host(s) with an openly accessible Firebase project.**", ""]
    for r in hits:
        L.append(f"## {r['host']} ({r.get('program','')})")
        for p in r["hits"]:
            bits = []
            if p["readable"]:
                bits.append(f"DB readable ({p['bytes']}B, ~{p['records']} records "
                            f"{', '.join(p['kinds'])})")
            if p["writable"]:
                bits.append("**DB WRITABLE**")
            if p["storage_objects"]:
                bits.append(f"storage listable ({p['storage_objects']} objects)")
            L.append(f"- `{p['project']}` — {'; '.join(bits)}")
        L.append("")
    open(out, "w", encoding="utf-8").write("\n".join(L))
    log(f"report → {out}")
    print(json.dumps([{"host": r.get("host"), "hits": len(r.get("hits", []))} for r in runs])[:800])
    return 0


if __name__ == "__main__":
    sys.exit(main())

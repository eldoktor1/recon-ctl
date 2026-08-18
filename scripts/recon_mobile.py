#!/usr/bin/env python3
"""
recon_mobile.py — the app store is unauthenticated attack surface nobody scans.

Every commodity pipeline points at web hosts. Almost none decompile the mobile app, and yet
the APK is a complete, downloadable copy of the client — shipped with whatever the developers
baked into it. Hardcoded API keys, cloud identity-pool ids, private backend hostnames that
appear in no certificate transparency log, staging endpoints, signing secrets.

For an operator with a day job this is the best-shaped lane there is:

  * NO TRAFFIC TO THE TARGET. The APK comes from a mirror; the analysis is local. Nobody
    can rate-limit, WAF, or ban us. It can run flat out at midday while the operator works.
  * The evidence is a file on disk. Re-checkable, quotable in a report, and it does not
    expire the way a live response does.
  * It is where this operation's only Critical came from — an unauth Cognito identity pool
    reached through client-side config. That was found by hand, once, through a Cognito
    side-branch. It should be a first-class lane.

    package id -> download APK -> decompile -> engine/impact.py -> credentials + hidden hosts

HARD LINES
  * Public store listings and public mirrors only. We never touch a paid app, never bypass
    licensing, never repackage or redistribute anything.
  * Secrets are redacted by engine.impact and never used. We prove recovery is possible.
  * Extracted hostnames are reported as SURFACE, and every one is scope-gated before any
    other lane is allowed near it.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone

BASE_DIR = os.environ.get("BASE_DIR", os.path.expanduser("~/recon"))
STATE_DIR = os.environ.get("STATE_DIR", os.path.join(BASE_DIR, "state"))
REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCOPE_CHECK = os.path.join(REPO_DIR, "scripts", "recon_scope_check.sh")
AUDIT = os.path.join(STATE_DIR, "mobile_audit.jsonl")
OUT_DIR = os.path.join(BASE_DIR, "mobile")
WORK = os.environ.get("MOBILE_WORK", "/tmp/recon_mobile")

sys.path.insert(0, REPO_DIR)
from engine import impact  # noqa: E402

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/127.0.0.0 Safari/537.36"
TIMEOUT = int(os.environ.get("MOBILE_TIMEOUT", "180"))
MAX_APK_MB = int(os.environ.get("MOBILE_MAX_APK_MB", "300"))

# Public APK mirrors. Store listings are public; we download only free apps.
MIRRORS = [
    "https://apkpure.com/{slug}/{pkg}/download?from=details",
    "https://d.apkpure.com/b/APK/{pkg}?version=latest",
    "https://apkcombo.com/{slug}/{pkg}/download/apk",
]

# Cloud identity material — the class that produced the Critical.
CLOUD_PATTERNS = [
    ("cognito-identity-pool", re.compile(rb"([a-z]{2}-[a-z]+-\d_[A-Za-z0-9]{9,})")),
    ("cognito-pool-id", re.compile(rb"(us-[a-z]+-\d:[0-9a-f-]{36})", re.I)),
    ("aws-region-pool", re.compile(rb"([a-z]{2}-[a-z]+-\d:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", re.I)),
    ("firebase-project", re.compile(rb"https?://([a-z0-9-]+)\.firebaseio\.com", re.I)),
    ("gcp-api-key", re.compile(rb"(AIza[0-9A-Za-z_\-]{35})")),
    ("s3-bucket", re.compile(rb"([a-z0-9][a-z0-9.\-]{2,61})\.s3[.\-][a-z0-9\-]*\.?amazonaws\.com", re.I)),
]
HOST_RX = re.compile(rb"https?://([a-z0-9][a-z0-9.\-]{3,120}\.[a-z]{2,18})", re.I)
# Hosts that belong to somebody else and are never the target's surface.
THIRD_PARTY = re.compile(
    r"(google|gstatic|googleapis|firebase|crashlytics|facebook|fbcdn|twitter|apple|"
    r"android|schemas\.|w3\.org|apache|github|jquery|bootstrap|cloudflare|akamai|"
    r"sentry\.io|bugsnag|amplitude|mixpanel|segment|branch\.io|adjust|appsflyer|"
    r"doubleclick|admob|unity3d|onesignal|zendesk|intercom)", re.I)


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(m: str) -> None:
    print(f"[mobile] {m}", file=sys.stderr, flush=True)


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
    except Exception:
        return False, "scope check failed"
    return (bool(d.get("in_scope") and d.get("pays") and not d.get("out_of_scope")),
            d.get("program") or "")


def download_apk(pkg: str, dest: str) -> str:
    slug = pkg.split(".")[-1]
    for tmpl in MIRRORS:
        url = tmpl.format(pkg=pkg, slug=slug)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                ct = (r.headers.get("Content-Type") or "").lower()
                cl = int(r.headers.get("Content-Length") or 0)
                if cl > MAX_APK_MB * 1024 * 1024:
                    log(f"    skip {url[:60]} — {cl/1048576:.0f}MB over cap")
                    continue
                if "android" not in ct and "octet" not in ct and "zip" not in ct:
                    continue
                path = os.path.join(dest, f"{pkg}.apk")
                with open(path, "wb") as f:
                    shutil.copyfileobj(r, f, 1024 * 512)
                if os.path.getsize(path) > 100_000:
                    log(f"    downloaded {os.path.getsize(path)/1048576:.1f}MB from {url.split('/')[2]}")
                    return path
        except Exception:
            continue
    return ""


def decompile(apk: str, dest: str) -> str:
    """jadx gives us readable sources; a plain unzip is the fallback for strings."""
    out = os.path.join(dest, "src")
    os.makedirs(out, exist_ok=True)
    if shutil.which("jadx"):
        try:
            subprocess.run(["jadx", "-d", out, "--no-res", "--no-debug-info", "-j", "2", apk],
                           capture_output=True, text=True, timeout=TIMEOUT * 4)
            if any(os.scandir(out)):
                return out
        except Exception as e:
            log(f"    jadx: {str(e)[:80]}")
    if shutil.which("unzip"):
        try:
            subprocess.run(["unzip", "-o", "-qq", apk, "-d", out],
                           capture_output=True, timeout=TIMEOUT)
        except Exception:
            pass
    return out if os.path.isdir(out) else ""


def harvest(src: str) -> tuple[list[dict], set[str], list[dict]]:
    secrets, hosts, cloud = [], set(), []
    seen = set()
    for root, _, files in os.walk(src):
        for fn in files:
            if not fn.endswith((".java", ".xml", ".json", ".properties", ".txt", ".js",
                                ".kt", ".smali", ".yml", ".yaml", ".cfg", ".ini")):
                continue
            p = os.path.join(root, fn)
            try:
                if os.path.getsize(p) > 12 * 1024 * 1024:
                    continue
                blob = open(p, "rb").read()
            except Exception:
                continue
            rel = os.path.relpath(p, src)

            for s in impact.scan_secrets(blob, rel):
                k = s["redacted"]
                if k not in seen:
                    seen.add(k)
                    secrets.append(s)
            for name, rx in CLOUD_PATTERNS:
                for m in rx.finditer(blob):
                    v = m.group(1).decode("utf-8", "replace")
                    k = f"{name}:{v}"
                    if k in seen:
                        continue
                    seen.add(k)
                    cloud.append({"kind": name, "value": v, "file": rel})
            for m in HOST_RX.finditer(blob):
                h = m.group(1).decode("utf-8", "replace").lower().strip(".")
                if not THIRD_PARTY.search(h):
                    hosts.add(h)
    return secrets, hosts, cloud


def run_pkg(pkg: str, dry: bool, keep: bool) -> dict:
    log(f"=== {pkg} ===")
    work = tempfile.mkdtemp(prefix=f"{pkg}-", dir=WORK)
    try:
        apk = download_apk(pkg, work)
        if not apk:
            log("    could not obtain the APK from any public mirror")
            audit({"package": pkg, "result": "download-failed"})
            return {"package": pkg, "downloaded": False}

        src = decompile(apk, work)
        if not src:
            return {"package": pkg, "downloaded": True, "decompiled": False}

        secrets, hosts, cloud = harvest(src)
        log(f"    {len(secrets)} secret(s), {len(cloud)} cloud identifier(s), "
            f"{len(hosts)} first-party host(s)")

        # Which recovered hosts are actually in scope? Those are new surface for other lanes.
        in_scope = []
        for h in sorted(hosts)[:120]:
            ok, prog = scope_ok(h)
            if ok:
                in_scope.append({"host": h, "program": prog})
        if in_scope:
            log(f"    {len(in_scope)} recovered host(s) are IN SCOPE and paying")
            for h in in_scope[:10]:
                log(f"      + {h['host']}  ({h['program']})")

        for c in cloud[:12]:
            log(f"    [{c['kind']}] {c['value'][:60]}  ({c['file'][:50]})")

        program = in_scope[0]["program"] if in_scope else ""
        res = {"package": pkg, "downloaded": True, "decompiled": True, "program": program,
               "secrets": secrets, "cloud": cloud, "hosts_in_scope": in_scope,
               "hosts_total": len(hosts)}
        audit({"package": pkg, "n_secrets": len(secrets), "n_cloud": len(cloud),
               "n_hosts_in_scope": len(in_scope), "program": program})

        if (secrets or cloud) and not dry:
            res["finding_id"] = mint(res)
        elif not secrets and not cloud:
            log("    nothing sensitive baked into the app — clean")
        return res
    finally:
        if not keep:
            shutil.rmtree(work, ignore_errors=True)


def mint(res: dict) -> int | None:
    from engine import state
    score, conf, headline = impact.severity_for(res["secrets"], None)
    if res["cloud"] and score < 15:
        score, conf = 15, 0.9
        kinds = sorted({c["kind"] for c in res["cloud"]})
        headline = f"cloud identity material hardcoded in the mobile client ({', '.join(kinds)})"
    if not score:
        return None
    ev = {
        "chain": "public app store -> APK -> decompile -> hardcoded credential / cloud config",
        "package": res["package"],
        "credentials_redacted": res["secrets"][:25],
        "cloud_identifiers": res["cloud"][:25],
        "recovered_in_scope_hosts": res["hosts_in_scope"][:25],
        "impact": headline,
        "method": ("APK obtained from a public mirror and analysed locally; NO traffic was sent "
                   "to the target. Secrets redacted and never used; the app was not repackaged "
                   "or redistributed."),
        "at": utc(),
    }
    host = res["hosts_in_scope"][0]["host"] if res["hosts_in_scope"] else f"apk:{res['package']}"
    conn = state.connect()
    state.init_db(conn)
    fid = state.record_confirmed(
        conn, host,
        url=f"https://play.google.com/store/apps/details?id={res['package']}",
        program=res["program"] or None,
        signal_class="mobile-app", vuln_class="hardcoded-credential-mobile",
        score=score, evidence=ev, confidence=conf)
    conn.close()
    log(f"    minted finding #{fid} — {headline}")
    return fid


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Decompile in-scope mobile apps and recover baked-in credentials.")
    ap.add_argument("package", nargs="+", help="android package id(s), e.g. com.example.app")
    ap.add_argument("--keep", action="store_true", help="keep the work dir for inspection")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    os.makedirs(WORK, exist_ok=True)
    if not shutil.which("jadx"):
        log("WARNING: jadx not found — falling back to unzip + strings (weaker)")

    runs = []
    for pkg in a.package:
        try:
            runs.append(run_pkg(pkg, a.dry_run, a.keep))
        except Exception as e:
            log(f"{pkg}: error {str(e)[:140]}")

    os.makedirs(OUT_DIR, exist_ok=True)
    out = os.path.join(OUT_DIR, f"mobile_{datetime.now().strftime('%Y-%m-%d')}.md")
    L = [f"# Mobile app analysis — {utc()}", ""]
    for r in runs:
        if not r.get("decompiled"):
            L += [f"## `{r['package']}` — not analysed", ""]
            continue
        L += [f"## `{r['package']}` ({r.get('program','')})",
              f"- {len(r['secrets'])} secret(s), {len(r['cloud'])} cloud identifier(s), "
              f"{len(r['hosts_in_scope'])} in-scope host(s) recovered", ""]
        for s in r["secrets"][:20]:
            L.append(f"  - **{s['kind']}** in `{s['source']}` — `{s['redacted']}`")
        for c in r["cloud"][:20]:
            L.append(f"  - **{c['kind']}** `{c['value']}` — `{c['file']}`")
        for h in r["hosts_in_scope"][:30]:
            L.append(f"  - surface: `{h['host']}` ({h['program']})")
        L.append("")
    open(out, "w", encoding="utf-8").write("\n".join(L))
    log(f"report → {out}")
    print(json.dumps([{k: v for k, v in r.items() if k not in ("secrets", "cloud")}
                      for r in runs], default=str)[:1200])
    return 0


if __name__ == "__main__":
    sys.exit(main())

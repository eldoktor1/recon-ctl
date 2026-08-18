#!/usr/bin/env python3
"""
recon_leak_chain.py — exposed file -> the credentials INSIDE it.

`recon_exposed_files.sh` already finds `.env` and `/.git/HEAD` by content signature, which
is good detection. But it mints on "exposed with credential-shaped keys" — a description of
the file, not of what was recovered. That is the discovery half again, and it is the report
every scanner files the same day.

This lane finishes the chain:

    exposed path -> FETCH it -> extract -> prove a credential is recoverable

The `.git` branch matters most. A readable `/.git/config` usually means the whole repository
is readable, and `config` frequently carries the remote URL with an embedded token
(`https://user:ghp_xxx@github.com/org/repo`). From there `logs/HEAD` gives committer
identities and branch history — the shape of an internal codebase. That is a different
finding from ".git is exposed", and it is the one that pays.

SAFETY
  * GET only, unauthenticated. Nothing is written, nothing executed.
  * Paths are a fixed curated list — no directory brute-force, no fuzzing, no ID guessing.
  * Bodies are held in memory, scanned by engine/impact.py, and discarded. Nothing is
    cloned to disk: we prove the exposure, we do not exfiltrate the repository.
  * Secrets are redacted by engine.impact and are never returned usable.
  * scope+pays gate per host, vpn_down fail-closed, rate-limited, size-capped.
  * Mints ONLY when impact.verdict says something was actually recovered. An exposed file
    containing nothing sensitive is recorded as a negative.
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
import urllib.request
from datetime import datetime, timezone

BASE_DIR = os.environ.get("BASE_DIR", os.path.expanduser("~/recon"))
STATE_DIR = os.environ.get("STATE_DIR", os.path.join(BASE_DIR, "state"))
REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCOPE_CHECK = os.path.join(REPO_DIR, "scripts", "recon_scope_check.sh")
AUDIT = os.path.join(STATE_DIR, "leak_chain_audit.jsonl")
OUT_DIR = os.path.join(BASE_DIR, "leaks")

sys.path.insert(0, REPO_DIR)
from engine import impact  # noqa: E402

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/127.0.0.0 Safari/537.36")
TIMEOUT = float(os.environ.get("LEAK_TIMEOUT", "12"))
CONNECT_TIMEOUT = float(os.environ.get("LEAK_CONNECT_TIMEOUT", "4"))
MIN_GAP = float(os.environ.get("LEAK_MIN_GAP", "0.8"))
CAP = int(os.environ.get("LEAK_BODY_CAP", str(3 * 1024 * 1024)))
BLOCK_TRIP = int(os.environ.get("LEAK_BLOCK_TRIP", "8"))

# (path, kind, content signature that proves it is the real file and not an SPA/404 page)
TARGETS: list[tuple[str, str, re.Pattern]] = [
    ("/.env",                     "env", re.compile(rb"(?m)^[A-Z0-9_]{2,40}=")),
    ("/.env.local",               "env", re.compile(rb"(?m)^[A-Z0-9_]{2,40}=")),
    ("/.env.production",          "env", re.compile(rb"(?m)^[A-Z0-9_]{2,40}=")),
    ("/.env.dev",                 "env", re.compile(rb"(?m)^[A-Z0-9_]{2,40}=")),
    ("/.git/config",              "git", re.compile(rb"\[core\]|repositoryformatversion")),
    ("/.git/HEAD",                "git", re.compile(rb"ref:\s*refs/heads/|^[0-9a-f]{40}")),
    ("/.git/logs/HEAD",           "git", re.compile(rb"[0-9a-f]{40}\s+[0-9a-f]{40}")),
    ("/.git/packed-refs",         "git", re.compile(rb"[0-9a-f]{40}\s+refs/")),
    ("/.svn/wc.db",               "vcs", re.compile(rb"SQLite format 3")),
    ("/.aws/credentials",         "cloud", re.compile(rb"\[(default|profile)|aws_access_key_id")),
    ("/.npmrc",                   "ci", re.compile(rb"_authToken|registry=")),
    ("/.dockercfg",               "ci", re.compile(rb"\"auth\"\s*:")),
    ("/docker-compose.yml",       "ci", re.compile(rb"(?m)^\s*(services|version)\s*:")),
    ("/appsettings.json",         "config", re.compile(rb"\{[\s\S]{0,400}(ConnectionStrings|Logging)")),
    ("/config.json",              "config", re.compile(rb"^\s*\{")),
    ("/web.config",               "config", re.compile(rb"<configuration")),
    ("/wp-config.php.bak",        "backup", re.compile(rb"DB_PASSWORD|DB_NAME")),
    ("/.DS_Store",                "listing", re.compile(rb"\x00\x00\x00\x01Bud1")),
    ("/server-status",            "status", re.compile(rb"Apache Server Status")),
    ("/.terraform/terraform.tfstate", "iac", re.compile(rb"\"terraform_version\"")),
    ("/terraform.tfstate",        "iac", re.compile(rb"\"terraform_version\"")),
]

# Followed ONLY when /.git/config or /.git/HEAD already proved the directory is readable.
GIT_FOLLOWUP = ["/.git/logs/HEAD", "/.git/packed-refs", "/.git/COMMIT_EDITMSG",
                "/.git/description", "/.git/info/refs"]

# A remote URL with an embedded credential — the single most valuable thing in a leaked
# .git/config, and the reason this branch is worth following.
GIT_REMOTE_CRED = re.compile(
    rb"url\s*=\s*(https?://[^\s:/@]+:[^\s@]{4,}@[^\s]+)", re.I)
GIT_REMOTE = re.compile(rb"url\s*=\s*(\S+)")


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(m: str) -> None:
    print(f"[leak] {m}", file=sys.stderr, flush=True)


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


class Fetcher:
    def __init__(self):
        self.last = 0.0
        self.blocks = 0
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))

    def get(self, url: str) -> dict:
        gap = time.time() - self.last
        if gap < MIN_GAP:
            time.sleep(MIN_GAP - gap)
        self.last = time.time()
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", UA)
        try:
            with self.op.open(req, timeout=TIMEOUT) as r:
                return {"status": r.status, "body": r.read(CAP),
                        "ctype": (r.headers.get("Content-Type") or "").split(";")[0].strip()}
        except urllib.error.HTTPError as e:
            if e.code in (429, 403, 503):
                self.blocks += 1
            return {"status": e.code, "body": b"", "ctype": ""}
        except Exception:
            return {"status": 0, "body": b"", "ctype": ""}


def reachable(host: str) -> bool:
    try:
        ip = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    except Exception:
        return False
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(CONNECT_TIMEOUT)
    try:
        return s.connect_ex((ip, 443)) == 0
    except Exception:
        return False
    finally:
        s.close()


def run_host(host: str, dry: bool) -> dict:
    ok, program = scope_ok(host)
    if not ok:
        log(f"SKIP {host}: {program}")
        return {"host": host, "skipped": program}
    if not reachable(host):
        audit({"host": host, "result": "unreachable"})
        return {"host": host, "reachable": False}

    f = Fetcher()
    base = f"https://{host}"
    found: list[dict] = []
    secrets: list[dict] = []
    pii_hits: list[dict] = []
    git_open = False

    for path, kind, sig in TARGETS:
        if f.blocks >= BLOCK_TRIP:
            log(f"{host}: backing off — {f.blocks} blocks")
            break
        r = f.get(base + path)
        if r["status"] != 200 or not r["body"]:
            continue
        # Content signature, never status alone — a 200 SPA shell is not an exposed file.
        if not sig.search(r["body"][:8192]):
            continue
        body = r["body"]
        log(f"  [{kind}] {path} exposed ({len(body)}B, {r['ctype'] or 'no ctype'})")
        found.append({"path": path, "kind": kind, "bytes": len(body)})
        if kind == "git":
            git_open = True

        s = impact.scan_secrets(body, path)
        # A git remote URL carrying an embedded token is the highest-value item here and
        # is not a generic secret shape, so match it explicitly.
        for m in GIT_REMOTE_CRED.finditer(body):
            s.append({"kind": "git-remote-embedded-credential", "source": path,
                      "redacted": impact.redact("git-remote", m.group(1), 24)})
        if s:
            log(f"        {len(s)} credential(s): {', '.join(sorted({x['kind'] for x in s}))}")
            secrets.extend(s)
        d = impact.classify_data(body, source=path)
        if d["is_pii"]:
            pii_hits.append(d)

    # Only walk further into .git once the directory has proven readable.
    if git_open:
        log(f"  .git is readable — pulling metadata (no clone, nothing written to disk)")
        for path in GIT_FOLLOWUP:
            if f.blocks >= BLOCK_TRIP:
                break
            r = f.get(base + path)
            if r["status"] != 200 or not r["body"]:
                continue
            found.append({"path": path, "kind": "git", "bytes": len(r["body"])})
            s = impact.scan_secrets(r["body"], path)
            for m in GIT_REMOTE_CRED.finditer(r["body"]):
                s.append({"kind": "git-remote-embedded-credential", "source": path,
                          "redacted": impact.redact("git-remote", m.group(1), 24)})
            if s:
                secrets.extend(s)

    if not found:
        audit({"host": host, "program": program, "exposed": 0})
        return {"host": host, "program": program, "exposed": []}

    pii = max(pii_hits, key=lambda x: x["records"]) if pii_hits else None
    score, conf, headline = impact.severity_for(secrets, pii)

    res = {"host": host, "program": program, "exposed": found, "git_readable": git_open,
           "secrets": secrets, "pii": pii, "score": score, "headline": headline}
    audit({k: v for k, v in res.items() if k != "secrets"} | {"n_secrets": len(secrets)})

    if score and not dry:
        res["finding_id"] = mint(res, score, conf, headline)
    elif not score:
        log(f"{host}: {len(found)} file(s) exposed but NOTHING sensitive recoverable — "
            f"a lead, not a finding")
    return res


def mint(res: dict, score: int, conf: float, headline: str) -> int | None:
    from engine import state
    ev = {
        "chain": "exposed file -> fetched -> credential recovery",
        "files_exposed": res["exposed"],
        "git_directory_readable": res["git_readable"],
        "credentials_redacted": res["secrets"][:25],
        "personal_data": res["pii"],
        "impact": headline,
        "method": ("unauthenticated GET of a fixed curated path list; no directory brute-force, "
                   "no repository clone; bodies scanned in memory and discarded; secrets "
                   "redacted and never used"),
        "at": utc(),
    }
    top = res["exposed"][0]["path"]
    conn = state.connect()
    state.init_db(conn)
    fid = state.record_confirmed(
        conn, res["host"], url=f"https://{res['host']}{top}", program=res["program"] or None,
        signal_class="data-leak", vuln_class="unauth-credential-disclosure",
        score=score, evidence=ev, confidence=conf)
    conn.close()
    log(f"  minted finding #{fid} — {headline}")
    return fid


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Exposed file -> the credentials inside it. GET-only, curated paths.")
    ap.add_argument("host", nargs="+")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    if os.path.exists(os.path.join(STATE_DIR, "vpn_down")):
        log("vpn_down — refusing (fail-closed)")
        return 2

    runs = []
    for h in a.host:
        try:
            runs.append(run_host(h, a.dry_run))
        except Exception as e:
            log(f"{h}: error {str(e)[:120]}")

    os.makedirs(OUT_DIR, exist_ok=True)
    out = os.path.join(OUT_DIR, f"leaks_{datetime.now().strftime('%Y-%m-%d')}.md")
    L = [f"# Exposed-file credential chain — {utc()}", ""]
    hits = [r for r in runs if r.get("score")]
    L += [f"**{len(hits)} host(s) leaked recoverable credentials** out of {len(runs)} tested.", ""]
    for r in runs:
        if not r.get("exposed"):
            continue
        paths = ", ".join("`" + e["path"] + "`" for e in r["exposed"])
        L += [f"## {r['host']} ({r.get('program','')})",
              f"- exposed: {paths}",
              f"- **{r.get('headline','no impact demonstrated')}**", ""]
        for s in r.get("secrets", [])[:25]:
            L.append(f"  - **{s['kind']}** in `{s['source']}` — `{s['redacted']}`")
        L.append("")
    open(out, "w", encoding="utf-8").write("\n".join(L))
    log(f"report → {out}")
    print(json.dumps([{k: v for k, v in r.items() if k != "secrets"} for r in runs],
                     default=str)[:1500])
    return 0


if __name__ == "__main__":
    sys.exit(main())

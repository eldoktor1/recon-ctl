#!/usr/bin/env python3
"""
recon_takeover.py — subdomain takeover, confirmed by CLAIMABILITY. Nothing else counts.

The old lane produced 24 findings and zero real verdicts because it minted on the wrong
thing: "this CNAME points at a provider and the root returns 404". Live applications 404 at
their root constantly. A dangling CNAME to a *working* ELB or CloudFront distribution is not
a takeover, it is a Tuesday.

A takeover is real only when the resource on the other end can actually be CLAIMED. So this
lane refuses to mint until it has proof of that, by one of exactly three routes:

  1. PROVIDER FINGERPRINT — the service itself says the resource is unclaimed, in its own
     words. "NoSuchBucket". "There isn't a GitHub Pages site here." Those strings are the
     provider telling us the name is free. A bare 404 never qualifies.

  2. NXDOMAIN ON A CLAIMABLE TARGET — the CNAME points somewhere that does not resolve at
     all, AND that somewhere belongs to a service where creating the name is self-service.
     An NXDOMAIN pointing at internal infrastructure is not claimable by us and is not a
     finding.

  3. LAPSED REGISTRATION — the CNAME target's registrable domain is unregistered, confirmed
     at WHOIS. Whoever buys it inherits the subdomain.

HARD LINE: we NEVER claim the resource. We do not create the bucket, register the app name,
or buy the domain. Proving it is claimable is the entire finding; taking it would be seizing
control of the target's namespace. If the operator wants a benign ownership PoC, that is a
deliberate, in-scope, operator-run act — never the daemon's.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
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
AUDIT = os.path.join(STATE_DIR, "takeover_audit.jsonl")
OUT_DIR = os.path.join(BASE_DIR, "takeover")

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/127.0.0.0 Safari/537.36"
TIMEOUT = float(os.environ.get("TKO_TIMEOUT", "15"))
MIN_GAP = float(os.environ.get("TKO_MIN_GAP", "0.7"))

# provider -> (cname suffixes, the provider's OWN words for "this is unclaimed",
#              is the name self-service claimable?)
PROVIDERS: list[dict] = [
    {"name": "aws-s3", "cnames": ["s3.amazonaws.com", "s3-website", ".s3."],
     "fingerprints": ["NoSuchBucket", "The specified bucket does not exist"], "claimable": True},
    {"name": "github-pages", "cnames": ["github.io", "githubusercontent.com"],
     "fingerprints": ["There isn't a GitHub Pages site here",
                      "For root URLs (like http://example.com/) you must provide an index.html file"],
     "claimable": True},
    {"name": "heroku", "cnames": ["herokuapp.com", "herokudns.com", "herokussl.com"],
     "fingerprints": ["No such app", "herokucdn.com/error-pages/no-such-app.html"],
     "claimable": True},
    {"name": "shopify", "cnames": ["myshopify.com"],
     "fingerprints": ["Sorry, this shop is currently unavailable",
                      "Only one step left!"], "claimable": True},
    {"name": "fastly", "cnames": ["fastly.net", "fastlylb.net"],
     "fingerprints": ["Fastly error: unknown domain"], "claimable": False},
    {"name": "pantheon", "cnames": ["pantheonsite.io"],
     "fingerprints": ["The gods are wise, but do not know of the site which you seek"],
     "claimable": True},
    {"name": "tumblr", "cnames": ["domains.tumblr.com"],
     "fingerprints": ["Whatever you were looking for doesn't currently exist at this address"],
     "claimable": True},
    {"name": "zendesk", "cnames": ["zendesk.com"],
     "fingerprints": ["Help Center Closed", "this help center no longer exists"],
     "claimable": True},
    {"name": "surge", "cnames": ["surge.sh"],
     "fingerprints": ["project not found"], "claimable": True},
    {"name": "bitbucket", "cnames": ["bitbucket.io"],
     "fingerprints": ["Repository not found"], "claimable": True},
    {"name": "netlify", "cnames": ["netlify.app", "netlify.com"],
     "fingerprints": ["Not Found - Request ID"], "claimable": True},
    {"name": "webflow", "cnames": ["proxy-ssl.webflow.com", "webflow.io"],
     "fingerprints": ["The page you are looking for doesn't exist or has been moved"],
     "claimable": True},
    {"name": "readthedocs", "cnames": ["readthedocs.io", "readthedocs.org"],
     "fingerprints": ["unknown to Read the Docs"], "claimable": True},
    {"name": "ghost", "cnames": ["ghost.io"],
     "fingerprints": ["Domain error", "The thing you were looking for is no longer here"],
     "claimable": True},
    {"name": "helpscout", "cnames": ["helpscoutdocs.com"],
     "fingerprints": ["No settings were found for this company"], "claimable": True},
    {"name": "unbounce", "cnames": ["unbouncepages.com"],
     "fingerprints": ["The requested URL was not found on this server"], "claimable": True},
    {"name": "statuspage", "cnames": ["statuspage.io"],
     "fingerprints": ["You are being redirected", "Better Uptime"], "claimable": False},
    {"name": "azure", "cnames": ["azurewebsites.net", "cloudapp.azure.com", "trafficmanager.net",
                                 "blob.core.windows.net", "azureedge.net"],
     "fingerprints": [], "claimable": True},   # azure is NXDOMAIN-only
    {"name": "gcs", "cnames": ["storage.googleapis.com"],
     "fingerprints": ["NoSuchBucket", "The specified bucket does not exist"], "claimable": True},
    {"name": "wordpress", "cnames": ["wordpress.com"],
     "fingerprints": ["Do you want to register"], "claimable": True},
    {"name": "intercom", "cnames": ["custom.intercom.help"],
     "fingerprints": ["Uh oh. That page doesn't exist"], "claimable": True},
]

# Providers where a live-but-empty response is NORMAL and never a takeover.
NEVER_CLAIMABLE = re.compile(
    r"(elb\.amazonaws\.com|cloudfront\.net|akamai|edgekey|edgesuite|"
    r"awsglobalaccelerator|elasticbeanstalk\.com)", re.I)


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(m: str) -> None:
    print(f"[takeover] {m}", file=sys.stderr, flush=True)


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


def dig(name: str, rtype: str) -> list[str]:
    if not shutil.which("dig"):
        return []
    try:
        r = subprocess.run(["dig", "+short", "+time=4", "+tries=2", rtype, name],
                           capture_output=True, text=True, timeout=25)
        return [l.strip().rstrip(".") for l in (r.stdout or "").splitlines() if l.strip()]
    except Exception:
        return []


def nxdomain(name: str) -> bool:
    """NXDOMAIN specifically — not merely 'no A record', which a live domain can have."""
    if shutil.which("dig"):
        try:
            r = subprocess.run(["dig", "+time=4", "+tries=2", name],
                               capture_output=True, text=True, timeout=25)
            return "status: NXDOMAIN" in (r.stdout or "")
        except Exception:
            pass
    try:
        socket.getaddrinfo(name, None)
        return False
    except socket.gaierror:
        return True
    except Exception:
        return False


_last = [0.0]


def get(url: str) -> tuple[int, str]:
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
            return r.status, r.read(200_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(200_000).decode("utf-8", "replace")
        except Exception:
            return e.code, ""
    except Exception:
        return 0, ""


def registrable(d: str) -> str:
    parts = d.strip(".").lower().split(".")
    if len(parts) < 2:
        return ""
    two = {"co.uk", "org.uk", "com.au", "co.nz", "co.jp", "com.br", "co.in", "com.cn",
           "co.za", "com.mx", "co.kr", "com.tr", "com.sg"}
    if len(parts) >= 3 and ".".join(parts[-2:]) in two:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def whois_free(domain: str) -> tuple[bool, str]:
    if not shutil.which("whois"):
        return False, "whois not installed"
    try:
        out = (subprocess.run(["whois", domain], capture_output=True, text=True,
                              timeout=45).stdout or "").lower()
    except Exception as e:
        return False, f"whois failed: {str(e)[:50]}"
    if not out.strip():
        return False, "whois empty"
    for m in ("no match for", "not found", "no data found", "no entries found",
              "domain not found", "status: free", "status: available", "no object found"):
        if m in out:
            return True, f"whois: {m}"
    return False, "registered"


# ---------------------------------------------------------------------------
# SECOND-STAGE CLAIMABILITY. The provider's *router* is not authoritative.
#
# Learned the hard way from this operation's own host_notes (2026-06-08):
#   "railing.meraki.com — Heroku FP: app record exists (API GET /apps/railing = 403,
#    not 404); router 'No such app' is not claimable"
#
# Heroku's router returns "No such app" for a name that IS registered but has no web
# dyno, no domain attached, or is suspended. The control-plane API is the truth:
#   404 = the name is genuinely free    403/200 = somebody owns it
# The same shape applies elsewhere: an S3 404 through a CDN is not NoSuchBucket, and a
# GitHub Pages 404 does not mean the org has not already claimed the domain.
#
# A fingerprint alone is a LEAD. Only the authoritative namespace check confirms.

def heroku_free(app: str) -> tuple[bool, str]:
    """Heroku control plane. 404 = claimable, anything else = taken."""
    code, _ = _api(f"https://api.heroku.com/apps/{app}",
                   {"Accept": "application/vnd.heroku+json; version=3"})
    if code == 404:
        return True, "heroku API 404 — the app name is unregistered"
    if code in (401, 403, 200):
        return False, f"heroku API {code} — the app record EXISTS (registered, not claimable)"
    return False, f"heroku API inconclusive ({code}) — refusing to claim confirmation"


def s3_free(bucket: str) -> tuple[bool, str]:
    """S3 namespace is global. NoSuchBucket from S3 itself, not from a CDN in front."""
    code, body = _api(f"https://{bucket}.s3.amazonaws.com/", {})
    if code == 404 and b"NoSuchBucket" in body:
        return True, "s3 returned NoSuchBucket — the name is unregistered"
    if code in (200, 403):
        return False, f"s3 {code} — the bucket exists"
    return False, f"s3 inconclusive ({code})"


def _api(url: str, headers: dict) -> tuple[int, bytes]:
    req = urllib.request.Request(url, headers={"User-Agent": UA, **headers})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx)).open(
                req, timeout=TIMEOUT) as r:
            return r.status, r.read(20000)
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(20000)
        except Exception:
            return e.code, b""
    except Exception:
        return 0, b""


def second_stage(provider: str, cname: str) -> tuple[bool, str]:
    """Authoritative namespace check. Returns (claimable, why)."""
    c = cname.lower()
    if provider == "heroku":
        app = c.split(".herokuapp.com")[0].split(".")[-1] if "herokuapp.com" in c else ""
        return heroku_free(app) if app else (False, "could not derive the heroku app name")
    if provider in ("aws-s3", "gcs"):
        b = c.split(".s3")[0] if ".s3" in c else c.split(".storage.googleapis.com")[0]
        return s3_free(b) if b else (False, "could not derive the bucket name")
    if provider == "github-pages":
        # A GitHub Pages 404 does not distinguish "unclaimed" from "claimed by the org
        # with a verified domain". There is no read-only way to tell them apart, and
        # this operation has repeatedly burned on it (host_notes: github-org-claimed-fp).
        return False, ("github-pages cannot be confirmed read-only — org-claimed and "
                       "verified domains present the identical 404. LEAD only.")
    return False, f"no authoritative namespace check implemented for {provider}"


def provider_for(cname: str) -> dict | None:
    c = cname.lower()
    for p in PROVIDERS:
        for suf in p["cnames"]:
            if suf in c:
                return p
    return None


NOTES_FILE = os.path.join(STATE_DIR, "host_notes.jsonl")


def prior_notes(host: str) -> list[dict]:
    """Worked-knowledge for this host. The scope resolver already flags has_notes; not
    reading them is how an already-killed host gets re-surfaced as a fresh lead."""
    out = []
    if not os.path.exists(NOTES_FILE):
        return out
    for line in open(NOTES_FILE, encoding="utf-8", errors="replace"):
        if host not in line:
            continue
        try:
            o = json.loads(line)
        except Exception:
            continue
        if o.get("host") == host:
            out.append({"at": (o.get("created_at") or "")[:10], "note": o.get("note") or ""})
    return out


KILLED_BY_NOTE = re.compile(r"\b(fp|false.?positive|claimed|taken|not claimable|dead)\b", re.I)


def check(host: str, dry: bool) -> dict:
    ok, program = scope_ok(host)
    if not ok:
        log(f"SKIP {host}: {program}")
        return {"host": host, "skipped": program}

    notes = prior_notes(host)
    killed = [n for n in notes if KILLED_BY_NOTE.search(n["note"])]
    if killed:
        log(f"{host}: ALREADY WORKED — {len(notes)} note(s); a prior pass killed this:")
        for n in killed[:3]:
            log(f"    [{n['at']}] {n['note'][:150]}")
        return {"host": host, "program": program, "verdict": "already killed by a host note",
                "notes": killed[:3], "skipped_by_note": True}
    if notes:
        log(f"{host}: {len(notes)} prior note(s) — continuing, none of them a kill")

    cnames = dig(host, "CNAME")
    if not cnames:
        return {"host": host, "program": program, "cname": None,
                "verdict": "no CNAME — nothing to take over"}
    cname = cnames[-1]

    if NEVER_CLAIMABLE.search(cname):
        log(f"{host} -> {cname}: shared infrastructure, not a claimable namespace")
        return {"host": host, "program": program, "cname": cname,
                "verdict": "points at shared infra (ELB/CloudFront/Akamai) — never claimable"}

    prov = provider_for(cname)
    log(f"{host} -> {cname}" + (f"  [{prov['name']}]" if prov else "  [unknown provider]"))

    # ROUTE 1 — the provider says, in its own words, that the resource is unclaimed.
    if prov and prov["fingerprints"]:
        code, body = get(f"https://{host}/")
        if not body:
            code, body = get(f"http://{host}/")
        for fp in prov["fingerprints"]:
            if fp.lower() in body.lower():
                if not prov["claimable"]:
                    log(f"  {prov['name']} says unclaimed, but the namespace is NOT self-service"
                        f" — reportable to the vendor, not takeable")
                    return {"host": host, "program": program, "cname": cname,
                            "provider": prov["name"], "verdict": "unclaimed but not self-service",
                            "evidence": fp}
                # The fingerprint is only a LEAD. Confirm against the namespace itself.
                free, why = second_stage(prov["name"], cname)
                if not free:
                    log(f"  fingerprint {fp!r} present, but NOT claimable — {why}")
                    return {"host": host, "program": program, "cname": cname,
                            "provider": prov["name"],
                            "verdict": "fingerprint only — namespace check says not claimable",
                            "evidence": fp, "second_stage": why}
                log(f"  *** CONFIRMED — {prov['name']}: {fp!r} AND {why}")
                return {"host": host, "program": program, "cname": cname,
                        "provider": prov["name"], "verdict": "claimable",
                        "route": "provider fingerprint + authoritative namespace check",
                        "evidence": f"{fp}; {why}", "status": code}

    # ROUTE 2 — NXDOMAIN on a namespace where creating the name is self-service.
    if nxdomain(cname):
        if prov and prov["claimable"]:
            free, why = second_stage(prov["name"], cname)
            if free:
                log(f"  *** CONFIRMED — NXDOMAIN on {prov['name']} AND {why}")
                return {"host": host, "program": program, "cname": cname,
                        "provider": prov["name"], "verdict": "claimable",
                        "route": "NXDOMAIN + authoritative namespace check",
                        "evidence": f"{cname} NXDOMAIN; {why}"}
            log(f"  NXDOMAIN on {prov['name']} but the namespace check disagrees — {why}")
        # ROUTE 3 — the target's registrable domain has lapsed.
        reg = registrable(cname)
        free, why = whois_free(reg) if reg else (False, "no registrable name")
        if free:
            log(f"  *** CONFIRMED — {reg} is unregistered ({why})")
            return {"host": host, "program": program, "cname": cname,
                    "provider": prov["name"] if prov else "domain", "verdict": "claimable",
                    "route": "lapsed registration", "evidence": f"{reg} unregistered ({why})",
                    "registrable": reg}
        log(f"  NXDOMAIN but not claimable by us ({reg}: {why})")
        return {"host": host, "program": program, "cname": cname,
                "verdict": f"NXDOMAIN but not claimable ({why})"}

    log("  target resolves and the provider does not report it unclaimed — NOT a takeover")
    return {"host": host, "program": program, "cname": cname,
            "verdict": "target resolves — not a takeover"}


def mint(r: dict) -> int | None:
    sys.path.insert(0, REPO_DIR)
    from engine import state
    ev = {
        "chain": "CNAME -> claimable resource, confirmed",
        "cname": r["cname"], "provider": r.get("provider"),
        "confirmation_route": r.get("route"), "evidence": r.get("evidence"),
        "impact": (f"`{r['host']}` delegates to `{r['cname']}`, which is unclaimed and "
                   f"self-service. Anyone may claim it and serve arbitrary content from this "
                   f"subdomain — cookie theft, phishing under the brand, and CSP/origin trust "
                   f"abuse all follow."),
        "method": ("claimability confirmed via " + (r.get("route") or "") +
                   ". The resource was NOT claimed — proving it is claimable is the finding; "
                   "taking it would be seizing the target's namespace."),
        "at": utc(),
    }
    conn = state.connect()
    state.init_db(conn)
    fid = state.record_confirmed(
        conn, r["host"], url=f"https://{r['host']}/", program=r["program"] or None,
        signal_class="takeover", vuln_class="subdomain-takeover-claimable",
        score=17, evidence=ev, confidence=0.95)
    conn.close()
    log(f"  minted finding #{fid}")
    return fid


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Subdomain takeover confirmed by claimability — never by a 404.")
    ap.add_argument("host", nargs="*")
    ap.add_argument("--from-file", help="file of hosts, one per line")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    if os.path.exists(os.path.join(STATE_DIR, "vpn_down")):
        log("vpn_down — refusing (fail-closed)")
        return 2

    hosts = list(a.host)
    if a.from_file and os.path.exists(a.from_file):
        hosts += [l.strip() for l in open(a.from_file) if l.strip()]
    if not hosts:
        log("no hosts given")
        return 2

    runs = []
    for h in hosts:
        try:
            r = check(h, a.dry_run)
            runs.append(r)
            audit({k: v for k, v in r.items() if k != "evidence"})
            if r.get("verdict") == "claimable" and not a.dry_run:
                r["finding_id"] = mint(r)
        except Exception as e:
            log(f"{h}: error {str(e)[:120]}")

    hits = [r for r in runs if r.get("verdict") == "claimable"]
    os.makedirs(OUT_DIR, exist_ok=True)
    out = os.path.join(OUT_DIR, f"takeover_{datetime.now().strftime('%Y-%m-%d')}.md")
    L = [f"# Subdomain takeover — {utc()}", "",
         f"{len(runs)} host(s) checked. **{len(hits)} confirmed claimable.**", ""]
    for r in hits:
        L += [f"## {r['host']} ({r.get('program','')})",
              f"- CNAME → `{r['cname']}` [{r.get('provider')}]",
              f"- confirmed via **{r.get('route')}** — {r.get('evidence')}", ""]
    other = [r for r in runs if r.get("verdict") != "claimable" and not r.get("skipped")]
    if other:
        L += ["---", "", "## Not takeovers (recorded so they are not re-walked)", ""]
        for r in other[:40]:
            L.append(f"- `{r['host']}` → `{r.get('cname') or '-'}` — {r.get('verdict')}")
    open(out, "w", encoding="utf-8").write("\n".join(L))
    log(f"report → {out}")
    log(f"DONE — {len(hits)}/{len(runs)} claimable")
    print(json.dumps({"checked": len(runs), "claimable": len(hits)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())

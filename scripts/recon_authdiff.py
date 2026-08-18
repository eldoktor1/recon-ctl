#!/usr/bin/env python3
"""
recon_authdiff.py — the DIFFERENTIAL access-control tester.

The rest of the pipeline matches PATTERNS ("this response contains a token-shaped
string") and then asks Claude whether that's real. This asks a question that has a
factual answer instead:

    Does this endpoint return the same data WITHOUT the session as it does WITH it?

Same request, two identities, compared. If an endpoint that only makes sense for an
authenticated user serves the same data to nobody, that is broken access control and
the two responses ARE the proof. There is no verdict to get wrong — which is why this
lane needs no ai_verdict gate and can't become an FP factory.

SAFETY (this drives an AUTHENTICATED session, so it is operator-run, never the daemon):
  * GET only. Never POST/PUT/PATCH/DELETE. Nothing is created, changed or deleted.
  * Endpoints are replayed EXACTLY as discovered. No ID enumeration, no fuzzing,
    no guessing at other users' object references — that is the hard line and this
    tool cannot cross it because it never synthesises an identifier.
  * Per-host scope+pays gate (authoritative resolver), vpn_down fail-closed.
  * Anti-burn: min gap + jitter, per-host cap, backs off hard on 429/403/503.
  * The session is supplied by the operator on the command line and is never logged;
    evidence records header NAMES only.

FALSE-POSITIVE KILLERS (each one is a documented pattern that has burned us before):
  * SPA catch-all — a route returning the app shell (same as `/`) is not a leak.
    We fingerprint `/` and a guaranteed-404 path up front and discard matches.
  * Content-type gate — an HTML page is public-by-design until proven otherwise;
    only structured data (json/xml/csv) counts as a data leak on its own.
  * Public-by-design paths — /health, /robots.txt, /.well-known, static assets.
  * Empty/trivial bodies prove nothing.
  * If the unauth response is 401/403 the endpoint is ENFORCED — recorded as a
    negative so we can prove coverage rather than silently dropping it.
"""
from __future__ import annotations

import argparse
import base64
import difflib
import gzip
import hashlib
import json
import os
import random
import re
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timezone

BASE_DIR = os.environ.get("BASE_DIR", os.path.expanduser("~/recon"))
STATE_DIR = os.environ.get("STATE_DIR", os.path.join(BASE_DIR, "state"))
REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENDPOINTS = os.path.join(BASE_DIR, "js_recon", "endpoints.jsonl")
SCOPE_CHECK = os.path.join(REPO_DIR, "scripts", "recon_scope_check.sh")
OUT_DIR = os.path.join(BASE_DIR, "authdiff")
AUDIT = os.path.join(STATE_DIR, "authdiff_audit.jsonl")

UA = os.environ.get(
    "AUTHDIFF_UA",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/127.0.0.0 Safari/537.36",
)
TIMEOUT = float(os.environ.get("AUTHDIFF_TIMEOUT", "15"))
MIN_GAP = float(os.environ.get("AUTHDIFF_MIN_GAP", "1.2"))
MAX_BODY = int(os.environ.get("AUTHDIFF_MAX_BODY", "300000"))
BLOCK_TRIP = int(os.environ.get("AUTHDIFF_BLOCK_TRIP", "6"))

# A body shorter than this can't carry a meaningful data leak.
MIN_DATA_BYTES = 120
# Similarity at/above which two bodies are "substantively the same response".
SAME_RATIO = 0.95
# Similarity to the shell/404 fingerprint at/above which we call it a catch-all.
SHELL_RATIO = 0.90

DATA_CTYPES = ("application/json", "application/xml", "text/xml", "text/csv",
               "application/x-ndjson", "application/ld+json", "application/vnd.api+json")

PUBLIC_BY_DESIGN = re.compile(
    r"(^/(robots\.txt|sitemap[^/]*\.xml|favicon\.ico|humans\.txt|ads\.txt|security\.txt)$"
    r"|^/\.well-known/"
    r"|^/(health|healthz|ping|status|version|_status)/?$"
    r"|\.(js|mjs|css|map|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|pdf|zip|mp4|webm)$)",
    re.I,
)

# Endpoint strings jsluice/katana emit that aren't requestable paths.
JUNK_ENDPOINT = re.compile(r"^(#|javascript:|data:|mailto:|tel:|blob:|\{|\$|%|\s*$)")

# A leftmost label that is a bare UUID/high-entropy blob under a shared vendor wildcard
# is a PER-CUSTOMER TENANT (e.g. <uuid>.unifi-hosting.ui.com). "In scope" describes the
# host; it never authorises touching equipment somebody else owns. Hard line, not a
# heuristic — the program's own rules forfeit rewards for it.
TENANT_LABEL = re.compile(
    r"^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"|[0-9a-f]{24,}"
    r"|[a-z0-9]{20,}\d[a-z0-9]*)$",
    re.I,
)


def is_shared_tenant(host: str) -> bool:
    label = host.split(".", 1)[0]
    return bool(TENANT_LABEL.match(label)) and host.count(".") >= 2


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg: str) -> None:
    print(f"[authdiff] {msg}", file=sys.stderr, flush=True)


def audit(rec: dict) -> None:
    os.makedirs(STATE_DIR, exist_ok=True)
    rec.setdefault("at", utc())
    with open(AUDIT, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")


# --------------------------------------------------------------------------- gates
def vpn_down() -> bool:
    return os.path.exists(os.path.join(STATE_DIR, "vpn_down"))


def scope_ok(host: str) -> tuple[bool, str]:
    """Authoritative per-asset in-scope + pays gate. Fail-closed when the resolver
    exists; only fall through if it is genuinely absent."""
    if not os.path.exists(SCOPE_CHECK):
        return False, "scope resolver missing (fail-closed)"
    try:
        out = subprocess.run(["bash", SCOPE_CHECK, host], capture_output=True,
                             text=True, timeout=45).stdout
        d = json.loads(out)
    except Exception as e:
        return False, f"scope check failed: {e}"
    if not d.get("in_scope"):
        return False, "not in scope"
    if not d.get("pays"):
        return False, "program does not pay for this asset"
    if d.get("out_of_scope"):
        return False, "explicitly out of scope"
    return True, d.get("program") or ""


# ---------------------------------------------------------------------- http layer
class Fetcher:
    """Minimal, deliberately dumb HTTP GET. No redirect following (a 302 to /login is
    itself the signal), no cookie jar (so the unauth side is genuinely unauthenticated)."""

    def __init__(self, min_gap: float = MIN_GAP):
        self.min_gap = min_gap
        self.last = 0.0
        self.blocks = 0
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # self-signed staging hosts are still in scope
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            NoRedirect(),
        )

    def _pace(self) -> None:
        gap = time.time() - self.last
        want = self.min_gap + random.uniform(0, 0.4)
        if gap < want:
            time.sleep(want - gap)
        self.last = time.time()

    def get(self, url: str, headers: dict[str, str] | None = None) -> dict:
        self._pace()
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", UA)
        req.add_header("Accept", "*/*")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with self.opener.open(req, timeout=TIMEOUT) as r:
                raw = r.read(MAX_BODY)
                return self._wrap(r.status, dict(r.headers), raw)
        except urllib.error.HTTPError as e:
            raw = b""
            try:
                raw = e.read(MAX_BODY)
            except Exception:
                pass
            if e.code in (429, 403, 503):
                self.blocks += 1
            return self._wrap(e.code, dict(e.headers or {}), raw)
        except Exception as e:
            return {"ok": False, "error": str(e)[:200], "status": 0,
                    "ctype": "", "body": "", "len": 0}

    @staticmethod
    def _wrap(status: int, headers: dict, raw: bytes) -> dict:
        if (headers.get("Content-Encoding") or "").lower() == "gzip":
            try:
                raw = gzip.decompress(raw)
            except Exception:
                pass
        try:
            body = raw.decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return {
            "ok": True,
            "status": status,
            "ctype": (headers.get("Content-Type") or "").split(";")[0].strip().lower(),
            "location": headers.get("Location") or "",
            "body": body,
            "len": len(raw),
        }


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# ------------------------------------------------------------------- normalisation
CSRF_ISH = re.compile(
    r'(csrf[-_]?token|xsrf|nonce|request[-_]?id|trace[-_]?id|session[-_]?id|'
    r'timestamp|"iat"|"exp"|__VIEWSTATE)["\']?\s*[:=]\s*["\']?[\w.\-+/=]{6,}',
    re.I,
)
HEXBLOB = re.compile(r"\b[0-9a-f]{16,}\b", re.I)
UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
NUMS = re.compile(r"\b\d{6,}\b")
WS = re.compile(r"\s+")


def normalise(body: str) -> str:
    """Strip the per-request noise (CSRF tokens, nonces, trace ids, timestamps) that
    would otherwise make two identical responses look different."""
    b = CSRF_ISH.sub("TOKEN", body)
    b = UUID.sub("UUID", b)
    b = HEXBLOB.sub("HEX", b)
    b = NUMS.sub("N", b)
    return WS.sub(" ", b).strip()


def similarity(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    la, lb = len(a), len(b)
    # length alone rules out most pairs far cheaper than a diff
    if min(la, lb) / max(la, lb) < 0.55:
        return 0.0
    sm = difflib.SequenceMatcher(None, a[:20000], b[:20000])
    return sm.quick_ratio() if sm.quick_ratio() < 0.9 else sm.ratio()


def looks_like_data(resp: dict) -> bool:
    """Does this response carry structured data (vs a page, a redirect, an error)?"""
    if resp["status"] not in (200, 206):
        return False
    if resp["len"] < MIN_DATA_BYTES:
        return False
    if resp["ctype"] in DATA_CTYPES:
        return True
    # JSON served with a sloppy content-type still counts
    s = resp["body"].lstrip()[:1]
    return s in ("{", "[")


# -------------------------------------------------------------- api base discovery
def discover_base(f: Fetcher, host: str, sample: list[str]) -> tuple[str, dict]:
    """jsluice pulls endpoints out of JS relative to whatever base that JS talks to —
    usually an API origin or a prefix, not the web root. Testing `/v1/admin/x` against
    `https://host/` then just 404s and the whole surface looks dead.

    So: try a handful of plausible bases against a small sample and keep the one that
    actually answers. Cheap (a few requests), and it is the difference between 162k
    discovered endpoints being testable or being noise.
    """
    root = ".".join(host.split(".")[-2:])
    candidates = [f"https://{host}/", f"https://{host}/api/"]
    for sib in (f"api.{root}", f"api.{host}", f"{host.split('.')[0]}-api.{root}"):
        if sib != host and not is_shared_tenant(sib):
            candidates.append(f"https://{sib}/")

    probe = sample[:5]
    if not probe:
        return candidates[0], {}

    scores: dict[str, tuple[int, int]] = {}
    for base in candidates:
        alive = 0
        authish = 0
        for ep in probe:
            r = f.get(urllib.parse.urljoin(base, ep.lstrip("/")))
            if not r.get("ok"):
                continue
            st = r["status"]
            if st == 404:
                continue
            alive += 1
            # 401/403 is the STRONGEST signal a base is right: the route exists and is
            # protected, which is exactly the surface we want to differential-test.
            if st in (401, 403):
                authish += 1
        scores[base] = (authish, alive)
        log(f"  base {base} → alive={alive}/{len(probe)} authgated={authish}")
        if authish >= 2 or alive == len(probe):
            break  # good enough, stop spending requests

    best = max(scores, key=lambda b: (scores[b][0] * 2 + scores[b][1]))
    if scores[best] == (0, 0):
        log("  no base answered — endpoints may belong to a different origin entirely")
    return best, scores


# ------------------------------------------------------------------ shell baseline
class Baseline:
    """Fingerprints of 'this host answers everything with the same thing' — the SPA
    catch-all and the soft-404. Any unauth body matching these proves nothing."""

    def __init__(self, fetcher: Fetcher, base: str):
        self.shapes: list[str] = []
        self.statuses: Counter = Counter()
        rnd = base64.b32encode(os.urandom(10)).decode().strip("=").lower()
        for path in ("/", f"/{rnd}", f"/{rnd}/{rnd}.json"):
            r = fetcher.get(urllib.parse.urljoin(base, path))
            if r.get("ok"):
                self.statuses[r["status"]] += 1
                if r["body"]:
                    self.shapes.append(normalise(r["body"]))

    def is_shell(self, body_norm: str) -> bool:
        return any(similarity(body_norm, s) >= SHELL_RATIO for s in self.shapes)


# ------------------------------------------------------- unauth bypass differential
# When an endpoint answers 401/403 we have something rare and valuable: a KNOWN-PROTECTED
# route. That makes a clean differential possible with NO session at all — if any variant
# of the same request returns real data, the control is bypassable and the 403 baseline is
# the proof. This is the autonomous half of the lane: unauthenticated, GET-only, and it
# targets a class that pays (unauth broken access control / auth bypass).
#
# Every variant below is a READ. Nothing is created, changed or deleted, and no identifier
# is ever invented — each variant is a rewriting of the SAME discovered path.

def _path_variants(path: str) -> list[str]:
    p = path.split("?")[0]
    q = ("?" + path.split("?", 1)[1]) if "?" in path else ""
    seen, out = set(), []
    for cand in (
        p + "/", p + "//", p + "/.", "/." + p, p + "%20", p + "%09",
        p + "?", p + "#", p + "..;/", p + ";/",
        p.replace("/", "//", 1), p.upper(), p.capitalize(),
        "/%2e" + p, p + "%2f",
    ):
        if cand and cand != p and cand not in seen:
            seen.add(cand)
            out.append(cand + q)
    return out


# Headers that make a front proxy or gateway believe the request is internal / already
# routed. Classic misconfiguration: the edge enforces auth, the origin trusts the header.
BYPASS_HEADERS: list[dict[str, str]] = [
    {"X-Original-URL": "@PATH@"},
    {"X-Rewrite-URL": "@PATH@"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Forwarded-Server": "localhost"},
]


def try_bypass(f: Fetcher, base_url: str, path: str, blocked: dict,
               base: Baseline, cap: int = 18) -> dict | None:
    """Return the first variant that turns a 401/403 into real data, or None.

    A hit must clear every bar the main test clears: structured data, not the app shell,
    not a trivial body. Otherwise a friendly 200 error page reads as a bypass."""
    tried = 0

    def judge(resp: dict, how: str) -> dict | None:
        if not resp.get("ok") or resp["status"] not in (200, 206):
            return None
        if not looks_like_data(resp):
            return None
        if base.is_shell(normalise(resp["body"])):
            return None
        return {"how": how, "resp": resp,
                "why": (f"base path returns {blocked['status']} unauthenticated, but "
                        f"{how} returns {resp['status']} with {resp['len']} bytes of "
                        f"{resp['ctype'] or 'data'} — the control is bypassable")}

    for v in _path_variants(path):
        if tried >= cap or f.blocks >= BLOCK_TRIP:
            return None
        tried += 1
        r = f.get(urllib.parse.urljoin(base_url, v.lstrip("/")))
        hit = judge(r, f"path variant `{v}`")
        if hit:
            hit["url"] = urllib.parse.urljoin(base_url, v.lstrip("/"))
            return hit

    full = urllib.parse.urljoin(base_url, path.lstrip("/"))
    root = urllib.parse.urlsplit(full)
    for hdr in BYPASS_HEADERS:
        if tried >= cap or f.blocks >= BLOCK_TRIP:
            return None
        tried += 1
        h = {k: (root.path if v == "@PATH@" else v) for k, v in hdr.items()}
        # X-Original-URL style headers are sent against the ROOT with the path in the header
        target = f"{root.scheme}://{root.netloc}/" if "@PATH@" in "".join(hdr.values()) else full
        r = f.get(target, h)
        hit = judge(r, f"header `{list(hdr)[0]}`")
        if hit:
            hit["url"] = full
            hit["headers"] = h
            return hit
    return None


# ------------------------------------------------------------------------ the test
def classify(auth: dict, anon: dict, base: Baseline) -> tuple[str, str]:
    """Return (verdict, why). The only verdict that mints a finding is 'exposed'."""
    if not auth.get("ok") or not anon.get("ok"):
        return "error", auth.get("error") or anon.get("error") or "request failed"

    # The endpoint pushed back — back off, don't interpret.
    if anon["status"] in (429, 503):
        return "throttled", f"unauth status {anon['status']}"

    # Auth side must actually return something, or there's nothing to compare.
    if not looks_like_data(auth):
        if auth["status"] in (401, 403):
            return "no-access", "session did not authenticate to this endpoint"
        return "no-data", f"auth side status={auth['status']} ctype={auth['ctype']} len={auth['len']}"

    # The good case: the app enforces.
    if anon["status"] in (401, 403):
        return "enforced", f"unauth correctly rejected ({anon['status']})"
    if anon["status"] in (301, 302, 303, 307, 308):
        loc = anon.get("location", "")
        if re.search(r"(login|signin|auth|sso|account)", loc, re.I):
            return "enforced", f"unauth redirected to auth ({anon['status']})"
        return "enforced", f"unauth redirected away ({anon['status']})"

    if anon["status"] not in (200, 206):
        return "enforced", f"unauth got {anon['status']}"

    anon_norm = normalise(anon["body"])
    auth_norm = normalise(auth["body"])

    # Documented FP #1: the SPA catch-all / soft-404.
    if base.is_shell(anon_norm):
        return "spa-shell", "unauth response is the app shell / soft-404, not data"

    # Documented FP #2: an HTML page is public-by-design until proven otherwise.
    if not looks_like_data(anon):
        return "no-data", f"unauth returned no structured data (ctype={anon['ctype']}, len={anon['len']})"

    ratio = similarity(auth_norm, anon_norm)
    if ratio >= SAME_RATIO:
        return "exposed", (f"unauth response is substantively identical to the "
                           f"authenticated one (similarity {ratio:.3f}, {anon['len']} bytes)")
    if ratio >= 0.55:
        return "partial", (f"unauth returns a reduced but non-empty version "
                           f"(similarity {ratio:.3f}) — verify what is missing")
    return "differs", f"unauth returns different content (similarity {ratio:.3f})"


# ----------------------------------------------------------------------- endpoints
def load_endpoints(host: str, limit: int) -> list[str]:
    """Discovered paths for this host, deduped and ranked so the interesting ones
    get tested first when a cap applies."""
    seen: set[str] = set()
    for line in open(ENDPOINTS, encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line or host not in line:
            continue
        try:
            o = json.loads(line)
        except Exception:
            continue
        if o.get("host") != host:
            continue
        ep = (o.get("endpoint") or "").strip()
        if not ep or JUNK_ENDPOINT.match(ep):
            continue
        if ep.startswith(("http://", "https://")):
            p = urllib.parse.urlsplit(ep)
            if p.netloc != host:
                continue  # never touch a third-party host
            ep = p.path + (("?" + p.query) if p.query else "")
        if not ep.startswith("/"):
            ep = "/" + ep
        if PUBLIC_BY_DESIGN.search(ep.split("?")[0]):
            continue
        if "{" in ep or "}" in ep or "${" in ep:
            continue  # unresolved template — we do not invent values for it
        seen.add(ep)

    def rank(ep: str) -> tuple:
        s = ep.lower()
        return (
            0 if re.search(r"/(api|v\d|graphql|rest)/", s) else 1,
            0 if re.search(r"(user|account|profile|admin|order|invoice|payment|billing|"
                           r"customer|member|token|key|secret|export|report|internal|"
                           r"config|setting|message|document|file)", s) else 1,
            len(ep),
        )

    return sorted(seen, key=rank)[:limit]


# ---------------------------------------------------------------------------- mint
def mint(host: str, program: str, url: str, why: str, auth: dict, anon: dict,
         header_names: list[str], signal: str = "authdiff",
         vuln: str = "broken-access-control") -> int | None:
    """Write a CONFIRMED finding. The evidence IS the differential — both responses,
    truncated and with the session values never recorded."""
    try:
        sys.path.insert(0, REPO_DIR)
        from engine import state  # noqa: E402
    except Exception as e:
        log(f"could not import engine.state ({e}) — finding not persisted")
        return None
    evidence = {
        "test": "unauth-vs-auth differential (GET)",
        "url": url,
        "why": why,
        "authenticated": {"status": auth["status"], "ctype": auth["ctype"],
                          "len": auth["len"], "body_head": auth["body"][:1200]},
        "unauthenticated": {"status": anon["status"], "ctype": anon["ctype"],
                            "len": anon["len"], "body_head": anon["body"][:1200]},
        "session_headers_used": header_names,  # NAMES only — never the values
        "method": "GET only; endpoint replayed exactly as discovered; no ID enumeration",
        "at": utc(),
    }
    conn = state.connect()
    state.init_db(conn)
    fid = state.record_confirmed(
        conn, host, url=url, program=program or None,
        signal_class=signal, vuln_class=vuln,
        score=14, evidence=evidence, confidence=0.95,
    )
    conn.close()
    return fid


# ---------------------------------------------------------------------------- main
def run_host(host: str, headers: dict[str, str], limit: int, dry: bool,
             base_override: str | None = None, no_session: bool = False) -> dict:
    if is_shared_tenant(host):
        why = ("shared-tenant host — this is a customer-owned instance; in-scope "
               "describes the host, not permission to touch someone else's data")
        log(f"REFUSE {host}: {why}")
        audit({"host": host, "refused": why})
        return {"host": host, "skipped": why}

    ok, info = scope_ok(host)
    if not ok:
        log(f"SKIP {host}: {info}")
        audit({"host": host, "skipped": info})
        return {"host": host, "skipped": info}
    program = info

    eps = load_endpoints(host, limit)
    if not eps:
        log(f"{host}: no testable endpoints in endpoints.jsonl")
        return {"host": host, "endpoints": 0}

    f = Fetcher()
    if base_override:
        base_url = base_override if base_override.endswith("/") else base_override + "/"
        log(f"{host} ({program}) — {len(eps)} endpoints, base pinned to {base_url}")
    else:
        log(f"{host} ({program}) — {len(eps)} endpoints, resolving API base…")
        base_url, _ = discover_base(f, host, eps)
        log(f"{host}: base = {base_url}")

    # If the base resolved to a DIFFERENT host, it needs its own scope+pays verdict —
    # a sibling API origin is not covered by the original host's gate.
    base_host = urllib.parse.urlsplit(base_url).netloc
    if base_host != host:
        if is_shared_tenant(base_host):
            return {"host": host, "skipped": f"resolved base {base_host} is a customer tenant"}
        bok, binfo = scope_ok(base_host)
        if not bok:
            log(f"{host}: resolved base {base_host} fails its own scope gate ({binfo}) — stopping")
            audit({"host": host, "base": base_host, "skipped": binfo})
            return {"host": host, "skipped": f"base {base_host}: {binfo}"}
        log(f"{host}: base host {base_host} is in scope ({binfo})")

    base = Baseline(f, base_url)
    log(f"{host}: shell shapes={len(base.shapes)} statuses={dict(base.statuses)}")

    results = Counter()
    hits: list[dict] = []
    hdr_names = sorted(headers.keys())

    for i, ep in enumerate(eps, 1):
        if f.blocks >= BLOCK_TRIP:
            log(f"{host}: backing off — {f.blocks} blocks seen; stopping this host")
            results["aborted-burn"] += 1
            break
        url = urllib.parse.urljoin(base_url, ep.lstrip("/"))
        auth = f.get(url, headers)
        anon = f.get(url)
        verdict, why = classify(auth, anon, base)
        results[verdict] += 1
        audit({"host": host, "url": url, "verdict": verdict, "why": why,
               "auth_status": auth.get("status"), "anon_status": anon.get("status")})
        if verdict == "exposed":
            if no_session:
                continue  # meaningless without two distinct identities
            log(f"  [EXPOSED] {ep} — {why}")
            hits.append({"url": url, "why": why, "auth": auth, "anon": anon})
            if not dry:
                fid = mint(host, program, url, why, auth, anon, hdr_names)
                if fid:
                    log(f"            minted finding #{fid}")
        elif verdict == "partial":
            log(f"  [partial] {ep} — {why}")
            hits.append({"url": url, "why": why, "auth": auth, "anon": anon, "partial": True})
        elif verdict in ("enforced", "no-access") and anon.get("status") in (401, 403):
            # KNOWN-PROTECTED route → the cleanest unauth differential available.
            # Needs no session, so this half runs fully autonomously.
            bp = try_bypass(f, base_url, ep, anon, base)
            if bp:
                results["bypassed"] += 1
                results[verdict] -= 1
                log(f"  [BYPASSED] {ep} — {bp['why']}")
                audit({"host": host, "url": bp["url"], "verdict": "bypassed",
                       "why": bp["why"], "how": bp["how"]})
                hits.append({"url": bp["url"], "why": bp["why"],
                             "auth": anon, "anon": bp["resp"], "bypass": True})
                if not dry:
                    fid = mint(host, program, bp["url"], bp["why"], anon, bp["resp"],
                               hdr_names, signal="auth-bypass",
                               vuln="unauth-access-control-bypass")
                    if fid:
                        log(f"             minted finding #{fid}")
        if i % 25 == 0:
            log(f"  …{i}/{len(eps)}  {dict(results)}")

    log(f"{host}: DONE {dict(results)}")
    return {"host": host, "program": program, "endpoints": len(eps),
            "results": dict(results), "hits": hits}


def write_report(runs: list[dict], path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    lines = [f"# Auth differential — {utc()}", ""]
    total_exposed = sum(r.get("results", {}).get("exposed", 0) for r in runs)
    total_enf = sum(r.get("results", {}).get("enforced", 0) for r in runs)
    lines += [f"**{total_exposed} exposed**, {total_enf} correctly enforced, "
              f"across {len(runs)} host(s).", ""]
    for r in runs:
        if r.get("skipped"):
            lines += [f"## {r['host']} — SKIPPED ({r['skipped']})", ""]
            continue
        lines += [f"## {r['host']}  ({r.get('program','')})",
                  f"`{r.get('endpoints',0)}` endpoints tested — {r.get('results',{})}", ""]
        for h in r.get("hits", []):
            tag = "PARTIAL" if h.get("partial") else "EXPOSED"
            lines += [f"### [{tag}] {h['url']}", f"{h['why']}", "",
                      f"- authenticated: `{h['auth']['status']}` "
                      f"`{h['auth']['ctype']}` {h['auth']['len']}B",
                      f"- unauthenticated: `{h['anon']['status']}` "
                      f"`{h['anon']['ctype']}` {h['anon']['len']}B", "",
                      "```", h["anon"]["body"][:700], "```", ""]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    log(f"report → {path}")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Differential access-control tester: same GET, with and without "
                    "the session, compared.")
    ap.add_argument("host", nargs="*", help="host(s) to test")
    ap.add_argument("--cookie", help="Cookie header value for the authenticated side")
    ap.add_argument("--header", action="append", default=[],
                    help="extra auth header, 'Name: Value' (repeatable)")
    ap.add_argument("--limit", type=int, default=150,
                    help="max endpoints per host (default 150)")
    ap.add_argument("--base", default=None,
                    help="pin the API base URL instead of auto-resolving it")
    ap.add_argument("--dry-run", action="store_true",
                    help="test and report but do not write findings")
    ap.add_argument("--out", default=None, help="report path")
    a = ap.parse_args()

    if not a.host:
        ap.error("give at least one host")
    if vpn_down():
        log("vpn_down present — refusing to send target traffic (fail-closed)")
        return 2
    if not os.path.exists(ENDPOINTS):
        log(f"missing {ENDPOINTS}")
        return 2

    headers: dict[str, str] = {}
    if a.cookie:
        headers["Cookie"] = a.cookie
    for h in a.header:
        if ":" not in h:
            ap.error(f"bad --header {h!r}; want 'Name: Value'")
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()
    no_session = not headers
    if no_session:
        # Without a session both sides are the SAME request, so the auth differential is
        # meaningless — every data endpoint would compare identical and mint a bogus
        # "exposed". That half is suppressed.
        #
        # The BYPASS differential is unaffected and still mints: it compares a known-403
        # baseline against a variant of the same request, which needs no second identity.
        # This is the fully autonomous, unauthenticated half of the lane.
        log("no session supplied — auth differential disabled; running the UNAUTH "
            "bypass differential (fully autonomous, still mints).")

    runs = [run_host(h, headers, a.limit, a.dry_run, a.base, no_session) for h in a.host]
    out = a.out or os.path.join(OUT_DIR, f"authdiff_{datetime.now().strftime('%Y-%m-%d')}.md")
    write_report(runs, out)
    print(json.dumps({"runs": runs, "report": out}, default=str)[:2000])
    return 0


if __name__ == "__main__":
    sys.exit(main())

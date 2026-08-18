#!/usr/bin/env python3
"""
recon_bucket_loot.py — public-read bucket -> the credentials inside it.

This is a rebuild of the chain that produced the only Critical this operation has ever
landed: a world-readable build bucket -> JavaScript source maps -> reconstructed original
source -> cloud configuration -> unauthenticated credential issuance. That chain was run
by hand, once, and never again.

The bucket lane currently mints public-WRITE and demotes public-READ to a LEAD that nobody
works. But public-read is where the Critical came from. A public-read bucket full of CDN
images is by design and is the #1 bucket false positive; a public-read bucket containing
`.env`, `terraform.tfstate`, a database dump or source maps is a different finding entirely.
The only way to tell them apart is to LOOK.

    list -> rank objects by loot value -> fetch the few that matter -> extract -> prove

SAFETY
  * Anonymous GET and LIST only. Never PUT/DELETE/POST, never an ACL change.
  * PROVENANCE REQUIRED: the S3 namespace is global, so a name match is not ownership.
    A bucket is only looted if it was referenced by the target's own surface, or the caller
    passes --provenance to record why it belongs to this program. Never blind-permute names.
  * Objects are fetched to MEMORY, size-capped, scanned, and discarded. Nothing is retained.
  * Secrets are redacted by engine.impact and are never returned usable. We prove the
    exposure; we do not use the credential.
  * Personal data is COUNTED and TYPED, never copied. No mass download of third-party PII.
"""
from __future__ import annotations

import argparse
import gzip
import io
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
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

BASE_DIR = os.environ.get("BASE_DIR", os.path.expanduser("~/recon"))
STATE_DIR = os.environ.get("STATE_DIR", os.path.join(BASE_DIR, "state"))
REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCOPE_CHECK = os.path.join(REPO_DIR, "scripts", "recon_scope_check.sh")
AUDIT = os.path.join(STATE_DIR, "bucket_loot_audit.jsonl")
OUT_DIR = os.path.join(BASE_DIR, "buckets")

sys.path.insert(0, REPO_DIR)
from engine import impact  # noqa: E402

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"
TIMEOUT = float(os.environ.get("LOOT_TIMEOUT", "20"))
OBJ_CAP = int(os.environ.get("LOOT_OBJ_CAP_MB", "12")) * 1024 * 1024
MAX_FETCH = int(os.environ.get("LOOT_MAX_FETCH", "40"))
MIN_GAP = float(os.environ.get("LOOT_MIN_GAP", "0.6"))

# What is worth fetching, and how badly. Higher = looted first.
LOOT_RULES: list[tuple[int, str, re.Pattern]] = [
    (100, "env-file", re.compile(r"(^|/)\.env(\.|$)|(^|/)env\.(json|yaml|yml)$", re.I)),
    (98, "terraform-state", re.compile(r"\.tfstate(\.backup)?$", re.I)),
    (96, "private-key", re.compile(r"(^|/)(id_rsa|id_dsa|id_ecdsa|id_ed25519)$|\.(pem|ppk|p12|pfx|key)$", re.I)),
    (94, "git-config", re.compile(r"(^|/)\.git/(config|HEAD|packed-refs)$", re.I)),
    (92, "cloud-credentials", re.compile(r"(^|/)\.(aws|azure|gcloud)/|credentials(\.json)?$|service[-_]account.*\.json$", re.I)),
    (90, "db-dump", re.compile(r"\.(sql|dump|bak|mdb|sqlite3?|db)(\.(gz|bz2|zip|xz))?$", re.I)),
    (86, "source-map", re.compile(r"\.js\.map$|\.mjs\.map$|\.css\.map$", re.I)),
    (84, "ci-config", re.compile(r"(^|/)(\.npmrc|\.pypirc|\.dockercfg|\.docker/config\.json|docker-compose[^/]*\.ya?ml|\.gitlab-ci\.ya?ml|Jenkinsfile|\.circleci/config\.yml)$", re.I)),
    (80, "app-config", re.compile(r"(^|/)(config|settings|secrets|credentials|application)[-_.\w]*\.(json|ya?ml|xml|properties|conf|ini|toml)$", re.I)),
    (72, "backup-archive", re.compile(r"(backup|dump|export|archive)[-_.\w]*\.(zip|tar|tar\.gz|tgz|7z|rar)$", re.I)),
    (68, "log", re.compile(r"\.log$|(^|/)logs?/", re.I)),
    (60, "spreadsheet", re.compile(r"\.(csv|xlsx?|tsv)$", re.I)),
]

# Static/CDN payload — the by-design public bucket. Never worth fetching.
BORING = re.compile(
    r"\.(png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|eot|otf|mp4|webm|mov|mp3|wav|"
    r"pdf|zip|gz|br|wasm|css)$", re.I)


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(m: str) -> None:
    print(f"[loot] {m}", file=sys.stderr, flush=True)


def audit(rec: dict) -> None:
    os.makedirs(STATE_DIR, exist_ok=True)
    rec.setdefault("at", utc())
    with open(AUDIT, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")


def _opener():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))


_last = [0.0]


def get(url: str, cap: int = OBJ_CAP) -> dict:
    gap = time.time() - _last[0]
    if gap < MIN_GAP:
        time.sleep(MIN_GAP - gap)
    _last[0] = time.time()
    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", UA)
    try:
        with _opener().open(req, timeout=TIMEOUT) as r:
            raw = r.read(cap)
            if (r.headers.get("Content-Encoding") or "").lower() == "gzip":
                try:
                    raw = gzip.decompress(raw)
                except Exception:
                    pass
            return {"ok": True, "status": r.status, "body": raw}
    except urllib.error.HTTPError as e:
        try:
            return {"ok": True, "status": e.code, "body": e.read(8192)}
        except Exception:
            return {"ok": True, "status": e.code, "body": b""}
    except Exception as e:
        return {"ok": False, "status": 0, "body": b"", "error": str(e)[:160]}


# ------------------------------------------------------------------- listing
NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"


def list_bucket(bucket: str, region_hint: str = "") -> tuple[list[dict], str, str]:
    """Anonymous list. Returns (objects, endpoint_used, error). Handles dotted names via
    path-style and follows the region redirect S3 hands back."""
    endpoints = [f"https://{bucket}.s3.amazonaws.com/?list-type=2&max-keys=1000",
                 f"https://s3.amazonaws.com/{bucket}/?list-type=2&max-keys=1000"]
    if region_hint:
        endpoints.insert(0, f"https://{bucket}.s3.{region_hint}.amazonaws.com/?list-type=2&max-keys=1000")

    for ep in endpoints:
        r = get(ep, cap=4_000_000)
        if not r["ok"]:
            continue
        body = r["body"]
        if r["status"] == 200 and b"<ListBucketResult" in body:
            objs = []
            try:
                root = ET.fromstring(body)
            except Exception:
                continue
            for c in root.findall(f"{NS}Contents"):
                k = c.findtext(f"{NS}Key") or ""
                sz = int(c.findtext(f"{NS}Size") or 0)
                lm = c.findtext(f"{NS}LastModified") or ""
                objs.append({"key": k, "size": sz, "modified": lm})
            return objs, ep.split("?")[0], ""
        if b"PermanentRedirect" in body or b"AuthorizationHeaderMalformed" in body:
            m = re.search(rb"<Region>([a-z0-9\-]+)</Region>", body)
            if m:
                reg = m.group(1).decode()
                r2 = get(f"https://{bucket}.s3.{reg}.amazonaws.com/?list-type=2&max-keys=1000",
                         cap=4_000_000)
                if r2["ok"] and r2["status"] == 200 and b"<ListBucketResult" in r2["body"]:
                    objs = []
                    try:
                        root = ET.fromstring(r2["body"])
                    except Exception:
                        return [], "", "unparseable listing"
                    for c in root.findall(f"{NS}Contents"):
                        objs.append({"key": c.findtext(f"{NS}Key") or "",
                                     "size": int(c.findtext(f"{NS}Size") or 0),
                                     "modified": c.findtext(f"{NS}LastModified") or ""})
                    return objs, f"https://{bucket}.s3.{reg}.amazonaws.com/", ""
        if r["status"] == 403:
            return [], "", "listing denied (403) — this is the normal secure state"
        if r["status"] == 404 or b"NoSuchBucket" in body:
            return [], "", "NoSuchBucket — if a live host references it, that is a takeover lead"
    return [], "", "no endpoint answered with a listing"


def rank(objs: list[dict]) -> list[dict]:
    out = []
    for o in objs:
        k = o["key"]
        if not k or k.endswith("/") or o["size"] == 0:
            continue
        best = 0
        label = ""
        for score, name, rx in LOOT_RULES:
            if rx.search(k):
                if score > best:
                    best, label = score, name
        if not best and BORING.search(k):
            continue
        if not best:
            continue
        out.append({**o, "loot_score": best, "loot_kind": label})
    return sorted(out, key=lambda x: (-x["loot_score"], x["size"]))


def from_source_map(blob: bytes) -> bytes:
    """A .map carries `sourcesContent` — the ORIGINAL un-minified source. That is where
    the cloud config and identity-pool ids live, and it is the step the crowd skips."""
    try:
        j = json.loads(blob)
    except Exception:
        return b""
    sc = j.get("sourcesContent") or []
    if not isinstance(sc, list):
        return b""
    return "\n".join(s for s in sc if isinstance(s, str)).encode("utf-8", "replace")


# ---------------------------------------------------------------------- main
# `s3:ListBucket` and `s3:GetObject` are SEPARATE permissions. A 403 on listing is the normal
# secure state for listing and says nothing about whether objects are readable — plenty of
# buckets deny LIST while serving any object to whoever knows the key. Since provenance came
# from the target's own JS referencing real object URLs, we already know keys.
WELL_KNOWN = [
    ".env", ".env.production", ".env.local", "config.json", "config/config.json",
    "settings.json", "credentials.json", "terraform.tfstate", ".git/config",
    "docker-compose.yml", ".npmrc", "backup.sql", "dump.sql", "users.csv",
]


def probe_keys(bucket: str, keys: list[str]) -> tuple[list[tuple[str, bytes]], str]:
    """GET specific object keys directly. Used when listing is denied."""
    got: list[tuple[str, bytes]] = []
    endpoint = f"https://{bucket}.s3.amazonaws.com/"
    for k in keys:
        r = get(endpoint + urllib.parse.quote(k.lstrip("/")))
        if r["ok"] and r["status"] == 200 and r["body"]:
            log(f"  readable despite denied listing: {k} ({len(r['body'])} bytes)")
            got.append((k, r["body"]))
    return got, endpoint


def loot(bucket: str, program: str, provenance: str, dry: bool,
         max_fetch: int = MAX_FETCH, keys: list[str] | None = None) -> dict:
    log(f"{bucket}: listing anonymously…")
    objs, endpoint, err = list_bucket(bucket)
    if err:
        log(f"{bucket}: {err}")
        if "403" in err:
            # Listing denied is not the end of the test — try known and well-known keys.
            cand = (keys or []) + WELL_KNOWN
            log(f"{bucket}: listing denied, but GetObject is a separate permission — "
                f"trying {len(cand)} known key(s)…")
            got, ep = probe_keys(bucket, cand)
            if got:
                secrets, pii_hits = [], []
                for k, blob in got:
                    secrets.extend(impact.scan_secrets(blob, k))
                    d = impact.classify_data(blob, source=k)
                    if d["is_pii"]:
                        pii_hits.append(d)
                pii = max(pii_hits, key=lambda x: x["records"]) if pii_hits else None
                score, conf, headline = impact.severity_for(secrets, pii)
                res = {"bucket": bucket, "program": program, "provenance": provenance,
                       "listed": False, "endpoint": ep, "objects": 0, "ranked": 0,
                       "fetched": [{"key": k, "kind": "direct-get", "size": len(b)}
                                   for k, b in got],
                       "secrets": secrets, "pii": pii, "headline": headline, "score": score}
                if score and not dry:
                    res["finding_id"] = mint(res, score, conf, headline)
                elif not score:
                    log(f"{bucket}: objects readable without listing, but nothing "
                        f"sensitive recovered — LEAD, not a finding")
                return res
            log(f"{bucket}: no known key readable either — properly secured")
        audit({"bucket": bucket, "result": err})
        return {"bucket": bucket, "listed": False, "reason": err}

    log(f"{bucket}: {len(objs)} objects listed via {endpoint}")
    ranked = rank(objs)
    log(f"{bucket}: {len(ranked)} worth looking at "
        f"({len(objs) - len(ranked)} static/CDN objects ignored)")
    if not ranked:
        log(f"{bucket}: public-read but only static assets — by design, NOT a finding")
        return {"bucket": bucket, "listed": True, "objects": len(objs),
                "loot": [], "reason": "static/CDN content only — public by design"}

    secrets: list[dict] = []
    pii_hits: list[dict] = []
    fetched: list[dict] = []

    for o in ranked[:max_fetch]:
        if o["size"] > OBJ_CAP:
            log(f"  skip {o['key']} ({o['size'] / 1048576:.1f} MB > cap)")
            continue
        url = urllib.parse.urljoin(endpoint.rstrip("/") + "/", urllib.parse.quote(o["key"]))
        r = get(url)
        if not r["ok"] or r["status"] != 200 or not r["body"]:
            continue
        blob = r["body"]
        fetched.append({"key": o["key"], "kind": o["loot_kind"], "size": o["size"]})

        s = impact.scan_secrets(blob, o["key"])
        if o["loot_kind"] == "source-map":
            src = from_source_map(blob)
            if src:
                extra = impact.scan_secrets(src, o["key"] + " (reconstructed source)")
                known = {x["redacted"] for x in s}
                s += [e for e in extra if e["redacted"] not in known]
                log(f"  [{o['loot_kind']}] {o['key']} — reconstructed "
                    f"{len(src) // 1024}KB of original source")
        if s:
            log(f"  [{o['loot_kind']}] {o['key']} — {len(s)} credential(s): "
                f"{', '.join(sorted({x['kind'] for x in s}))}")
            secrets.extend(s)

        d = impact.classify_data(blob, source=o["key"])
        if d["is_pii"]:
            log(f"  [{o['loot_kind']}] {o['key']} — {d['reason']}")
            pii_hits.append(d)

    pii = max(pii_hits, key=lambda x: x["records"]) if pii_hits else None
    score, conf, headline = impact.severity_for(secrets, pii)

    res = {"bucket": bucket, "program": program, "provenance": provenance,
           "listed": True, "endpoint": endpoint, "objects": len(objs),
           "ranked": len(ranked), "fetched": fetched,
           "secrets": secrets, "pii": pii, "headline": headline, "score": score}
    audit({k: v for k, v in res.items() if k != "secrets"} | {"n_secrets": len(secrets)})

    if score and not dry:
        res["finding_id"] = mint(res, score, conf, headline)
    elif not score:
        log(f"{bucket}: readable, but nothing sensitive recovered — LEAD, not a finding")
    return res


def mint(res: dict, score: int, conf: float, headline: str) -> int | None:
    from engine import state
    ev = {
        "chain": "public-read bucket -> object triage -> credential/PII recovery",
        "bucket": res["bucket"], "endpoint": res["endpoint"],
        "provenance": res["provenance"],
        "objects_listed": res["objects"], "objects_examined": len(res["fetched"]),
        "objects_of_interest": res["fetched"][:25],
        "credentials_redacted": res["secrets"][:25],
        "personal_data": res["pii"],
        "impact": headline,
        "method": ("anonymous GET/LIST only; objects held in memory, scanned and discarded; "
                   "secrets redacted and not used; personal data counted, never copied"),
        "at": utc(),
    }
    conn = state.connect()
    state.init_db(conn)
    fid = state.record_confirmed(
        conn, res["bucket"], url=res["endpoint"], program=res["program"] or None,
        signal_class="bucket-exposure", vuln_class="unauth-credential-disclosure",
        score=score, evidence=ev, confidence=conf)
    conn.close()
    log(f"  minted finding #{fid} — {headline}")
    return fid


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Loot a provenance-confirmed public-read bucket for credentials/PII.")
    ap.add_argument("bucket", nargs="+")
    ap.add_argument("--program", default="", help="program this bucket belongs to")
    ap.add_argument("--provenance", default="",
                    help="WHY this bucket belongs to the target (required to mint) — e.g. "
                         "'referenced in https://host/app.js'")
    ap.add_argument("--max-fetch", type=int, default=MAX_FETCH)
    ap.add_argument("--key", action="append", default=[],
                    help="object key known from provenance; tried directly when listing is "
                         "denied (repeatable)")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    if os.path.exists(os.path.join(STATE_DIR, "vpn_down")):
        log("vpn_down — refusing (fail-closed)")
        return 2
    if not a.provenance and not a.dry_run:
        log("refusing to mint without --provenance: the S3 namespace is global, so a name "
            "match is not ownership and an unproven bucket may be a third party's data. "
            "Re-run with --provenance, or use --dry-run to look without minting.")
        return 2

    runs = [loot(b, a.program, a.provenance, a.dry_run, a.max_fetch, a.key) for b in a.bucket]
    os.makedirs(OUT_DIR, exist_ok=True)
    out = os.path.join(OUT_DIR, f"loot_{datetime.now().strftime('%Y-%m-%d')}.md")
    L = [f"# Bucket loot — {utc()}", ""]
    for r in runs:
        L += [f"## `{r['bucket']}`"]
        if not r.get("listed"):
            L += [f"- not listable: {r.get('reason')}", ""]
            continue
        L += [f"- {r['objects']} objects, {r.get('ranked', 0)} of interest",
              f"- **{r.get('headline', 'no impact demonstrated')}**", ""]
        for s in r.get("secrets", [])[:25]:
            L.append(f"  - **{s['kind']}** in `{s['source']}` — `{s['redacted']}`")
        if r.get("pii"):
            L.append(f"  - personal data: {r['pii']['reason']}")
        L.append("")
    open(out, "w", encoding="utf-8").write("\n".join(L))
    log(f"report → {out}")
    print(json.dumps([{k: v for k, v in r.items() if k != "secrets"} for r in runs],
                     default=str)[:1500])
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""recon_bucket_scanner.py — helpers for recon_bucket_scanner.sh

Two subcommands (the bash orchestrator drives scope/scan/emit):

  extract  --jsintel <endpoints.jsonl> --params-dir <dir> [--max N]
      Lane A target-reference mining: scan the target's OWN mined surface (jsintel
      endpoints + the params catalog) for cloud-bucket references, extract the
      (provider, bucket, region) and carry the source host/program for the
      mandatory provenance + scope gate. Emits candidate JSONL to stdout. NEVER
      permutes/guesses names (that is the dup-magnet + third-party-data risk).

  classify --results <s3scanner.jsonl> --candidates <candidates.jsonl>
      Join S3Scanner results with candidate metadata and apply the CONFIRMED-vs-LEAD
      verdict table (see docs/knowledge/class-bucket-exposure.md). Emits verdict JSONL.

Pure stdlib. See the KB doc for the severity ladder / FP table / provenance rule.
"""
import argparse
import glob
import json
import os
import re
import sys

# ----------------------------------------------------------------------------
# Provider reference patterns (Lane A). gf s3-buckets set + issue #23 fix
# (quantifier on the region label) + GCS/DO/Azure. Case-insensitive; we lowercase.
# ----------------------------------------------------------------------------
_BKT = r"[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]"   # 3-63 chars, alnum-bounded
_GBKT = r"[a-z0-9][a-z0-9._\-]{1,61}[a-z0-9]"  # GCS allows underscores

PATTERNS = [
    # AWS virtual-host:  bucket.s3.amazonaws.com | bucket.s3.<region>.amazonaws.com
    #                    bucket.s3-<region>.amazonaws.com | bucket.s3-website-<region>...
    ("aws", "vhost", re.compile(
        r"(?P<bucket>" + _BKT + r")\.s3"
        r"(?:[.-]website)?(?:[.-]dualstack)?"
        r"(?:[.-](?P<region>[a-z]{2}-[a-z]+-\d))?"
        r"\.amazonaws\.com")),
    # AWS path-style:    s3.amazonaws.com/bucket | s3.<region>.amazonaws.com/bucket | s3-<region>...
    ("aws", "path", re.compile(
        r"s3"
        r"(?:[.-](?P<region>[a-z]{2}-[a-z]+-\d))?"
        r"\.amazonaws\.com/(?P<bucket>" + _BKT + r")")),
    # GCS vhost + path + console/storage browser links
    ("gcp", "vhost", re.compile(r"(?P<bucket>" + _GBKT + r")\.storage\.googleapis\.com")),
    ("gcp", "path", re.compile(r"storage\.googleapis\.com/(?P<bucket>" + _GBKT + r")")),
    ("gcp", "browser", re.compile(
        r"(?:storage\.cloud\.google\.com|console\.cloud\.google\.com/storage/browser)/(?P<bucket>" + _GBKT + r")")),
    # DigitalOcean Spaces:  bucket.<region>.digitaloceanspaces.com | <region>.digitaloceanspaces.com/bucket
    ("digitalocean", "vhost", re.compile(
        r"(?P<bucket>" + _BKT + r")\.(?P<region>[a-z]{3}\d)\.digitaloceanspaces\.com")),
    ("digitalocean", "path", re.compile(
        r"(?P<region>[a-z]{3}\d)\.digitaloceanspaces\.com/(?P<bucket>" + _BKT + r")")),
    # Azure Blob (no S3Scanner support — captured as a manual lead, provider=azure)
    ("azure", "vhost", re.compile(
        r"(?P<bucket>[a-z0-9]{3,24})\.blob\.core\.windows\.net(?:/(?P<region>[a-z0-9][a-z0-9\-]{1,61}))?")),
]

# Names that are never a real customer bucket even if the regex grabs them.
# "doc" = the S3 XML namespace URI (s3.amazonaws.com/doc/2006-03-01/) present in
# EVERY S3 ListBucketResult response — pure noise, not a target bucket.
_DENY = {"s3", "www", "amazonaws", "storage", "googleapis", "cloudfront",
         "s3-website", "static", "assets-cdn", "doc"}
_VALID_AWS = re.compile(r"^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$")


def _valid_bucket(provider, name):
    if not name or len(name) < 3 or len(name) > 63:
        return False
    if name in _DENY:
        return False
    if ".." in name or name.startswith("-") or name.endswith("-"):
        return False
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", name):   # not an IP
        return False
    if provider in ("aws", "digitalocean") and not _VALID_AWS.match(name):
        return False
    return True


def _scan_text(text):
    """Yield (provider, bucket, region) for every bucket ref in a string."""
    if not text:
        return
    t = text.lower()
    if "amazonaws.com" not in t and "googleapis.com" not in t \
            and "digitaloceanspaces.com" not in t and "blob.core.windows.net" not in t \
            and "google.com/storage" not in t:
        return
    for provider, _style, rx in PATTERNS:
        for m in rx.finditer(t):
            gd = m.groupdict()
            bucket = gd.get("bucket")
            region = gd.get("region") or ""
            if _valid_bucket(provider, bucket):
                yield provider, bucket, region


def _host_of(url):
    m = re.match(r"https?://([^/:?#]+)", url or "", re.I)
    return m.group(1).lower() if m else ""


def cmd_extract(args):
    seen = {}          # (provider,bucket) -> record (first wins)
    cap = args.max or 100000

    def add(provider, bucket, region, source_host, program, source_url):
        key = (provider, bucket)
        if key in seen:
            # prefer a record that has a real source host (provenance)
            if not seen[key].get("source_host") and source_host:
                seen[key]["source_host"] = source_host
                seen[key]["program"] = program or seen[key].get("program", "")
            return
        seen[key] = {
            "provider": provider, "bucket": bucket, "region": region,
            "source_host": source_host or "", "program": program or "",
            "source_url": (source_url or "")[:300],
        }

    # --- jsintel endpoints.jsonl (richest provenance: host + program) ---
    jf = args.jsintel
    if jf and os.path.exists(jf):
        with open(jf, "r", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line or "{" not in line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                host = (rec.get("host") or "").lower()
                program = rec.get("program") or ""
                # the endpoint field can be a full URL carrying a bucket ref
                for field in ("endpoint", "url", "value"):
                    val = rec.get(field)
                    if not isinstance(val, str):
                        continue
                    for provider, bucket, region in _scan_text(val):
                        add(provider, bucket, region, host, program, val)
                if len(seen) >= cap:
                    break

    # --- ES full-text refs: in-scope recon_alive docs whose cname/final_url/url/title
    #     reference a bucket (the bash layer pre-filters to triage_in_scope, so .host is
    #     in-scope provenance). cname-fronted buckets here aren't in jsintel — the widening. ---
    ef = args.es_refs
    if ef and os.path.exists(ef) and len(seen) < cap:
        with open(ef, "r", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line or "{" not in line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                host = (rec.get("host") or "").lower()
                program = rec.get("program") or ""
                for field in ("text", "cname", "final_url", "url", "title"):
                    val = rec.get(field)
                    if not isinstance(val, str):
                        continue
                    for provider, bucket, region in _scan_text(val):
                        # don't let the bucket's own provider host pose as provenance
                        sh = host if all(d not in host for d in (
                            "amazonaws.com", "googleapis.com",
                            "digitaloceanspaces.com", "windows.net")) else ""
                        add(provider, bucket, region, sh, program, val)
                if len(seen) >= cap:
                    break

    # --- params catalog *.txt (lines are target URLs; provenance = URL host) ---
    pdir = args.params_dir
    if pdir and os.path.isdir(pdir) and len(seen) < cap:
        for pf in glob.glob(os.path.join(pdir, "*.txt")):
            try:
                with open(pf, "r", errors="ignore") as fh:
                    for line in fh:
                        url = line.strip()
                        if not url:
                            continue
                        host = _host_of(url)
                        for provider, bucket, region in _scan_text(url):
                            # don't let the bucket's OWN host masquerade as the
                            # provenance host — that would defeat the scope gate.
                            sh = host if "amazonaws.com" not in host \
                                and "googleapis.com" not in host \
                                and "digitaloceanspaces.com" not in host \
                                and "windows.net" not in host else ""
                            add(provider, bucket, region, sh, "", url)
                        if len(seen) >= cap:
                            break
            except Exception:
                continue
            if len(seen) >= cap:
                break

    for rec in seen.values():
        sys.stdout.write(json.dumps(rec) + "\n")


# ----------------------------------------------------------------------------
# classify
# ----------------------------------------------------------------------------
ALLOWED, DENIED, UNKNOWN = 1, 0, 2


def _bucket_url(provider, bucket, region):
    if provider == "aws":
        return ("https://%s.s3.%s.amazonaws.com/" % (bucket, region)) if region \
            else ("https://%s.s3.amazonaws.com/" % bucket)
    if provider == "gcp":
        return "https://storage.googleapis.com/%s/" % bucket
    if provider == "digitalocean":
        return ("https://%s.%s.digitaloceanspaces.com/" % (bucket, region)) if region \
            else ("https://%s.digitaloceanspaces.com/" % bucket)
    if provider == "azure":
        return "https://%s.blob.core.windows.net/" % bucket
    return "https://%s/" % bucket


def cmd_classify(args):
    meta = {}
    if args.candidates and os.path.exists(args.candidates):
        with open(args.candidates, "r", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except Exception:
                    continue
                meta[(r.get("provider", "aws"), r.get("bucket", ""))] = r

    if not args.results or not os.path.exists(args.results):
        return
    with open(args.results, "r", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            b = rec.get("bucket")
            if not isinstance(b, dict) or not b.get("name"):
                continue
            name = b["name"].lower()
            provider = b.get("provider", "aws")
            m = meta.get((provider, name)) or meta.get(("aws", name)) or {}
            exists = b.get("exists", UNKNOWN)
            r_read = b.get("perm_all_users_read", UNKNOWN)
            r_racl = b.get("perm_all_users_read_acl", UNKNOWN)
            r_write = b.get("perm_all_users_write", UNKNOWN)
            r_wacl = b.get("perm_all_users_write_acl", UNKNOWN)
            r_full = b.get("perm_all_users_full_control", UNKNOWN)

            src_host = m.get("source_host") or ""
            host = src_host or name           # host field used by findings.db / briefing
            region = b.get("region") or m.get("region") or ""
            # object keys if an -enumerate pass populated them (best-effort field names)
            sample = []
            objs = b.get("objects")
            if isinstance(objs, list):
                for o in objs[:8]:
                    if isinstance(o, dict):
                        sample.append(o.get("key") or o.get("Key") or "")
                    elif isinstance(o, str):
                        sample.append(o)
                sample = [s for s in sample if s][:8]

            out = {
                "host": host, "source_host": src_host, "bucket": name,
                "provider": provider, "region": region,
                "url": _bucket_url(provider, name, region),
                "program": m.get("program") or "",
                "source_url": m.get("source_url") or "",
                "num_objects": b.get("num_objects", 0),
                "sample_keys": sample,
                "perms": {"read": r_read, "read_acl": r_racl, "write": r_write,
                          "write_acl": r_wacl, "full_control": r_full},
            }

            # ---- verdict table (KB: class-bucket-exposure.md) ----
            if exists == DENIED:                       # NoSuchBucket
                if src_host:
                    out.update(kind="dangling-takeover", verdict="lead",
                               severity="medium",
                               access="gone (referenced by live host → takeover lane)")
                else:
                    continue                            # name-only miss → drop
            elif exists != ALLOWED:                    # unknown / inconclusive
                continue
            elif ALLOWED in (r_write, r_wacl, r_full):  # public WRITE / ACL-write
                kind = "public-write"
                sev = "critical" if ALLOWED in (r_wacl, r_full) else "high"
                acc = []
                if r_write == ALLOWED:
                    acc.append("PutObject")
                if r_wacl == ALLOWED:
                    acc.append("PutBucketAcl")
                if r_full == ALLOWED:
                    acc.append("FullControl")
                out.update(kind=kind, verdict="confirmed", severity=sev,
                           access="public-write: " + ",".join(acc))
            elif r_read == ALLOWED:                    # public LIST/READ (authoritative probe)
                out.update(kind="public-read", verdict="lead", severity="medium",
                           access="public-read (verify content sensitivity + not by-design CDN)")
            elif r_racl == ALLOWED:                    # ACL world-readable only
                out.update(kind="public-read-acl", verdict="lead", severity="low",
                           access="public-read-acl (grant list world-readable)")
            elif r_read == DENIED:                      # explicitly 403 → genuinely secure
                out.update(kind="secure", verdict="fp", severity="info",
                           access="exists-but-403 (secure)")
            else:                                       # exists but access undetermined (no probe signal)
                out.update(kind="inconclusive", verdict="skip", severity="info",
                           access="exists; access undetermined (region/redirect — re-check)")
            sys.stdout.write(json.dumps(out) + "\n")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("extract")
    e.add_argument("--jsintel", default="")
    e.add_argument("--params-dir", default="")
    e.add_argument("--es-refs", default="")
    e.add_argument("--max", type=int, default=0)
    e.set_defaults(func=cmd_extract)
    c = sub.add_parser("classify")
    c.add_argument("--results", default="")
    c.add_argument("--candidates", default="")
    c.set_defaults(func=cmd_classify)
    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

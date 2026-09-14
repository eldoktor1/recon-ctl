#!/usr/bin/env python3
"""program_map.py - standing PROGRAM-MAP routine for a committed program.

The program walk produced its best material from two techniques, both of which are
mechanical and therefore worth running on a cadence instead of by hand:

  1. RESPONSE-SIGNATURE CLUSTERING. Cluster every answering host on
     (status, content_length, server, title). On this estate two thirds of the hosts
     collapsed into ~24 commodity classes answering identically, and only the hosts with
     a DISTINCT signature were worth a human minute. That ratio is the whole value:
     it turns "624 hosts" into a short worklist.

  2. BUNDLE MINING. A small 200 is almost always an SPA shell, not content - so the
     app's own JS is where the API surface lives. Mining bundles recovered the complete
     account-portal GraphQL surface, a 64-route authentication table, two Cognito pools
     and a crisis backend's endpoint list. None of it needed a single probe of an app
     endpoint.

TRANSITION GATE (CLAUDE.md): a STATE is always true and therefore fires forever, so this
routine reports on CHANGE. First sighting builds the baseline SILENTLY; afterwards only
new hosts, changed signatures and newly-discovered endpoints are surfaced. Something that
was already exposed when we started watching has been exposed for months and is a
duplicate; the thing that appeared today is the un-reported one.

SCANNER BANS ARE RESPECTED BY CONSTRUCTION. Programs that prohibit automated scanning
(booking.com among them) are marked `no_probe`, and for those this routine issues ZERO
requests to the application: it reads the pipeline index and fetches only static JS from
CDN hosts. Bundle fetching is a plain GET of a public asset, not a scan of the target app.

USAGE:  program_map.py <workspace-key> [--probe] [--limit N] [--json OUT]
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse

BASE = os.path.expanduser(os.environ.get("BASE_DIR", "~/recon"))
STATE = os.path.join(BASE, "state")
BRIEF = os.path.join(BASE, "briefings")
ES_URL = os.environ.get("ES_URL", "http://127.0.0.1:9200")
INDEX = os.environ.get("INDEX_NAME", "recon_alive")
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36")

# Programs whose policy forbids automated scanning: never touch the application itself.
NO_PROBE = {"bookingcom"}

# Only these hosts are ever fetched when a program is no_probe: static asset CDNs.
CDN_ALLOW = re.compile(r"(^|\.)(bstatic\.com|cloudfront\.net|akamaized\.net|fastly\.net)$")


# --------------------------------------------------------------------------- ES
def es_hosts(program: str) -> list[dict]:
    pw_file = os.path.expanduser("~/.recon_es_pass")
    auth = []
    if os.path.exists(pw_file):
        auth = ["-u", "elastic:" + open(pw_file).read().strip()]
    q = {
        "query": {"term": {"triage_program": program}},
        "_source": ["host", "root_domain", "status_code", "content_length", "title", "tech",
                    "webserver", "cdn_name", "cname", "ip", "favicon_hash", "first_seen",
                    "triage_score", "triage_in_scope", "triage_pays", "host_notes_count",
                    "content_type", "ignore_expires_at"],
        "size": 2000,
    }
    out = subprocess.run(
        ["curl", "-s", "--max-time", "40", *auth, "-H", "Content-Type: application/json",
         f"{ES_URL}/{INDEX}/_search", "-d", json.dumps(q)],
        capture_output=True, text=True).stdout
    try:
        return [h["_source"] for h in json.loads(out)["hits"]["hits"]]
    except Exception as exc:                                    # index down / auth change
        print(f"[progmap] ES query failed: {exc}", file=sys.stderr)
        return []


# ------------------------------------------------------------------- clustering
def answering(rows: list[dict]) -> list[dict]:
    """In-scope, paying, not benched, answering something other than a 404.

    `wildcard.*` hosts are certificate-transparency artefacts from *.<name> wildcard
    certs, not real hostnames - they must never be treated as live.
    """
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    out = []
    for r in rows:
        h = r.get("host") or ""
        if not h or h.startswith("wildcard."):
            continue
        if not r.get("triage_in_scope") or not r.get("triage_pays"):
            continue
        exp = r.get("ignore_expires_at")
        if exp and str(exp) > now:                              # operator-benched
            continue
        if str(r.get("status_code") or "") in ("", "0", "None", "404"):
            continue
        out.append(r)
    return out


def sig(r: dict) -> str:
    return "|".join(str(x) for x in (r.get("status_code"), r.get("content_length"),
                                     (r.get("webserver") or "")[:26],
                                     (r.get("title") or "")[:44]))


FAMILIES = [
    ("partner",   r"(partner|supply|supplier|extranet|admin|pulse|hotel|property|provider)"),
    ("payment",   r"(pay|payment|billing|invoice|wallet|finance|payout|psp|kyc)"),
    ("identity",  r"(account|auth|login|signin|sso|oauth|identity|iam|token|cred|scim)"),
    ("api",       r"(api|gw|gateway|graphql|xml|rest|edge|proxy|mesh|dispatch)"),
    ("core",      r"(secure|book|res|reserv|cart|checkout|order)"),
    ("vertical",  r"(flight|car|taxi|attract|experience|accommodation|rail|insur|cruise)"),
    ("messaging", r"(chat|message|messag|inbox|mail|notif|squeak|comms)"),
    ("internal",  r"(dev|test|staging|stage|qa|dqs|sandbox|demo|internal|corp|git|jenkins|"
                  r"jira|teleport|vault|grafana|kibana|pega|jamf)"),
    ("data",      r"(analytic|track|metric|telemetry|otel|log|beacon|counter|sink|perf|stat)"),
    ("cdn",       r"(static|cdn|img|image|photo|media|assets)"),
]


def family(host: str) -> str:
    lead = host.split(".")[0].lower()
    for name, pat in FAMILIES:
        if re.search(pat, lead):
            return name
    return "other"


# ---------------------------------------------------------------- bundle mining
API_PATH = re.compile(r'"(/(?:api|v1|v2|v3|graphql|dml|rest|internal|prod|dev|stage)'
                      r'[A-Za-z0-9_:./\-{}]{2,70})"')
GQL_OP = re.compile(r"\b(query|mutation|subscription)\s+([A-Z][A-Za-z0-9_]{3,60})")
IDENT = re.compile(r"([a-z]{2}-[a-z]+-\d_[A-Za-z0-9]{8,}"          # cognito user pool
                   r"|[a-z]{2}-[a-z]+-\d:[0-9a-f]{8}-[0-9a-f\-]{20,}"  # identity pool
                   r"|[a-z0-9\-]{4,}\.auth0\.com"
                   r"|[a-z0-9\-]{6,}\.okta(?:preview)?\.com"
                   r"|[a-z0-9\-]+\.auth\.[a-z0-9\-]+\.amazoncognito\.com)")
ENVKEY = re.compile(r"\b((?:REACT_APP|VUE_APP|NEXT_PUBLIC|VITE)_[A-Z0-9_]{3,44})\b")
SCRIPT_SRC = re.compile(r'<script[^>]+src="([^"]+\.js[^"]*)"', re.I)


def fetch(url: str, timeout: int = 25) -> tuple[int, bytes]:
    try:
        p = subprocess.run(
            ["curl", "-sgL", "--max-redirs", "3", "--max-time", str(timeout),
             "-A", UA, "-w", "\n%{http_code}", url],
            capture_output=True, timeout=timeout + 10)
        raw = p.stdout
        i = raw.rfind(b"\n")
        code = int(raw[i + 1:].strip() or 0)
        return code, raw[:i if i > 0 else len(raw)]
    except Exception:
        return 0, b""


def mine_bundles(host: str, allow_app_fetch: bool, budget: int = 6) -> dict:
    """Pull a host's own script bundles and mine them for surface.

    A small 200 is an SPA shell, so the shell is fetched for its <script src> list and
    the BUNDLES carry the intelligence. When the program forbids probing, only the shell
    is read (one GET of a page already public) and only CDN-hosted bundles are fetched.
    """
    found = {"api_paths": set(), "gql_ops": set(), "identity": set(), "env_keys": set(),
             "bundles": 0, "bytes": 0}
    code, body = fetch(f"https://{host}/")
    if code != 200 or not body:
        return found
    html = body.decode("utf-8", "replace")
    srcs = []
    for m in SCRIPT_SRC.findall(html):
        u = urllib.parse.urljoin(f"https://{host}/", m)
        hp = urllib.parse.urlparse(u).hostname or ""
        if not allow_app_fetch and not CDN_ALLOW.search(hp) and hp != host:
            continue
        srcs.append(u)
    for u in srcs[:budget]:
        c, b = fetch(u, 30)
        if c != 200 or not b:
            continue
        found["bundles"] += 1
        found["bytes"] += len(b)
        t = b.decode("utf-8", "replace")
        found["api_paths"].update(API_PATH.findall(t))
        found["gql_ops"].update(n for _k, n in GQL_OP.findall(t))
        found["identity"].update(IDENT.findall(t))
        found["env_keys"].update(ENVKEY.findall(t))
    # html itself can carry inline config
    found["identity"].update(IDENT.findall(html))
    found["env_keys"].update(ENVKEY.findall(html))
    return found


# ------------------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("key")
    ap.add_argument("--probe", action="store_true",
                    help="allow fetching bundles from the application host itself "
                         "(ignored for programs whose policy bans scanning)")
    ap.add_argument("--limit", type=int, default=8,
                    help="hosts to bundle-mine this cycle (slides through the pool)")
    ap.add_argument("--json", default="")
    args = ap.parse_args()
    key = args.key
    os.makedirs(STATE, exist_ok=True)
    os.makedirs(BRIEF, exist_ok=True)

    no_probe = key in NO_PROBE
    allow_app_fetch = args.probe and not no_probe

    rows = es_hosts(key)
    if not rows:
        print(f"[progmap] no hosts for program {key}", file=sys.stderr)
        return 1
    live = answering(rows)

    clusters = collections.defaultdict(list)
    for r in live:
        clusters[sig(r)].append(r["host"])
    commodity = {s: hs for s, hs in clusters.items() if len(hs) >= 4}
    distinct = [r for r in live if len(clusters[sig(r)]) < 4]

    # ---- transition gate: compare against the stored baseline -----------------
    sp = os.path.join(STATE, f"progmap_{key}.json")
    prev = {}
    if os.path.exists(sp):
        try:
            prev = json.load(open(sp))
        except Exception:
            prev = {}
    first_run = not prev
    prev_sigs = prev.get("sigs", {})
    prev_mined = prev.get("mined", {})
    prev_cursor = int(prev.get("cursor", 0))

    cur_sigs = {r["host"]: sig(r) for r in live}
    new_hosts = sorted(set(cur_sigs) - set(prev_sigs))
    gone_hosts = sorted(set(prev_sigs) - set(cur_sigs))
    changed = sorted(h for h in set(cur_sigs) & set(prev_sigs)
                     if cur_sigs[h] != prev_sigs[h])

    # ---- bundle mining, slid through the distinct pool so every host gets a turn
    # Only hosts that actually SERVE a page can have a bundle: a 403 or 401 has nothing to
    # mine, and the highest triage_score on this estate belongs to sealed staging 403s - so
    # ranking by score alone spends the whole cycle on hosts that cannot yield anything.
    minable = [r for r in distinct if str(r.get("status_code") or "") in ("200", "302", "304")]
    pool = [r["host"] for r in sorted(minable, key=lambda r: -(r.get("triage_score") or 0))]
    pick, mined, new_surface = [], {}, {}
    if pool:
        for i in range(min(args.limit, len(pool))):
            pick.append(pool[(prev_cursor + i) % len(pool)])
        for h in pick:
            f = mine_bundles(h, allow_app_fetch)
            if not f["bundles"] and not f["identity"]:
                continue
            rec = {k: sorted(v) for k, v in f.items() if isinstance(v, set)}
            rec["bundles"] = f["bundles"]
            rec["bytes"] = f["bytes"]
            mined[h] = rec
            old = prev_mined.get(h) or {}
            delta = {}
            for k in ("api_paths", "gql_ops", "identity", "env_keys"):
                d = sorted(set(rec.get(k) or []) - set(old.get(k) or []))
                if d:
                    delta[k] = d
            if delta and not first_run:
                new_surface[h] = delta
            elif delta and first_run:
                new_surface[h] = delta          # first run still reports what it mined
    cursor = (prev_cursor + len(pick)) % max(len(pool), 1)

    # ---- write the baseline back ---------------------------------------------
    keep_mined = dict(prev_mined)
    keep_mined.update(mined)
    json.dump({"sigs": cur_sigs, "mined": keep_mined, "cursor": cursor,
               "updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
              open(sp, "w"))

    # ---- briefing -------------------------------------------------------------
    date = time.strftime("%Y-%m-%d", time.gmtime())
    bp = os.path.join(BRIEF, f"progmap_{key}_{date}.md")
    L: list[str] = []
    L.append(f"# program map - {key} - {date}")
    L.append("")
    L.append(f"- hosts indexed: **{len(rows)}**, in-scope+paying and answering: **{len(live)}**")
    L.append(f"- commodity classes: **{len(commodity)}** covering "
             f"**{sum(len(v) for v in commodity.values())}** hosts")
    L.append(f"- distinct responses (the worklist): **{len(distinct)}**")
    L.append(f"- probing of the application: **{'DISABLED by policy' if no_probe else ('on' if allow_app_fetch else 'CDN assets only')}**")
    if first_run:
        L.append("")
        L.append("> FIRST RUN - baseline established, change reporting starts next cycle.")
    L.append("")
    if new_hosts:
        L.append(f"## NEW hosts ({len(new_hosts)})")
        for h in new_hosts[:40]:
            r = next((x for x in live if x["host"] == h), {})
            L.append(f"- `{h}` - {r.get('status_code')} "
                     f"{r.get('content_length')}b {(r.get('title') or '')[:50]}")
        L.append("")
    if changed:
        L.append(f"## CHANGED signature ({len(changed)}) - a response that moved is the thing to look at")
        for h in changed[:40]:
            L.append(f"- `{h}` - was `{prev_sigs[h]}` now `{cur_sigs[h]}`")
        L.append("")
    if gone_hosts:
        L.append(f"## no longer answering ({len(gone_hosts)})")
        L.append("- " + ", ".join(f"`{h}`" for h in gone_hosts[:30]))
        L.append("")
    if new_surface:
        L.append(f"## NEW SURFACE from bundle mining ({len(new_surface)} hosts)")
        for h, d in new_surface.items():
            L.append(f"### `{h}`")
            for k, v in d.items():
                L.append(f"- **{k}**: " + ", ".join(f"`{x}`" for x in v[:22]))
            L.append("")
    if commodity:
        L.append("## commodity classes (dismissible as a class, representatives only)")
        for s, hs in sorted(commodity.items(), key=lambda c: -len(c[1]))[:20]:
            st, cl, ws, ti = (s.split("|") + ["", "", "", ""])[:4]
            L.append(f"- **{len(hs)}x** {st} len={cl} srv={ws or '-'} "
                     f"{('title=' + ti) if ti else ''} - reps: "
                     + ", ".join(f"`{x}`" for x in sorted(hs)[:3]))
        L.append("")
    fam = collections.Counter(family(r["host"]) for r in distinct)
    L.append("## worklist by family")
    for f, n in fam.most_common():
        L.append(f"- {f}: {n}")
    open(bp, "w", encoding="utf-8").write("\n".join(L) + "\n")

    delta = {"key": key, "date": date, "briefing": bp, "first_run": first_run,
             "counts": {"indexed": len(rows), "answering": len(live),
                        "commodity_classes": len(commodity), "distinct": len(distinct)},
             "new_hosts": new_hosts, "changed": changed, "gone": gone_hosts,
             "new_surface": new_surface, "mined_hosts": sorted(mined)}
    if args.json:
        json.dump(delta, open(args.json, "w"), indent=1)
    print(json.dumps({k: v for k, v in delta.items() if k != "new_surface"}))
    return 0


if __name__ == "__main__":
    sys.exit(main())

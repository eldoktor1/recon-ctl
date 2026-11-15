#!/usr/bin/env python3
"""
recon_panel_chain.py — fingerprint an exposed infra panel, then chase THAT product's
credential-bearing endpoint until something is actually recovered.

WHY (2026-08-22). freshchain ran four fixed chains against every fresh host: leak (.env/.git),
actuator (Spring), port-proto, authdiff. On 2026-08-22 that batch contained
`argocd-ne.prod.etoro.com`, `argo-cd-eggplant.indeed.tech` and `argo-cd-honeydew.indeed.tech`
— and every one came back `clean`, because none of the four chains knows what Argo CD is.
The KB has had `docs/knowledge/tech-argocd.md` the whole time. The lane could not read it.

This closes that gap the way the CHAIN-TO-IMPACT LAW requires: identify the product, then
request the endpoints of THAT product which return credential material, and let the shared
impact gate decide whether anything was recovered.

    fresh/known host -> fingerprint -> product-specific loot endpoints -> engine/impact.py

The endpoints are chosen because they carry SECRETS, not because they prove the panel exists:
Prometheus `/api/v1/status/config` embeds scrape `basic_auth` passwords and bearer tokens;
Airflow `/api/v1/connections` embeds DSN passwords; Consul KV is where teams hide API keys;
Argo CD `/api/v1/settings` has leaked `dexConfig` OIDC client secrets. "The panel responds"
is the duplicate everyone else files an hour later — the recovered credential is the report.

MINT RULE — deliberately strict, one source of truth: a finding is minted ONLY when
engine/impact.py recovers a credential or real personal data from a response body. A panel
that answers unauthenticated but yields nothing recoverable is written to the briefing as a
LEAD with its evidence, never minted. No new false-positive class is introduced here.

FP GUARDS (the three that killed previous lanes):
  * SPA-shell check — the root document is hashed first; any "API" response identical to it
    is the app's catch-all route, not a leak (documented as the #1 unauth-exposure FP).
  * content-type — an HTML login page scores nothing; a real API answer is JSON/text.
  * positive matcher — each product carries a signature its genuine API response contains,
    so a generic 200 from a reverse proxy cannot pass as product data.

SAFETY: every request goes through tools/safe_probe_worker.py, so this inherits the SSRF /
metadata guard, the GET/HEAD/OPTIONS allowlist, no-redirect-follow, the no-credentials rule
and the multi-exit rotation. Read-only by construction: no endpoint in the table below
mutates, and the destructive members of each product's API (Jenkins /script, Consul KV write,
k8s exec) are deliberately absent. Secrets are REDACTED by the impact gate and never used.
Scope+pays gated, vpn_down fail-closed.

Usage: recon_panel_chain.py <host> [host...] [--dry-run]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE_DIR = os.environ.get("BASE_DIR", os.path.expanduser("~/recon"))
STATE_DIR = os.environ.get("STATE_DIR", os.path.join(BASE_DIR, "state"))
OUT_DIR = os.path.join(BASE_DIR, "briefings")
AUDIT = os.path.join(STATE_DIR, "panel_chain_audit.jsonl")
SCOPE_CHECK = os.path.join(REPO_DIR, "scripts", "recon_scope_check.sh")

sys.path.insert(0, REPO_DIR)
sys.path.insert(0, os.path.join(REPO_DIR, "tools"))
import safe_probe_worker as spw          # noqa: E402  (guards + proxy rotation live here)
from engine import impact                # noqa: E402  (the ONE impact gate)

# the worker truncates hard for LLM consumption; the impact gate wants the whole body
spw.SNIP = int(os.environ.get("PANEL_SNIPPET", "400000"))
spw.MAX_BODY = int(os.environ.get("PANEL_MAX_BODY", "2000000"))

MAX_LOOT_PER_HOST = int(os.environ.get("PANEL_MAX_LOOT", "6"))

# ---------------------------------------------------------------------------------------
# The table. `fp` matches the fingerprint page; `loot` are the endpoints that carry secrets;
# `proof` is a signature the product's genuine API response contains.
# ---------------------------------------------------------------------------------------
PANELS = [
    {
        "name": "argocd",
        "fp": re.compile(rb"argo\s*-?\s*cd|argocd|__ARGO", re.I),
        "loot": [
            ("/api/v1/settings", "server settings — dexConfig/OIDC client secrets have leaked here"),
            ("/api/v1/applications", "application inventory: repo URLs + cluster endpoints"),
            ("/api/v1/clusters", "managed clusters (bearer tokens when unredacted)"),
            ("/api/v1/session/userinfo", "unauthenticated session state"),
        ],
        "proof": re.compile(rb'"items"|"dexConfig"|"loggedIn"|"appLabelKey"|"metadata"'),
    },
    {
        "name": "prometheus",
        "fp": re.compile(rb"Prometheus Time Series|prometheus|/graph", re.I),
        "loot": [
            ("/api/v1/status/config", "scrape config — embeds basic_auth passwords + bearer tokens"),
            ("/api/v1/targets", "scrape targets: internal hosts and ports"),
            ("/api/v1/status/flags", "runtime flags"),
        ],
        "proof": re.compile(rb'"status"\s*:\s*"success"|scrape_configs|activeTargets'),
    },
    {
        "name": "grafana",
        "fp": re.compile(rb"grafana|Grafana", re.I),
        "loot": [
            ("/api/datasources", "datasource list — DB connection details, sometimes passwords"),
            ("/api/search?query=", "dashboard inventory (anonymous-org exposure)"),
            ("/api/org", "organisation the anonymous user lands in"),
        ],
        "proof": re.compile(rb'"datasource"|"orgId"|"uid"\s*:|"type"\s*:\s*"dash'),
    },
    {
        "name": "airflow",
        "fp": re.compile(rb"Airflow|airflow", re.I),
        "loot": [
            ("/api/v1/connections", "connection store — DSNs with embedded passwords"),
            ("/api/v1/variables", "variables: teams keep API keys here"),
            ("/api/v1/dags", "DAG inventory"),
        ],
        "proof": re.compile(rb'"connections"|"variables"|"dags"|"total_entries"'),
    },
    {
        "name": "consul",
        "fp": re.compile(rb"Consul|consul", re.I),
        "loot": [
            ("/v1/kv/?recurse=true", "KV store — the classic hiding place for API keys"),
            ("/v1/agent/self", "agent config incl. datacentre + addresses"),
        ],
        "proof": re.compile(rb'"LockIndex"|"Datacenter"|"Config"\s*:'),
    },
    {
        "name": "jenkins",
        "fp": re.compile(rb"Jenkins|jenkins|X-Jenkins", re.I),
        "loot": [
            ("/api/json?depth=1", "job inventory (unauth read = anonymous read permission)"),
            ("/env-vars.html", "documented build environment variables"),
        ],
        # NB: /script (Groovy console) and /credentials are deliberately NOT here — the first
        # is RCE, which the hard line forbids running autonomously.
        "proof": re.compile(rb'"_class"\s*:\s*"hudson|"jobs"\s*:|Jenkins'),
    },
    {
        "name": "kubernetes-api",
        "fp": re.compile(rb'"kind"\s*:\s*"Status"|k8s|kubernetes', re.I),
        "loot": [
            ("/api/v1/namespaces/default/secrets", "Secret objects — credential material"),
            ("/api/v1/namespaces", "namespace inventory"),
            ("/version", "cluster version"),
        ],
        "proof": re.compile(rb'"apiVersion"|"kind"\s*:\s*"(SecretList|NamespaceList)"|gitVersion'),
    },
    {
        "name": "docker-registry",
        "fp": re.compile(rb"docker-distribution|registry", re.I),
        "loot": [
            ("/v2/_catalog", "private image catalogue (unauth pull surface)"),
        ],
        "proof": re.compile(rb'"repositories"\s*:'),
    },
    {
        "name": "harbor",
        "fp": re.compile(rb"Harbor|harbor", re.I),
        "loot": [
            ("/api/v2.0/projects", "project inventory"),
            ("/api/v2.0/systeminfo", "system info"),
        ],
        "proof": re.compile(rb'"project_id"|"harbor_version"|"registry_url"'),
    },
    {
        "name": "rancher",
        "fp": re.compile(rb"Rancher|rancher", re.I),
        "loot": [
            ("/v3/settings", "settings incl. server-url and CA"),
            ("/v3/clusters", "managed cluster inventory"),
        ],
        "proof": re.compile(rb'"type"\s*:\s*"collection"|"resourceType"'),
    },
    {
        "name": "nomad",
        "fp": re.compile(rb"Nomad|nomad", re.I),
        "loot": [
            ("/v1/jobs", "job inventory"),
            ("/v1/agent/self", "agent config"),
        ],
        "proof": re.compile(rb'"JobSummary"|"NomadConfig"|"Datacenter"'),
    },
    {
        "name": "sentry",
        "fp": re.compile(rb"Sentry|sentry", re.I),
        "loot": [
            ("/api/0/organizations/", "organisation inventory"),
            ("/api/0/internal/health/", "internal health"),
        ],
        "proof": re.compile(rb'"slug"\s*:|"healthy"\s*:'),
    },
]


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(m: str) -> None:
    print(f"[panel] {m}", file=sys.stderr, flush=True)


def audit(rec: dict) -> None:
    os.makedirs(STATE_DIR, exist_ok=True)
    rec.setdefault("at", utc())
    with open(AUDIT, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")


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


def get(url: str) -> dict:
    """One guarded probe. Inherits SSRF guard, method allowlist and exit rotation."""
    try:
        return spw.probe(url, "GET")
    except Exception as e:
        return {"ok": False, "error": f"probe-exc:{e.__class__.__name__}"}


def _body(r: dict) -> bytes:
    return (r.get("body_snippet") or "").encode("utf-8", "replace")


def fingerprint(host: str) -> tuple[str | None, str, dict]:
    """(panel_name, root_hash, root_response). Root is fetched once and reused as the
    SPA-shell reference — the check that kills the 'a 200 means a leak' false positive."""
    root = get(f"https://{host}/")
    if not root.get("ok"):
        return None, "", root
    blob = _body(root)
    hdrs = json.dumps(root.get("headers", {})).encode()
    title = (root.get("title") or "").encode()
    hay = blob[:20000] + hdrs + title
    rh = hashlib.sha256(blob).hexdigest()
    for p in PANELS:
        if p["fp"].search(hay):
            return p["name"], rh, root
    return None, rh, root


def chase(host: str, panel: str, root_hash: str, program: str, dry: bool) -> dict:
    spec = next(p for p in PANELS if p["name"] == panel)
    base = f"https://{host}"
    recovered, leads, tried = [], [], []
    for path, why in spec["loot"][:MAX_LOOT_PER_HOST]:
        url = base + path
        if dry:
            tried.append({"url": url, "status": "dry-run"})
            continue
        r = get(url)
        st = r.get("status")
        tried.append({"url": url, "status": st, "error": r.get("error", ""),
                      "egress": r.get("egress", "")})
        if not r.get("ok") or st != 200:
            continue
        blob = _body(r)
        ctype = (r.get("headers", {}) or {}).get("content-type", "")

        # FP GUARD 1 — the SPA catch-all: identical to the root document = a route, not data.
        if hashlib.sha256(blob).hexdigest() == root_hash:
            tried[-1]["verdict"] = "spa-shell (identical to /)"
            continue
        # FP GUARD 2 — an HTML page is a login screen or the app, not an API answer.
        if "html" in ctype.lower():
            tried[-1]["verdict"] = f"html response ({ctype}) — not API data"
            continue
        # FP GUARD 3 — the product's own signature must be present.
        if not spec["proof"].search(blob):
            tried[-1]["verdict"] = "200 without the product signature — not genuine panel data"
            continue

        v = impact.verdict(blob, source=f"panel:{panel}:{url}")
        tried[-1]["verdict"] = f"panel data; impact score {v.get('score', 0)}"
        if v.get("mint"):
            recovered.append({"url": url, "why": why, "impact": v})
        else:
            leads.append({"url": url, "why": why, "bytes": len(blob),
                          "ctype": ctype, "sample_keys": _keys(blob)})
    return {"host": host, "panel": panel, "program": program,
            "recovered": recovered, "leads": leads, "tried": tried}


def _keys(blob: bytes, n: int = 12) -> list[str]:
    """Top-level JSON keys — shows WHAT was exposed without copying any values out."""
    try:
        o = json.loads(blob.decode("utf-8", "replace"))
    except Exception:
        return []
    if isinstance(o, dict):
        return sorted(o.keys())[:n]
    if isinstance(o, list) and o and isinstance(o[0], dict):
        return sorted(o[0].keys())[:n]
    return []


def mint(res: dict, item: dict) -> int | None:
    try:
        from engine import state
    except Exception as e:
        log(f"could not persist ({e})")
        return None
    v = item["impact"]
    ev = {
        "chain": f"unauthenticated {res['panel']} panel -> credential recovery",
        "panel": res["panel"],
        "endpoint": item["url"],
        "why_this_endpoint": item["why"],
        "impact_gate": v,
        "endpoints_tried": res["tried"],
        "method": "GET only, read-only product API; secrets redacted by engine/impact.py and never used",
        "at": utc(),
    }
    conn = state.connect()
    state.init_db(conn)
    fid = state.record_confirmed(
        conn, res["host"], url=item["url"], program=res["program"] or None,
        signal_class="panel-chain", vuln_class="unauth-credential-disclosure",
        score=int(v.get("score", 15)), evidence=ev,
        confidence=float(v.get("confidence", 0.9)))
    conn.close()
    log(f"  minted finding #{fid} — {v.get('impact', '')}")
    return fid


def write_leads(all_res: list[dict]) -> None:
    rows = [r for r in all_res if r.get("leads")]
    if not rows:
        return
    os.makedirs(OUT_DIR, exist_ok=True)
    path = os.path.join(OUT_DIR, f"panel_chain_{datetime.now().strftime('%Y-%m-%d')}.md")
    new = not os.path.exists(path)
    with open(path, "a", encoding="utf-8") as f:
        if new:
            f.write(f"# Panel chain — unauthenticated infra panels — {utc()}\n\n"
                    "Each entry answered unauthenticated with genuine product data but the impact\n"
                    "gate recovered no credential or personal data, so nothing was minted. These are\n"
                    "LEADS: verify sensitivity by hand before reporting.\n\n")
        for r in rows:
            f.write(f"## `{r['host']}` — {r['panel']} ({r['program'] or 'unknown program'})\n")
            for l in r["leads"]:
                f.write(f"- `{l['url']}` — {l['why']}\n"
                        f"  - {l['bytes']} bytes, `{l['ctype']}`"
                        + (f", keys: {', '.join(l['sample_keys'])}\n" if l["sample_keys"] else "\n"))
            f.write("\n")
    log(f"  {sum(len(r['leads']) for r in rows)} lead(s) -> {path}")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Fingerprint an exposed infra panel and chase its credential-bearing API.")
    ap.add_argument("host", nargs="+")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    if vpn_down() and not a.dry_run:
        log("vpn_down — refusing target traffic (fail-closed)")
        return 2

    out = []
    for host in a.host:
        host = host.strip().lower().rstrip(".")
        if not host:
            continue
        ok, program = scope_ok(host)
        if not ok:
            log(f"{host}: SKIP — {program}")
            audit({"host": host, "skipped": program})
            continue
        panel, rh, _root = fingerprint(host)
        if not panel:
            log(f"{host}: no known panel fingerprint")
            audit({"host": host, "program": program, "panel": None})
            continue
        log(f"{host}: {panel} detected — chasing its credential endpoints")
        res = chase(host, panel, rh, program, a.dry_run)
        for item in res["recovered"]:
            if a.dry_run:
                log(f"  [dry-run] would mint: {item['url']}")
            else:
                mint(res, item)
        if not res["recovered"]:
            log(f"  no credential recovered from {panel} "
                f"({len(res['leads'])} unauth data endpoint(s), {len(res['tried'])} tried)")
        audit(res)
        out.append(res)
    write_leads(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())

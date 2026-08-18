#!/usr/bin/env python3
"""
recon_program_gate.py — pick the program to COMMIT to, before spending an evening on it.

Every program the operator has abandoned died the same way: not hunted out, but failing
an eligibility check that was run *after* the investment. Couldn't register an account.
Customer-owned instances. An explicit exclusion. This runs those checks up front, in
batch, over every program we have scope data for, and ranks what survives.

It scores for ONE thing: the likelihood of finding an AUTHENTICATED authorization bug
(IDOR / BOLA / broken access control / privilege escalation). That is the class the
findings DB has zero of and the class that pays. A program with a huge unauthenticated
attack surface and no user model scores badly here on purpose — that surface is what
produced 316 false positives.

Signals, in rough order of weight:
  * pays, and pays well (per-asset eligible_for_bounty where the platform exposes it)
  * an actual multi-user application — org/team/role/billing/admin vocabulary in the
    asset names and descriptions is what an authorization model looks like from outside
  * endpoints ALREADY discovered by jsintel — means the differential tester can run today
    rather than after a week of recon
  * wildcard scope (room to move) without being a per-customer tenant estate
  * not already worked to death (host_notes count is our own effort ledger)
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
import sys
from datetime import datetime

BASE = os.path.expanduser("~/recon")
SCOPE = os.path.join(BASE, "scope")
RAW = os.path.join(SCOPE, "raw")
NOTES = os.path.join(BASE, "state", "host_notes.jsonl")
ENDPOINTS = os.path.join(BASE, "js_recon", "endpoints.jsonl")
OUT = os.path.join(BASE, "briefings")

# The vocabulary of an authorization model, seen from the outside.
ROLE_WORDS = re.compile(
    r"(organi[sz]ation|workspace|tenant|team|member|admin|console|portal|dashboard|"
    r"account|customer|billing|invoice|subscription|payment|payout|order|project|"
    r"partner|reseller|merchant|seller|employer|manage|back ?office|crm|erp)", re.I)

# Products whose "in scope" wildcard is mostly other people's installations.
TENANT_ESTATE = re.compile(
    r"(\*\.[a-z0-9-]*(hosting|tenant|instance|customer|client|shop|store|site|cloud)"
    r"[a-z0-9-]*\.)", re.I)

APP_ASSET = re.compile(r"(app|portal|console|dashboard|my|admin|account|secure|manage)", re.I)


def load_json(p):
    try:
        return json.load(open(p, encoding="utf-8"))
    except Exception:
        return []


def norm_host(s: str) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"^\w+://", "", s).split("/")[0].split(":")[0]
    return s.strip()


def collect() -> list[dict]:
    """Flatten all five platforms into one comparable shape."""
    progs: list[dict] = []

    for p in load_json(os.path.join(RAW, "hackerone.json")):
        tg = p.get("targets") or {}
        ins = tg.get("in_scope") or []
        paid = [a for a in ins if a.get("eligible_for_bounty")]
        progs.append(dict(
            platform="hackerone", name=p.get("name"), handle=p.get("handle"),
            url=p.get("url"), pays=bool(p.get("offers_bounties")) and bool(paid),
            max_bounty=0, managed=bool(p.get("managed_program")),
            open=(p.get("submission_state") == "open"),
            assets=[str(a.get("asset_identifier") or "") for a in paid],
            asset_types=[a.get("asset_type") for a in paid],
            descs=[str(a.get("instruction") or "") for a in paid],
            n_assets=len(paid), n_assets_all=len(ins),
            resp_days=p.get("average_time_to_first_program_response"),
        ))

    for p in load_json(os.path.join(RAW, "bugcrowd.json")):
        tg = p.get("targets") or {}
        ins = tg.get("in_scope") or []
        progs.append(dict(
            platform="bugcrowd", name=p.get("name"), handle=p.get("name"),
            url=p.get("url"), pays=bool(p.get("max_payout")),
            max_bounty=p.get("max_payout") or 0, managed=bool(p.get("managed_by_bugcrowd")),
            open=True,
            assets=[str(a.get("target") or a.get("uri") or "") for a in ins],
            asset_types=[a.get("type") for a in ins],
            descs=[str(a.get("name") or "") for a in ins],
            n_assets=len(ins), n_assets_all=len(ins), resp_days=None,
            safe_harbor=p.get("safe_harbor"),
        ))

    for p in load_json(os.path.join(RAW, "intigriti.json")):
        tg = p.get("targets") or {}
        ins = tg.get("in_scope") or []
        mb = (p.get("max_bounty") or {}).get("value") or 0
        progs.append(dict(
            platform="intigriti", name=p.get("name"), handle=p.get("handle"),
            url=p.get("url"), pays=bool(mb), max_bounty=mb, managed=False,
            open=(p.get("status") == "open"),
            assets=[str(a.get("endpoint") or "") for a in ins],
            asset_types=[a.get("type") for a in ins],
            descs=[str(a.get("description") or "") for a in ins],
            n_assets=len(ins), n_assets_all=len(ins), resp_days=None,
        ))

    for p in load_json(os.path.join(RAW, "yeswehack.json")):
        if p.get("disabled"):
            continue
        tg = p.get("targets") or {}
        ins = tg.get("in_scope") or []
        progs.append(dict(
            platform="yeswehack", name=p.get("name"), handle=p.get("id"),
            url=f"https://yeswehack.com/programs/{p.get('id')}",
            pays=bool(p.get("max_bounty")), max_bounty=p.get("max_bounty") or 0,
            managed=bool(p.get("managed")), open=True,
            assets=[str(a.get("target") or "") for a in ins],
            asset_types=[a.get("type") for a in ins],
            descs=[str(a.get("target") or "") for a in ins],
            n_assets=len(ins), n_assets_all=len(ins), resp_days=None,
        ))

    return progs


def effort_index() -> tuple[collections.Counter, collections.Counter]:
    """How much have we ALREADY spent here? notes = effort, and a program with a lot of
    notes and nothing to show is not where the next six weeks go."""
    notes = collections.Counter()
    hosts = collections.Counter()
    if os.path.exists(NOTES):
        for line in open(NOTES, encoding="utf-8", errors="replace"):
            try:
                o = json.loads(line)
            except Exception:
                continue
            pr = (o.get("program") or "").strip().lower()
            if pr:
                notes[pr] += 1
                hosts[pr] += 1
    return notes, hosts


def endpoint_index() -> tuple[collections.Counter, collections.Counter]:
    """Endpoints jsintel already pulled, by program — surface we can differential-test
    on day one instead of week two."""
    eps = collections.Counter()
    api = collections.Counter()
    API = re.compile(r"/(api|v\d|graphql|rest)/", re.I)
    if os.path.exists(ENDPOINTS):
        for line in open(ENDPOINTS, encoding="utf-8", errors="replace"):
            try:
                o = json.loads(line)
            except Exception:
                continue
            pr = (o.get("program") or "").strip().lower()
            if not pr:
                continue
            eps[pr] += 1
            if API.search(o.get("endpoint") or ""):
                api[pr] += 1
    return eps, api


def score(p: dict, notes: collections.Counter, eps: collections.Counter,
          api: collections.Counter) -> dict:
    reasons: list[str] = []
    kills: list[str] = []

    if not p["pays"]:
        kills.append("no bounty (VDP or unpaid assets only)")
    if not p.get("open", True):
        kills.append("not accepting submissions")
    if p["n_assets"] == 0:
        kills.append("no bounty-eligible assets")

    blob = " ".join(p["assets"] + [d for d in p["descs"] if d])
    key = (p["name"] or "").strip().lower()

    # tenant estate — in scope, but mostly other people's installs
    if TENANT_ESTATE.search(blob):
        kills.append("scope is largely per-customer tenant instances")

    s = 0.0

    # --- money ---------------------------------------------------------------
    mb = p.get("max_bounty") or 0
    if mb >= 10000:
        s += 30; reasons.append(f"max bounty {mb:,}")
    elif mb >= 5000:
        s += 22; reasons.append(f"max bounty {mb:,}")
    elif mb >= 2500:
        s += 14; reasons.append(f"max bounty {mb:,}")
    elif mb:
        s += 7; reasons.append(f"max bounty {mb:,}")
    elif p["pays"]:
        s += 10; reasons.append("pays (amount not published)")

    # --- does an authorization model even exist here? ------------------------
    role_hits = len(set(m.group(0).lower() for m in ROLE_WORDS.finditer(blob)))
    if role_hits >= 4:
        s += 34; reasons.append(f"rich user/role vocabulary ({role_hits} distinct)")
    elif role_hits >= 2:
        s += 20; reasons.append(f"has user/role surface ({role_hits})")
    elif role_hits == 1:
        s += 8; reasons.append("thin role surface")
    else:
        s -= 12; reasons.append("no visible user/role model — poor IDOR ground")

    app_assets = sum(1 for a in p["assets"] if APP_ASSET.search(norm_host(a)))
    if app_assets:
        s += min(16, 5 * app_assets); reasons.append(f"{app_assets} app/portal asset(s)")

    # --- can we start testing TODAY? -----------------------------------------
    e = eps.get(key, 0)
    a = api.get(key, 0)
    if a >= 200:
        s += 26; reasons.append(f"{a:,} API endpoints already mapped")
    elif a >= 50:
        s += 18; reasons.append(f"{a} API endpoints already mapped")
    elif e >= 50:
        s += 9; reasons.append(f"{e} endpoints already mapped")
    elif e == 0:
        s -= 4; reasons.append("no endpoint intel yet (recon needed first)")

    # --- surface room ---------------------------------------------------------
    wild = sum(1 for x in p["assets"] if x.strip().startswith("*."))
    if wild:
        s += min(12, 4 * wild); reasons.append(f"{wild} wildcard(s)")
    if p["n_assets"] >= 20:
        s += 8; reasons.append(f"{p['n_assets']} paid assets")
    elif p["n_assets"] >= 5:
        s += 4

    # --- have we already burned this one? ------------------------------------
    n = notes.get(key, 0)
    if n >= 40:
        s -= 18; reasons.append(f"already worked heavily ({n} notes)")
    elif n >= 15:
        s -= 8; reasons.append(f"already worked ({n} notes)")
    elif n:
        reasons.append(f"lightly touched ({n} notes)")

    # managed programs triage faster and close cleaner
    if p.get("managed"):
        s += 5; reasons.append("managed triage")
    if p.get("safe_harbor") == "full":
        s += 4; reasons.append("full safe harbour")
    rd = p.get("resp_days")
    if isinstance(rd, (int, float)) and rd and rd <= 3:
        s += 6; reasons.append(f"responds in ~{rd:.0f}d")

    return {"score": round(s, 1), "reasons": reasons, "kills": kills,
            "endpoints": e, "api_endpoints": a, "notes": n}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--top", type=int, default=20)
    ap.add_argument("--platform", default=None)
    ap.add_argument("--min-bounty", type=int, default=0)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    progs = collect()
    notes, _ = effort_index()
    eps, api = endpoint_index()

    scored = []
    killed = 0
    for p in progs:
        if a.platform and p["platform"] != a.platform:
            continue
        r = score(p, notes, eps, api)
        p.update(r)
        if r["kills"]:
            killed += 1
            continue
        if (p.get("max_bounty") or 0) < a.min_bounty:
            continue
        scored.append(p)

    scored.sort(key=lambda x: -x["score"])
    top = scored[:a.top]

    date = datetime.now().strftime("%Y-%m-%d")
    out = a.out or os.path.join(OUT, f"program_gate_{date}.md")
    os.makedirs(os.path.dirname(out), exist_ok=True)

    L = [f"# Program eligibility gate — {date}", "",
         f"{len(progs)} programs across 5 platforms. **{killed} killed** at the gate "
         f"(no bounty / closed / tenant estate). {len(scored)} survive; top {len(top)} below.", "",
         "Scored for ONE thing: the odds of an authenticated authorization bug "
         "(IDOR / BOLA / privesc) — the class with zero findings in the DB and the one that pays.", ""]

    for i, p in enumerate(top, 1):
        L += [f"## {i}. {p['name']}  `{p['platform']}`  — score {p['score']}",
              f"{p['url']}", "",
              f"- paid assets: **{p['n_assets']}**"
              + (f" · max bounty **{p['max_bounty']:,}**" if p.get("max_bounty") else "")
              + (f" · endpoints mapped **{p['endpoints']:,}** ({p['api_endpoints']:,} API)"
                 if p['endpoints'] else " · no endpoint intel yet"),
              f"- why: {'; '.join(p['reasons'])}", ""]
        show = [x for x in p["assets"] if APP_ASSET.search(norm_host(x))][:6] or p["assets"][:6]
        if show:
            L += ["- likely app surface:"] + [f"  - `{x}`" for x in show] + [""]

    L += ["---", "", "## Killed at the gate (sample)", ""]
    for p in progs:
        if p.get("kills"):
            L.append(f"- **{p['name']}** (`{p['platform']}`) — {'; '.join(p['kills'])}")
            if len([x for x in L if x.startswith("- **")]) > 25:
                break

    open(out, "w", encoding="utf-8").write("\n".join(L))
    print(f"[gate] {len(progs)} programs, {killed} killed, {len(scored)} survive")
    print(f"[gate] report → {out}\n")
    for i, p in enumerate(top[:12], 1):
        print(f"{i:2d}. {p['score']:6.1f}  {p['name'][:44]:44s} {p['platform']:10s} "
              f"eps={p['endpoints']:>6,} api={p['api_endpoints']:>5,} notes={p['notes']:>3}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
recon_target_select.py — decide WHERE the unauth pipeline hunts. Low saturation only.

Three months of evidence: 320 findings, 3 `real`, and the only Critical came from
`builds.myharmony.com` — a legacy Logitech Harmony host. Meanwhile 96 findings came from
Tesla and produced nothing. The pattern is not subtle.

On a saturated program the commodity unauth surface is already gone. Full-time hunters,
XBOW, and every automated pipeline in the world are watching the same certificate-transparency
feed and running the same checks. A part-time hunter cannot win that race, and does not need
to: nobody is racing for the forgotten subdomain of an acquired company's legacy product.

So this scores for OBSCURITY, deliberately inverting the usual "highest payout first"
instinct. A programme paying $500 that nobody hunts beats one paying $20,000 that everyone
hunts, because expected value is payout times P(you are first), and the second term collapses
on famous targets.

Two levels:
  PROGRAM  — how much attention does this brand attract?
  ASSET    — inside any program, which hosts are the forgotten corners?

Pure data. No target traffic.
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
RAW = os.path.join(BASE, "scope", "raw")
NOTES = os.path.join(BASE, "state", "host_notes.jsonl")
STATE = os.path.join(BASE, "state")
OUT_DIR = os.path.join(BASE, "briefings")

# Brands that draw a permanent crowd. Not a judgement on the programs — a statement about
# how many people are already looking. Being on this list is disqualifying for a part-timer
# chasing commodity unauth surface.
CROWDED = {
    "tesla", "coinbase", "amazon", "aws", "google", "meta", "facebook", "apple", "microsoft",
    "netflix", "paypal", "uber", "airbnb", "shopify", "github", "gitlab", "atlassian",
    "dropbox", "slack", "stripe", "twitter", "x corp", "linkedin", "snap", "tiktok",
    "bytedance", "openai", "anthropic", "nvidia", "intel", "oracle", "salesforce", "adobe",
    "cloudflare", "digitalocean", "spotify", "reddit", "discord", "twitch", "epic games",
    "sony", "nintendo", "valve", "binance", "kraken", "robinhood", "block", "square",
    "goldman", "jpmorgan", "visa", "mastercard", "t-mobile", "verizon", "at&t", "comcast",
    "yahoo", "ebay", "walmart", "target", "starbucks", "mcdonald", "nike", "disney",
    "hackerone", "bugcrowd", "intigriti", "yeswehack", "mozilla", "brave", "opera",
    "samsung", "xiaomi", "huawei", "lg ", "dell", "hp ", "ibm", "cisco", "vmware",
}

# Asset-level markers of a forgotten corner. These are where the Logitech Critical lived.
FORGOTTEN = [
    (28, re.compile(r"\b(legacy|deprecated|old|retired|sunset|archive|eol)\b", re.I)),
    (24, re.compile(r"\b(staging|preprod|pre-prod|uat|qa|test|dev|sandbox|demo|beta|alpha)\b", re.I)),
    (22, re.compile(r"\b(builds?|ci|jenkins|artifact|nexus|registry|repo)\b", re.I)),
    (20, re.compile(r"\b(internal|admin|ops|infra|tools?|dashboard|console|portal)\b", re.I)),
    (16, re.compile(r"\b(api|gateway|bff|service|svc|backend)\b", re.I)),
    (14, re.compile(r"\b(partner|vendor|supplier|reseller|affiliate|b2b)\b", re.I)),
    (12, re.compile(r"\b(support|help|docs?|status|monitor|metrics)\b", re.I)),
]


def load(p):
    try:
        return json.load(open(p, encoding="utf-8"))
    except Exception:
        return []


def crowded(name: str) -> str:
    n = (name or "").lower()
    for b in CROWDED:
        if b in n:
            return b
    return ""


def collect() -> list[dict]:
    progs = []

    for p in load(os.path.join(RAW, "hackerone.json")):
        tg = p.get("targets") or {}
        paid = [a for a in (tg.get("in_scope") or []) if a.get("eligible_for_bounty")]
        progs.append(dict(
            platform="hackerone", name=p.get("name"), url=p.get("url"),
            pays=bool(p.get("offers_bounties")) and bool(paid), max_bounty=0,
            open=(p.get("submission_state") == "open"),
            assets=[str(a.get("asset_identifier") or "") for a in paid],
            n_assets=len(paid),
            resp=p.get("average_time_to_first_program_response"),
            managed=bool(p.get("managed_program"))))

    for p in load(os.path.join(RAW, "bugcrowd.json")):
        ins = (p.get("targets") or {}).get("in_scope") or []
        progs.append(dict(
            platform="bugcrowd", name=p.get("name"), url=p.get("url"),
            pays=bool(p.get("max_payout")), max_bounty=p.get("max_payout") or 0, open=True,
            assets=[str(a.get("target") or a.get("uri") or "") for a in ins],
            n_assets=len(ins), resp=None, managed=bool(p.get("managed_by_bugcrowd"))))

    for p in load(os.path.join(RAW, "intigriti.json")):
        ins = (p.get("targets") or {}).get("in_scope") or []
        mb = (p.get("max_bounty") or {}).get("value") or 0
        progs.append(dict(
            platform="intigriti", name=p.get("name"), url=p.get("url"),
            pays=bool(mb), max_bounty=mb, open=(p.get("status") == "open"),
            assets=[str(a.get("endpoint") or "") for a in ins],
            n_assets=len(ins), resp=None, managed=False))

    for p in load(os.path.join(RAW, "yeswehack.json")):
        if p.get("disabled"):
            continue
        ins = (p.get("targets") or {}).get("in_scope") or []
        progs.append(dict(
            platform="yeswehack", name=p.get("name"),
            url=f"https://yeswehack.com/programs/{p.get('id')}",
            pays=bool(p.get("max_bounty")), max_bounty=p.get("max_bounty") or 0, open=True,
            assets=[str(a.get("target") or "") for a in ins],
            n_assets=len(ins), resp=None, managed=bool(p.get("managed"))))

    return progs


def our_effort() -> collections.Counter:
    c = collections.Counter()
    if os.path.exists(NOTES):
        for line in open(NOTES, encoding="utf-8", errors="replace"):
            try:
                o = json.loads(line)
            except Exception:
                continue
            p = (o.get("program") or "").strip().lower()
            if p:
                c[p] += 1
    return c


def score(p: dict, effort: collections.Counter) -> dict:
    reasons, kills = [], []

    if not p["pays"]:
        kills.append("no bounty")
    if not p.get("open", True):
        kills.append("closed to submissions")
    if p["n_assets"] == 0:
        kills.append("no bounty-eligible assets")

    fame = crowded(p["name"] or "")
    if fame:
        kills.append(f"crowded brand ({fame}) — commodity unauth surface is already gone")

    s = 0.0

    # --- obscurity is the point ---------------------------------------------
    mb = p.get("max_bounty") or 0
    if 0 < mb <= 1500:
        s += 26; reasons.append(f"modest max bounty ({mb:,}) — attracts less of a crowd")
    elif 1500 < mb <= 5000:
        s += 18; reasons.append(f"mid max bounty ({mb:,})")
    elif mb > 15000:
        s -= 14; reasons.append(f"headline bounty ({mb:,}) — draws full-timers")
    elif mb:
        s += 6; reasons.append(f"max bounty {mb:,}")
    elif p["pays"]:
        s += 12; reasons.append("pays, amount unpublished (less advertised)")

    # A slow-responding, unmanaged program is unattractive to full-timers — which is
    # exactly why its surface is still there.
    r = p.get("resp")
    if isinstance(r, (int, float)) and r:
        if r >= 14:
            s += 14; reasons.append(f"slow triage (~{r:.0f}d) — crowd avoids it")
        elif r >= 7:
            s += 8; reasons.append(f"unhurried triage (~{r:.0f}d)")
        else:
            s -= 4
    if not p.get("managed"):
        s += 8; reasons.append("self-managed (no triage team farming it)")

    # --- forgotten corners inside the scope ----------------------------------
    blob = " ".join(p["assets"])
    hits = []
    for w, rx in FORGOTTEN:
        m = rx.search(blob)
        if m:
            s += w * 0.6
            hits.append(m.group(0).lower())
    if hits:
        reasons.append(f"forgotten-corner assets: {', '.join(sorted(set(hits))[:6])}")

    wild = sum(1 for x in p["assets"] if x.strip().startswith("*."))
    if wild:
        s += min(14, 5 * wild); reasons.append(f"{wild} wildcard(s) — room to find the odd host")

    # A very large scope is usually a famous program; a small odd scope is ours to take.
    if p["n_assets"] > 60:
        s -= 8; reasons.append(f"very large scope ({p['n_assets']}) — heavily walked")
    elif 3 <= p["n_assets"] <= 25:
        s += 10; reasons.append(f"tractable scope ({p['n_assets']} assets)")

    # --- have WE already been here? -----------------------------------------
    n = effort.get((p["name"] or "").strip().lower(), 0)
    if n >= 40:
        s -= 16; reasons.append(f"we already worked it hard ({n} notes)")
    elif n:
        reasons.append(f"lightly touched ({n} notes)")
    else:
        s += 6; reasons.append("untouched by us")

    return {"score": round(s, 1), "reasons": reasons, "kills": kills, "notes": n}


def main() -> int:
    ap = argparse.ArgumentParser(description="Pick low-saturation programs for the unauth pipeline.")
    ap.add_argument("--top", type=int, default=40)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    progs = collect()
    effort = our_effort()
    kept, killed = [], collections.Counter()
    for p in progs:
        r = score(p, effort)
        p.update(r)
        if r["kills"]:
            killed[r["kills"][0].split(" —")[0]] += 1
            continue
        kept.append(p)
    kept.sort(key=lambda x: -x["score"])
    top = kept[:a.top]

    date = datetime.now().strftime("%Y-%m-%d")
    out = a.out or os.path.join(OUT_DIR, f"targets_unsaturated_{date}.md")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    L = [f"# Low-saturation target set — {date}", "",
         f"{len(progs)} programs. **{sum(killed.values())} killed**, {len(kept)} kept. "
         f"Scored for OBSCURITY, not payout — expected value is payout x P(you are first), "
         f"and the second term collapses on famous targets.", "",
         "## Killed", ""]
    for k, n in killed.most_common():
        L.append(f"- {n} — {k}")
    L += ["", "## The set the pipeline hunts", ""]
    for i, p in enumerate(top, 1):
        L += [f"### {i}. {p['name']}  `{p['platform']}`  — {p['score']}",
              f"{p['url']}",
              f"- {p['n_assets']} paid asset(s)"
              + (f" · max {p['max_bounty']:,}" if p.get("max_bounty") else ""),
              f"- {'; '.join(p['reasons'])}", ""]

    open(out, "w", encoding="utf-8").write("\n".join(L))

    # The machine-readable set every lane reads.
    sel = os.path.join(STATE, "target_programs.json")
    json.dump({"generated_at": datetime.now().isoformat(timespec="seconds"),
               "programs": [{"name": p["name"], "platform": p["platform"],
                             "score": p["score"], "assets": p["assets"][:200]}
                            for p in top]}, open(sel, "w"), indent=2)

    print(f"[targets] {len(progs)} programs, {sum(killed.values())} killed, {len(kept)} kept")
    print(f"[targets] report  -> {out}")
    print(f"[targets] machine -> {sel}\n")
    for i, p in enumerate(top[:20], 1):
        print(f"{i:2d}. {p['score']:6.1f}  {(p['name'] or '')[:44]:44s} {p['platform']:10s} "
              f"assets={p['n_assets']:<4d} notes={p['notes']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

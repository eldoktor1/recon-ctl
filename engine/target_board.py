#!/usr/bin/env python3
"""
target_board.py — the Under-Hunted Target Board scorer.

Re-aims the pipeline at the RIGHT question: not "how completely can I scan the
targets I already have?" (coverage of mostly-saturated giants = dup-bait) but
"which under-hunted program deserves my depth this week?" (selection).

Reads the authoritative bounty-targets scope dumps (scope/raw/*.json — the same
data each platform's own scraper publishes), scores every PROGRAM by an
Under-Hunted EV metric that is deliberately DOMINATED by anti-dup signals
(freshness + low saturation), not payout, and emits a ranked board:
  - <RECON>/briefings/targets_<date>.md   (human menu of options)
  - <RECON>/briefings/targets_latest.md    (symlink)
  - <RECON>/briefings/targets_latest.json  (machine: full ranked list + onboard roots)

Freshness ledger: <RECON>/state/targets_seen.json  ({platform:key -> first_seen_epoch}).
Pure data (no target traffic) — runs as d0k, gated by killswitch v2_targets in the lane.
"""
import os, sys, json, time, re, urllib.request
from datetime import date, datetime, timedelta, timezone

RECON = os.environ.get("RECON_DIR", os.path.expanduser("~/recon"))
RAW   = os.path.join(RECON, "scope", "raw")
BRIEF = os.path.join(RECON, "briefings")
STATE = os.path.join(RECON, "state")
SEEN_F = os.path.join(STATE, "targets_seen.json")
REPO = "arkadiyt/bounty-targets-data"
NOW = int(time.time())

# ---- scoring weights (freshness + low-saturation dominate; payout capped low = anti-crowd) ----
W_FRESH, W_PLATFORM, W_AUTHED, W_PAYS, W_ACCESS, W_SCOPE = 40, 20, 16, 9, 7, 8
PLATFORM_UNCROWDED = {  # smaller researcher community => fewer dups (research-backed)
    "yeswehack": 1.00, "intigriti": 0.92, "federacy": 0.85,
    "bugcrowd": 0.55, "hackerone": 0.35,
}
FRESH_CAP_DAYS = 45      # a program older than this gets 0 freshness
BOOT_OLD_DAYS  = 75      # bootstrap: handles already present ~28d ago are treated this old

def _get(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": "recon-targets"})
    return urllib.request.urlopen(req, timeout=timeout).read()

# Shared third-party app-marketplace / hosting hosts. A program whose scope points here
# (e.g. an Atlassian-Marketplace app vendor's Bugcrowd scope = marketplace.atlassian.com/apps/…)
# has NO ownable enumeration surface — subdomain recon on the shared host finds only the
# PLATFORM's assets, never the vendor's. These collapse many distinct programs onto one root
# and poison the board's top slots (RV Softwares / 55 Degrees / AppLiger all → marketplace.atlassian.com).
# The board exists to point ENUMERATION depth; a host we can't enumerate for THIS program is not a root.
PLATFORM_HOSTS = {
    "marketplace.atlassian.com", "apps.shopify.com", "chromewebstore.google.com",
    "chrome.google.com", "addons.mozilla.org", "apps.apple.com", "play.google.com",
    "marketplace.visualstudio.com", "workspace.google.com", "gsuite.google.com",
    "appsource.microsoft.com", "store.salesforce.com", "appexchange.salesforce.com",
}

def _host(s):
    """Extract a bare hostname from a scope string (URL / host / wildcard).
    Returns None for shared-platform hosts (see PLATFORM_HOSTS) so they never become roots."""
    if not s or not isinstance(s, str): return None
    s = s.strip()
    s = re.sub(r"^[a-zA-Z]+://", "", s)          # strip scheme
    s = s.split("/")[0].split("?")[0]            # strip path/query
    s = s.split("@")[-1].split(":")[0]           # strip creds/port
    s = s.lstrip("*.").strip(". ")               # *.x.com -> x.com
    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", s, re.I): return None
    s = s.lower()
    if s in PLATFORM_HOSTS: return None
    return s

# ---- per-platform normalizers -> common program record ----
def norm_hackerone(p):
    sc = (p.get("targets") or {}).get("in_scope") or []
    web = [a for a in sc if a.get("asset_type") in ("URL", "WILDCARD", "API") and a.get("eligible_for_bounty")]
    roots = sorted({h for a in web if (h := _host(a.get("asset_identifier")))})
    # H1 dump has no payout; weak saturation proxy = has it resolved reports yet
    resolved = p.get("average_time_to_report_resolved")
    return dict(platform="hackerone", key=p["handle"], name=p["name"], url=p.get("url"),
                pays=bool(p.get("offers_bounties")), payout=None,
                authed=bool(web), n_authed=len(web), roots=roots,
                access="public", scope_types=_types(sc, "asset_type"),
                managed=bool(p.get("managed_program")), has_activity=(resolved is not None))

def norm_bugcrowd(p):
    sc = (p.get("targets") or {}).get("in_scope") or []
    web = [a for a in sc if a.get("type") in ("website", "api")]
    roots = sorted({h for a in web if (h := _host(a.get("target") or a.get("uri")))})
    return dict(platform="bugcrowd", key=p.get("url") or p.get("name"), name=p.get("name", "").strip(),
                url=p.get("url"), pays=bool((p.get("max_payout") or 0) > 0), payout=p.get("max_payout") or 0,
                authed=bool(web), n_authed=len(web), roots=roots,
                access="public", scope_types=_types(sc, "type"),
                managed=bool(p.get("managed_by_bugcrowd")), has_activity=True)

def norm_yeswehack(p):
    sc = (p.get("targets") or {}).get("in_scope") or []
    web = [a for a in sc if a.get("type") in ("web-application", "api", "web", "application")]
    roots = sorted({h for a in web if (h := _host(a.get("target")))})
    return dict(platform="yeswehack", key=p.get("id"), name=p.get("name"), url=f"https://yeswehack.com/programs/{p.get('id')}",
                pays=bool((p.get("max_bounty") or 0) > 0), payout=p.get("max_bounty") or 0,
                authed=bool(web), n_authed=len(web), roots=roots,
                access="public" if p.get("public") else "private", scope_types=_types(sc, "type"),
                managed=bool(p.get("managed")), has_activity=True)

def norm_intigriti(p):
    # bounty-targets intigriti schema is best-effort; detect web/api fields generically
    sc = (p.get("targets") or {}).get("in_scope") or []
    def itype(a): return (a.get("type") or a.get("asset_type") or "").lower()
    web = [a for a in sc if any(k in itype(a) for k in ("web", "api", "url", "wildcard"))]
    roots = sorted({h for a in web if (h := _host(a.get("endpoint") or a.get("target") or a.get("uri") or a.get("asset_identifier")))})
    mb = p.get("max_bounty") or p.get("maxBounty") or 0
    if isinstance(mb, dict): mb = mb.get("value") or 0
    return dict(platform="intigriti", key=p.get("handle") or p.get("id") or p.get("name"), name=p.get("name"),
                url=p.get("url"), pays=bool(mb > 0), payout=mb,
                authed=bool(web), n_authed=len(web), roots=roots,
                access="public", scope_types=_types(sc, "type"), managed=False, has_activity=True)

def _types(sc, k):
    d = {}
    for a in sc:
        t = a.get(k); d[t] = d.get(t, 0) + 1
    return dict(sorted(d.items(), key=lambda x: -x[1]))

# (platform, dump filename, normalizer, github-key fn, gh_freshness)
# gh_freshness=False where our local scope/raw schema differs from the github dump
# (e.g. intigriti) so the git-diff can't key-match — those bootstrap to a neutral age
# and accrue accurate freshness locally as new programs appear.
PLATFORMS = [
    ("hackerone", "hackerone_data.json", norm_hackerone, lambda p: p["handle"], True),
    ("bugcrowd",  "bugcrowd_data.json",  norm_bugcrowd,  lambda p: p.get("url") or p.get("name"), True),
    ("yeswehack", "yeswehack_data.json", norm_yeswehack, lambda p: p.get("id"), True),
    ("intigriti", "intigriti_data.json", norm_intigriti, lambda p: p.get("handle") or p.get("id") or p.get("name"), False),
]

def load_raw(fname):
    for cand in (os.path.join(RAW, fname), os.path.join(RAW, fname.replace("_data", ""))):
        if os.path.exists(cand):
            try: return json.load(open(cand))
            except Exception: pass
    return None

def bootstrap_old_keys(fname, keyfn, days=28):
    """Keys present ~`days` ago (via the repo's git history) = established, not fresh."""
    try:
        since = (date.today() - timedelta(days=days)).isoformat()
        api = f"https://api.github.com/repos/{REPO}/commits?path=data/{fname}&until={since}T00:00:00Z&per_page=1"
        sha = json.loads(_get(api))[0]["sha"]
        old = json.loads(_get(f"https://raw.githubusercontent.com/{REPO}/{sha}/data/{fname}"))
        return set(str(keyfn(p)) for p in old)
    except Exception as e:
        sys.stderr.write(f"[target_board] freshness bootstrap failed for {fname}: {e}\n")
        return None

def main():
    os.makedirs(BRIEF, exist_ok=True); os.makedirs(STATE, exist_ok=True)
    seen = {}
    if os.path.exists(SEEN_F):
        try: seen = json.load(open(SEEN_F))
        except Exception: seen = {}
    bootstrapping = not seen

    progs = []
    for plat, fname, norm, keyfn, gh_fresh in PLATFORMS:
        data = load_raw(fname)
        if not data:
            sys.stderr.write(f"[target_board] no dump for {plat}\n"); continue
        old_keys = bootstrap_old_keys(fname, keyfn) if (bootstrapping and gh_fresh) else None
        for p in data:
            try: rec = norm(p)
            except Exception: continue
            if not rec.get("key"): continue
            sk = f"{plat}:{rec['key']}"
            if sk not in seen:
                if bootstrapping:
                    # established 28d ago -> old; otherwise genuinely new
                    if old_keys is not None and str(rec["key"]) in old_keys:
                        seen[sk] = NOW - BOOT_OLD_DAYS * 86400
                    elif old_keys is not None:
                        seen[sk] = NOW                      # added in the last 28d = fresh
                    else:
                        seen[sk] = NOW - 30 * 86400         # bootstrap fetch failed -> neutral
                else:
                    seen[sk] = NOW                          # newly appeared since last run = fresh
            rec["first_seen"] = seen[sk]
            rec["fresh_days"] = round((NOW - seen[sk]) / 86400, 1)
            progs.append(rec)
    json.dump(seen, open(SEEN_F, "w"))

    for r in progs:
        r["score"], r["why"] = score(r)
    progs.sort(key=lambda r: -r["score"])

    write_outputs(progs)
    print(f"[target_board] scored {len(progs)} programs; board -> {BRIEF}/targets_{date.today().isoformat()}.md")

def score(r):
    fresh = max(0.0, (FRESH_CAP_DAYS - r["fresh_days"]) / FRESH_CAP_DAYS)         # newer = 1
    plat = PLATFORM_UNCROWDED.get(r["platform"], 0.4)
    authed = 1.0 if r["authed"] else 0.0
    payout = r.get("payout") or (2500 if r["pays"] else 0)
    pays = min(payout / 3000.0, 1.0) if r["pays"] else 0.0                        # capped low = anti-crowd
    access = {"public": 1.0, "registered": 1.0, "private": 0.85, "application": 0.6}.get(r["access"], 0.7)
    scope = min(r["n_authed"] / 10.0, 1.0)
    s = (W_FRESH*fresh + W_PLATFORM*plat + W_AUTHED*authed + W_PAYS*pays + W_ACCESS*access + W_SCOPE*scope)
    # giant penalty: established (not fresh) + high payout = crowded mega-program
    if payout >= 10000 and r["fresh_days"] > 40:
        s -= 18
    if not r["pays"]:
        s -= 25
    why = []
    if fresh > 0.6: why.append(f"FRESH({r['fresh_days']}d)")
    why.append(f"{r['platform']}")
    if r["authed"]: why.append(f"authed×{r['n_authed']}")
    if payout: why.append(f"~{payout}")
    return round(s, 1), " ".join(why)

def write_outputs(progs):
    today = date.today().isoformat()
    # require a REAL enumeration root: a paying+authed program whose only scope was a shared
    # platform host (roots now empty) can't be enumerated for itself — keep it off the board so
    # it never occupies a top slot or gets onboarded to walk someone else's marketplace.
    payable_authed = [r for r in progs if r["pays"] and r["authed"] and r.get("roots")]
    md = [f"# 🎯 UNDER-HUNTED TARGET BOARD — {today}",
          "",
          "Ranked by **Under-Hunted EV** (freshness + low-saturation dominate; payout capped = anti-dup).",
          "The MENU of options to point depth at. Auto-onboard seeds the top N; `recon-targets onboard <key>` adds any.",
          "",
          f"_{len(progs)} programs scored · {len(payable_authed)} paying + authed-app · top 15 below_",
          "",
          "| # | Score | Program | Platform | Pay | Authed scope | Fresh | Why |",
          "|---|------|---------|----------|-----|--------------|-------|-----|"]
    for i, r in enumerate(payable_authed[:15], 1):
        sc = ", ".join(f"{k}×{v}" for k, v in list(r["scope_types"].items())[:3])
        po = f"${r['payout']}" if r.get("payout") else ("pays" if r["pays"] else "—")
        md.append(f"| {i} | {r['score']} | **{r['name']}** `{r['key']}` | {r['platform']} | {po} "
                  f"| {r['n_authed']} ({sc}) | {r['fresh_days']}d | {r['why']} |")
    md.append("")
    md.append("Onboarding seeds the in-scope roots into the validator queue; per-asset pays/scope still gated at hunt time.")
    out_md = os.path.join(BRIEF, f"targets_{today}.md")
    open(out_md, "w").write("\n".join(md))
    link = os.path.join(BRIEF, "targets_latest.md")
    try:
        if os.path.islink(link) or os.path.exists(link): os.remove(link)
        os.symlink(out_md, link)
    except Exception: pass
    # machine-readable full ranking (for onboard + briefing)
    slim = [dict(rank=i+1, **{k: r[k] for k in ("platform","key","name","url","score","why","pays","payout",
                                                "authed","n_authed","roots","access","fresh_days")})
            for i, r in enumerate(payable_authed)]
    json.dump({"generated": today, "count": len(slim), "programs": slim},
              open(os.path.join(BRIEF, "targets_latest.json"), "w"), indent=0)

if __name__ == "__main__":
    main()

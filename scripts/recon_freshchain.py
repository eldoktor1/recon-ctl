#!/usr/bin/env python3
"""
recon_freshchain.py — be FIRST to new surface, and chain it to credentials immediately.

The certificate-transparency feed (`recon_true_fresh.sh`) already produces in-scope hosts
minutes after their certificate is issued — 875 of them, with entries timestamped the same
hour. Nothing ever ran a credential chain against them. They went into a briefing for an
evening that, for an operator with a day job, frequently never came.

That gap is the single most-documented unauth payday in bug bounty: a hunter finds
`staging-api.target.com` in a CT log, pulls its `.env`, and cashes a $5,000 cheque. CT-sourced
subdomains are repeatedly reported as carrying hardcoded credentials. The surface is
valuable precisely because it is NEW — nobody else has scanned it yet, so a finding there is
not a duplicate.

This lane closes the loop:

    new CT host -> scope+pays gate -> run EVERY credential chain within minutes

It orchestrates the existing chains rather than reimplementing them, so the impact gate,
redaction and safety rules stay in exactly one place:

    recon_leak_chain.py      .env / .git / tfstate / .npmrc  -> credentials
    recon_actuator_chain.py  /actuator/env + heapdump        -> credentials
    recon_port_proto.py      open port -> speak protocol     -> unauth service
    recon_authdiff.py        known-403 route                 -> auth bypass

Each mints ONLY on recovered impact. A freshly-issued host that is properly configured is
recorded as a negative and never surfaces.

SAFETY: every chain keeps its own scope+pays gate, vpn_down fail-closed, GET-only rules and
anti-burn. This adds a bounded batch size and a cursor so a backlog cannot become a flood.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone, timedelta

BASE_DIR = os.environ.get("BASE_DIR", os.path.expanduser("~/recon"))
STATE_DIR = os.environ.get("STATE_DIR", os.path.join(BASE_DIR, "state"))
SCRIPTS = os.path.dirname(os.path.abspath(__file__))
FEED = os.path.join(STATE_DIR, "true_fresh.jsonl")
CURSOR = os.path.join(STATE_DIR, "freshchain_cursor.json")
AUDIT = os.path.join(STATE_DIR, "freshchain_audit.jsonl")
OUT_DIR = os.path.join(BASE_DIR, "briefings")

# Bounded so a backlog (or a burst of CT issuance) cannot turn into a flood of traffic.
BATCH = int(os.environ.get("FRESH_BATCH", "12"))
MAX_AGE_H = int(os.environ.get("FRESH_MAX_AGE_H", "72"))
PER_CHAIN_TIMEOUT = int(os.environ.get("FRESH_CHAIN_TIMEOUT", "420"))

CHAINS = [
    ("leak",     [sys.executable, os.path.join(SCRIPTS, "recon_leak_chain.py")]),
    ("actuator", [sys.executable, os.path.join(SCRIPTS, "recon_actuator_chain.py")]),
    ("ports",    [sys.executable, os.path.join(SCRIPTS, "recon_port_proto.py")]),
    ("authdiff", [sys.executable, os.path.join(SCRIPTS, "recon_authdiff.py"), "--limit", "40"]),
]


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(m: str) -> None:
    print(f"[fresh] {m}", file=sys.stderr, flush=True)


def audit(rec: dict) -> None:
    os.makedirs(STATE_DIR, exist_ok=True)
    rec.setdefault("at", utc())
    with open(AUDIT, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")


def load_cursor() -> set:
    try:
        return set(json.load(open(CURSOR)).get("done", []))
    except Exception:
        return set()


def save_cursor(done: set) -> None:
    # Bound the cursor so it cannot grow without limit.
    keep = sorted(done)[-20000:]
    json.dump({"done": keep, "updated_at": utc()}, open(CURSOR, "w"))


def new_hosts(done: set, max_age_h: int) -> list[dict]:
    if not os.path.exists(FEED):
        log(f"no CT feed at {FEED}")
        return []
    cutoff = datetime.now(timezone.utc) - timedelta(hours=max_age_h)
    out = []
    for line in open(FEED, encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
        except Exception:
            continue
        h = (o.get("host") or "").strip().lower()
        if not h or h in done:
            continue
        seen = o.get("external_first_seen") or ""
        try:
            ts = datetime.strptime(seen, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except Exception:
            ts = None
        if ts and ts < cutoff:
            continue
        out.append({"host": h, "first_seen": seen, "_ts": ts})
    # Freshest FIRST — the whole point is being early.
    out.sort(key=lambda x: x["_ts"] or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    return out


def scope_ok(host: str) -> tuple[bool, str]:
    sc = os.path.join(SCRIPTS, "recon_scope_check.sh")
    if not os.path.exists(sc):
        return False, "scope resolver missing"
    try:
        d = json.loads(subprocess.run(["bash", sc, host], capture_output=True,
                                      text=True, timeout=45).stdout)
    except Exception as e:
        return False, f"scope check failed: {e}"
    if not d.get("in_scope"):
        return False, "not in scope"
    if not d.get("pays"):
        return False, "does not pay"
    if d.get("out_of_scope"):
        return False, "out of scope"
    return True, d.get("program") or ""


def run_chain(name: str, argv: list[str], host: str) -> dict:
    t0 = time.time()
    try:
        r = subprocess.run(argv + [host], capture_output=True, text=True,
                           timeout=PER_CHAIN_TIMEOUT)
        out = (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return {"chain": name, "status": "timeout", "secs": PER_CHAIN_TIMEOUT}
    except Exception as e:
        return {"chain": name, "status": f"error: {str(e)[:100]}"}
    minted = "minted finding #" in out
    fid = ""
    if minted:
        for tok in out.split("minted finding #")[1:]:
            fid = tok.split()[0].strip(" —-") ; break
    return {"chain": name, "status": "minted" if minted else "clean",
            "finding_id": fid, "secs": round(time.time() - t0, 1),
            "tail": out.strip().splitlines()[-1][:160] if out.strip() else ""}


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Run every credential chain against freshly-CT-issued in-scope hosts.")
    ap.add_argument("--batch", type=int, default=BATCH)
    ap.add_argument("--max-age-h", type=int, default=MAX_AGE_H)
    ap.add_argument("--host", action="append", default=[], help="force specific host(s)")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    if os.path.exists(os.path.join(STATE_DIR, "vpn_down")):
        log("vpn_down — refusing (fail-closed)")
        return 2

    done = load_cursor()
    if a.host:
        queue = [{"host": h, "first_seen": "(forced)"} for h in a.host]
    else:
        queue = new_hosts(done, a.max_age_h)
        log(f"{len(queue)} unprocessed host(s) in the last {a.max_age_h}h; taking {a.batch}")
        queue = queue[:a.batch]
    if not queue:
        log("nothing fresh to chase")
        return 0

    results = []
    for item in queue:
        host = item["host"]
        ok, program = scope_ok(host)
        done.add(host)
        if not ok:
            log(f"skip {host}: {program}")
            continue
        log(f"=== {host}  ({program})  first seen {item['first_seen']} ===")
        per = []
        for name, argv in CHAINS:
            cmd = list(argv) + (["--dry-run"] if a.dry_run else [])
            r = run_chain(name, cmd, host)
            per.append(r)
            mark = "MINTED" if r["status"] == "minted" else r["status"]
            log(f"    {name:9s} {mark:8s} {r.get('secs','?')}s  {r.get('tail','')[:90]}")
        hit = [p for p in per if p["status"] == "minted"]
        results.append({"host": host, "program": program,
                        "first_seen": item["first_seen"], "chains": per, "minted": len(hit)})
        audit({"host": host, "program": program, "first_seen": item["first_seen"],
               "minted": len(hit), "chains": {p["chain"]: p["status"] for p in per}})

    save_cursor(done)

    minted = [r for r in results if r["minted"]]
    os.makedirs(OUT_DIR, exist_ok=True)
    out = os.path.join(OUT_DIR, f"freshchain_{datetime.now().strftime('%Y-%m-%d')}.md")
    L = [f"# Fresh-surface chain — {utc()}", "",
         f"{len(results)} freshly-issued in-scope host(s) chained. "
         f"**{len(minted)} produced recovered impact.**", ""]
    for r in results:
        flag = "💰 " if r["minted"] else ""
        L.append(f"- {flag}`{r['host']}` ({r['program']}) — first seen {r['first_seen']} — "
                 + ", ".join(f"{p['chain']}:{p['status']}" for p in r["chains"]))
    with open(out, "a" if os.path.exists(out) else "w", encoding="utf-8") as fh:
        fh.write("\n".join(L) + "\n")
    log(f"report → {out}")
    log(f"DONE — {len(results)} hosts, {len(minted)} with recovered impact")
    print(json.dumps({"tested": len(results), "minted": len(minted),
                      "hosts": [r["host"] for r in results]}, default=str)[:1200])
    return 0


if __name__ == "__main__":
    sys.exit(main())

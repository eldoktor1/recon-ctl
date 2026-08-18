#!/usr/bin/env python3
"""
recon_enum_targets.py — enumerate the LOW-SATURATION programs. The ones nobody hunted.

The general discovery lane pulls roots from every paying program in scope, which sounds
reasonable and produced a catastrophic result: 849,539 of 1.39 million enumerated hosts were
tumblr blogs, while 12 of the 30 best low-saturation programs had ZERO hosts. The impact
lanes were never going to find anything, because the surface they were pointed at was
somebody's personal blog.

This enumerates the target set from recon_target_select.py and nothing else.

  target_programs.json -> root domains -> subfinder + assetfinder -> resolve -> queue

Priority prefix `01_` so the validator picks these up ahead of the general backlog (only the
CT-fresh feed at `00_` outranks them — being first to brand-new surface still wins).

Enumeration talks to passive sources and public resolvers, not to the bug-bounty host, so it
is cheap and carries no burn risk. The hosts it discovers are probed later by the validator
under the usual Mullvad + rate-limit rules.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone

BASE_DIR = os.environ.get("BASE_DIR", os.path.expanduser("~/recon"))
STATE_DIR = os.environ.get("STATE_DIR", os.path.join(BASE_DIR, "state"))
INBOX = os.path.join(BASE_DIR, "queue", "inbox")
TARGETS = os.path.join(STATE_DIR, "target_programs.json")
SEEN = os.path.join(STATE_DIR, "enum_targets_seen.txt")
CURSOR = os.path.join(STATE_DIR, "enum_targets_cursor.json")
AUDIT = os.path.join(STATE_DIR, "enum_targets_audit.jsonl")

# The TLD must be ALPHABETIC and at least two characters. Without that, scope entries like
# "8.0" (a version string in an asset list) parse as a root domain and get handed to
# subfinder, which is how junk enters the queue at high priority.
ROOT_RX = re.compile(
    r"^(?:\*\.)?([a-z0-9][a-z0-9\-]*(?:\.[a-z0-9][a-z0-9\-]*)*\.[a-z]{2,24})$", re.I)
# Public suffixes we must never enumerate as if they were a target's root.
NEVER = re.compile(
    r"^(amazonaws\.com|azurewebsites\.net|herokuapp\.com|github\.io|cloudfront\.net|"
    r"googleapis\.com|windows\.net|firebaseio\.com|myshopify\.com|zendesk\.com|"
    r"statuspage\.io|netlify\.app|vercel\.app|pages\.dev|workers\.dev)$", re.I)


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(m: str) -> None:
    print(f"[enum] {m}", file=sys.stderr, flush=True)


def audit(rec: dict) -> None:
    os.makedirs(STATE_DIR, exist_ok=True)
    rec.setdefault("at", utc())
    with open(AUDIT, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")


def roots_from_targets() -> dict[str, str]:
    """root domain -> program name, from the low-saturation set only."""
    if not os.path.exists(TARGETS):
        log(f"missing {TARGETS} — run `recon-ctl targets` first")
        return {}
    data = json.load(open(TARGETS))
    roots: dict[str, str] = {}
    for p in data.get("programs", []):
        prog = p.get("name") or ""
        for a in p.get("assets") or []:
            a = str(a).strip().lower()
            a = re.sub(r"^\w+://", "", a).split("/")[0].split(":")[0]
            a = a.lstrip("*.")
            m = ROOT_RX.match(a)
            if not m:
                continue
            host = m.group(1)
            parts = host.split(".")
            # keep the registrable root so subfinder enumerates the whole estate
            two = {"co.uk", "com.au", "co.nz", "co.jp", "com.br", "co.in", "com.cn",
                   "co.za", "com.mx", "co.kr", "com.tr", "com.sg", "org.uk", "ac.uk"}
            root = ".".join(parts[-3:]) if len(parts) >= 3 and ".".join(parts[-2:]) in two \
                else ".".join(parts[-2:])
            if NEVER.match(root):
                continue
            roots.setdefault(root, prog)
    return roots


def load_seen() -> set[str]:
    if not os.path.exists(SEEN):
        return set()
    return {l.strip() for l in open(SEEN, encoding="utf-8", errors="replace") if l.strip()}


def enumerate_root(root: str, timeout: int) -> set[str]:
    hosts: set[str] = set()
    if shutil.which("subfinder"):
        try:
            r = subprocess.run(["subfinder", "-d", root, "-silent", "-all",
                                "-timeout", "20", "-max-time", str(max(1, timeout // 60))],
                               capture_output=True, text=True, timeout=timeout)
            hosts |= {l.strip().lower() for l in (r.stdout or "").splitlines() if l.strip()}
        except subprocess.TimeoutExpired:
            log(f"    subfinder timed out on {root}")
        except Exception as e:
            log(f"    subfinder error on {root}: {str(e)[:80]}")
    if shutil.which("assetfinder"):
        try:
            r = subprocess.run(["assetfinder", "--subs-only", root],
                               capture_output=True, text=True, timeout=min(timeout, 180))
            hosts |= {l.strip().lower() for l in (r.stdout or "").splitlines()
                      if l.strip().endswith(root)}
        except Exception:
            pass
    return {h for h in hosts if h and "*" not in h and h.endswith(root)}


def resolve(hosts: list[str]) -> list[str]:
    """Public resolvers, not the target. Keeps dead names out of the validator queue."""
    if not hosts or not shutil.which("dnsx"):
        return hosts
    try:
        r = subprocess.run(["dnsx", "-silent", "-a", "-resp-only", "-t", "60"],
                           input="\n".join(hosts), capture_output=True, text=True, timeout=600)
        alive = {l.strip() for l in (r.stdout or "").splitlines() if l.strip()}
        # dnsx -resp-only returns IPs; re-run for names
        r2 = subprocess.run(["dnsx", "-silent", "-t", "60"],
                            input="\n".join(hosts), capture_output=True, text=True, timeout=600)
        names = {l.strip().lower() for l in (r2.stdout or "").splitlines() if l.strip()}
        return sorted(names) if names else hosts
    except Exception:
        return hosts


def main() -> int:
    ap = argparse.ArgumentParser(description="Enumerate the low-saturation target programs.")
    ap.add_argument("--roots", type=int, default=8, help="roots per run")
    ap.add_argument("--timeout", type=int, default=600, help="seconds per root")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    roots = roots_from_targets()
    if not roots:
        return 2
    seen = load_seen()
    todo = [r for r in sorted(roots) if r not in seen]
    if not todo:
        log(f"all {len(roots)} target roots already enumerated — resetting the cursor")
        seen = set()
        todo = sorted(roots)
        try:
            os.remove(SEEN)
        except Exception:
            pass

    batch = todo[:a.roots]
    log(f"{len(roots)} root(s) across the low-saturation set; {len(todo)} not yet enumerated; "
        f"taking {len(batch)}")

    os.makedirs(INBOX, exist_ok=True)
    total_new = 0
    for root in batch:
        prog = roots[root]
        log(f"  {root}  ({prog})")
        found = enumerate_root(root, a.timeout)
        log(f"    {len(found)} name(s) from passive sources")
        if not found:
            seen.add(root)
            continue
        alive = resolve(sorted(found))
        log(f"    {len(alive)} resolve")
        if alive and not a.dry_run:
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            safe = re.sub(r"[^a-z0-9]+", "-", root)
            # 01_ = ahead of the general backlog, behind only the CT-fresh feed
            path = os.path.join(INBOX, f"01_enumtarget_{stamp}_{safe}.txt")
            with open(path, "w") as f:
                f.write("\n".join(alive) + "\n")
            log(f"    queued -> {os.path.basename(path)}")
        total_new += len(alive)
        seen.add(root)
        audit({"root": root, "program": prog, "found": len(found), "resolved": len(alive)})
        time.sleep(1)

    if not a.dry_run:
        with open(SEEN, "w") as f:
            f.write("\n".join(sorted(seen)) + "\n")

    log(f"DONE — {total_new:,} host(s) queued from {len(batch)} root(s)")
    print(json.dumps({"roots_total": len(roots), "roots_done": len(batch),
                      "hosts_queued": total_new}))
    return 0


if __name__ == "__main__":
    sys.exit(main())

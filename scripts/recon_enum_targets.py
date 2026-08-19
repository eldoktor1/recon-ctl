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


def wildcard_ips(root: str) -> set[str]:
    """Does *.root resolve for names that cannot exist?

    Caught on the first live run: 8x8pilot.com returned 1,945 names and ALL 1,945 resolved.
    A 100% resolution rate is not a large estate, it is a wildcard record — and queueing
    those names is precisely how 849,539 tumblr blogs got into ES. Any host resolving to
    the wildcard's own IP set is discarded.
    """
    import base64
    ips: set[str] = set()
    if not shutil.which("dnsx"):
        return ips
    probes = [f"{base64.b32encode(os.urandom(8)).decode().strip('=').lower()}.{root}"
              for _ in range(3)]
    try:
        r = subprocess.run(["dnsx", "-silent", "-a", "-resp-only", "-t", "10"],
                           input="\n".join(probes), capture_output=True, text=True, timeout=120)
        ips = {l.strip() for l in (r.stdout or "").splitlines() if l.strip()}
    except Exception:
        pass
    return ips


def resolve_pairs(hosts: list[str]) -> dict[str, set[str]]:
    """host -> its A records, so wildcard IPs can be filtered out."""
    out: dict[str, set[str]] = {}
    if not hosts or not shutil.which("dnsx"):
        return {h: set() for h in hosts}
    try:
        r = subprocess.run(["dnsx", "-silent", "-a", "-resp", "-t", "60"],
                           input="\n".join(hosts), capture_output=True, text=True, timeout=900)
        for line in (r.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            # "host [1.2.3.4]"
            m = re.match(r"^(\S+)\s+\[([^\]]+)\]", line)
            if m:
                out.setdefault(m.group(1).lower(), set()).add(m.group(2).strip())
            else:
                out.setdefault(line.split()[0].lower(), set())
    except Exception:
        return {h: set() for h in hosts}
    return out


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

        wc = wildcard_ips(root)
        if wc:
            log(f"    WILDCARD DNS — *.{root} resolves to {sorted(wc)[:3]}; "
                f"discarding names that only point there")

        pairs = resolve_pairs(sorted(found))
        alive = []
        dropped = 0
        for h, ips in pairs.items():
            if wc and ips and ips <= wc:
                dropped += 1          # resolves ONLY to the wildcard — not a real host
                continue
            alive.append(h)
        alive.sort()
        log(f"    {len(alive)} resolve" + (f" ({dropped} wildcard-only discarded)" if dropped else ""))
        if wc and found and len(alive) / max(1, len(found)) > 0.95:
            log(f"    still {len(alive)}/{len(found)} resolving under a wildcard — "
                f"treating this root as unreliable and skipping the queue")
            seen.add(root)
            audit({"root": root, "program": prog, "found": len(found),
                   "resolved": len(alive), "skipped": "wildcard-dominated"})
            continue
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

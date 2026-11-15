#!/usr/bin/env python3
"""
recon_meta.py — compile what the pipeline has LEARNED into something the hunters read.

THE GAP THIS CLOSES (2026-08-22). `recon_research.sh` runs four Claude topics on a cadence and
produces genuinely current material: docs/research/{vulns,tooling,kb-enrich,detect-tune}_<date>.md
plus KB docs and review proposals. Grepping every runtime path shows `docs/knowledge/` is
referenced ONLY in comments and docstrings. The single prompt-time injection in the whole engine
is the Ollama fallback primer. So the ai-hunter's hypothesis prompt — the one creative step that
decides what the system goes looking for — contained one hardcoded PHP/Laravel hint and nothing
else, and had no idea what the research lane discovered yesterday, which classes have never once
produced a `real` verdict, or which FP patterns already burned an evening.

Research that lands in a folder nobody reads is not a feedback loop. This compiles four things
into state/current_meta.md, which the hunter injects into every hypothesis prompt:

  1. WHAT ACTUALLY PAYS   — outcome-driven, from findings.db: which classes reached `real`,
                            which reached a paid resolution. Reprioritises toward what works.
  2. WHAT HAS NEVER PAID  — classes with a lifetime real-rate of zero, with their FP counts.
                            A prior against proposing the same duplicate again.
  3. FRESH TECHNIQUE INTEL— headline bullets from the last N days of research digests.
  4. KB INDEX             — which tech/class docs exist, so the model can say "read tech-argocd"
                            instead of re-deriving it.

HONESTY RULES. Everything here is a PRIOR, never evidence. The file says so in its own header,
because LLM-sourced CVE IDs can be hallucinated (the digests self-flag this). Nothing here can
mint: the hunter still gates on harness evidence_state + engine/impact.py. This aims the search;
it does not lower any bar.

Usage: recon_meta.py [--days 21] [--out <path>] [--print]
"""
from __future__ import annotations

import argparse
import os
import re
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE_DIR = os.environ.get("BASE_DIR", os.path.expanduser("~/recon"))
STATE_DIR = os.environ.get("STATE_DIR", os.path.join(BASE_DIR, "state"))
V3_DB = os.environ.get("V3_DB", os.path.join(BASE_DIR, "v3", "findings.db"))
RESEARCH_DIR = os.path.join(REPO_DIR, "docs", "research")
KB_DIR = os.path.join(REPO_DIR, "docs", "knowledge")
OUT = os.path.join(STATE_DIR, "current_meta.md")

MAX_BULLETS_PER_DIGEST = 4
MAX_CHARS = int(os.environ.get("META_MAX_CHARS", "6000"))


def log(m: str) -> None:
    print(f"[meta] {m}", file=sys.stderr, flush=True)


def outcomes() -> tuple[list[str], list[str]]:
    """(what has produced real verdicts, what never has) straight from the ledger."""
    pays, never = [], []
    if not os.path.exists(V3_DB):
        return pays, never
    try:
        conn = sqlite3.connect(f"file:{V3_DB}?mode=ro", uri=True, timeout=10)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT COALESCE(signal_class,'(none)') lane, COUNT(*) n, "
            "COALESCE(SUM(ai_verdict='real'),0) real, COALESCE(SUM(ai_verdict='fp'),0) fp, "
            "COALESCE(SUM(bounty),0) paid "
            "FROM findings GROUP BY 1 ORDER BY real DESC, n DESC").fetchall()
        conn.close()
    except Exception as e:
        log(f"findings.db unreadable ({e})")
        return pays, never
    for r in rows:
        if r["real"]:
            bit = f"`{r['lane']}` — {r['real']} real of {r['n']} minted"
            if r["paid"]:
                bit += f", {r['paid']:.0f} paid"
            pays.append(bit)
        elif r["n"] >= 5:
            never.append(f"`{r['lane']}` — 0 real in {r['n']} minted ({r['fp']} confirmed FP)")
    return pays, never


def digest_bullets(days: int) -> list[str]:
    """Headline bullets from recent research digests, newest first."""
    out = []
    if not os.path.isdir(RESEARCH_DIR):
        return out
    cutoff = datetime.now() - timedelta(days=days)
    files = []
    for fn in os.listdir(RESEARCH_DIR):
        m = re.match(r"(\w[\w-]*)_(\d{4}-\d{2}-\d{2})\.md$", fn)
        if not m:
            continue
        try:
            d = datetime.strptime(m.group(2), "%Y-%m-%d")
        except ValueError:
            continue
        if d >= cutoff:
            files.append((d, m.group(1), os.path.join(RESEARCH_DIR, fn)))
    files.sort(reverse=True)
    for d, topic, path in files:
        picked = 0
        try:
            for line in open(path, encoding="utf-8", errors="replace"):
                s = line.strip()
                # headline bullets only; skip nav, headers and the digests' own caveat lines
                if not s.startswith(("- ", "* ")) or len(s) < 25:
                    continue
                if any(w in s.lower() for w in ("source:", "http://", "https://", "see also")):
                    continue
                out.append(f"[{topic} {d:%Y-%m-%d}] {s.lstrip('-* ').strip()[:220]}")
                picked += 1
                if picked >= MAX_BULLETS_PER_DIGEST:
                    break
        except Exception:
            continue
    return out


def kb_index() -> list[str]:
    if not os.path.isdir(KB_DIR):
        return []
    docs = sorted(f[:-3] for f in os.listdir(KB_DIR)
                  if f.endswith(".md") and f.startswith(("tech-", "class-")))
    return docs


def fp_patterns(limit: int = 8) -> list[str]:
    p = os.path.join(STATE_DIR, "fp_patterns.md")
    if not os.path.exists(p):
        return []
    out = []
    try:
        for line in reversed(open(p, encoding="utf-8", errors="replace").readlines()):
            s = line.strip()
            if s.startswith(("- ", "* ")) and len(s) > 25:
                out.append(s.lstrip("-* ").strip()[:200])
            if len(out) >= limit:
                break
    except Exception:
        pass
    return out


def build(days: int) -> str:
    pays, never = outcomes()
    parts = [
        "# CURRENT META — compiled priors for the hunt",
        f"_generated {datetime.now(timezone.utc):%Y-%m-%dT%H:%M:%SZ} from the outcome ledger, "
        f"the last {days} days of research, and the KB._",
        "",
        "**These are PRIORS, not evidence.** They aim what you look for. They never lower a bar: "
        "a finding still requires a real harness-captured response and a recovered impact. "
        "CVE identifiers sourced from research digests can be wrong — verify a version before "
        "treating any of it as confirmed.",
        "",
    ]
    if pays:
        parts += ["## What has actually produced real findings here", *(f"- {x}" for x in pays), ""]
    if never:
        parts += [
            "## What has NEVER produced a real finding here (treat as duplicate-by-default)",
            *(f"- {x}" for x in never),
            "- Proposing one of these needs a reason THIS host is different, not the class again.",
            "",
        ]
    fps = fp_patterns()
    if fps:
        parts += ["## Recently-burned false-positive patterns", *(f"- {x}" for x in fps), ""]
    bullets = digest_bullets(days)
    if bullets:
        parts += ["## Fresh technique / vuln intel", *(f"- {x}" for x in bullets), ""]
    kb = kb_index()
    if kb:
        parts += [
            "## Knowledge base available (docs/knowledge/)",
            "If the target runs one of these, its documented paths/sinks/bypasses apply:",
            "  " + ", ".join(kb),
            "",
        ]
    text = "\n".join(parts)
    if len(text) > MAX_CHARS:
        text = text[:MAX_CHARS].rsplit("\n", 1)[0] + "\n\n_(truncated to fit the prompt budget)_\n"
    return text


def main() -> int:
    ap = argparse.ArgumentParser(description="Compile learned priors into state/current_meta.md")
    ap.add_argument("--days", type=int, default=21)
    ap.add_argument("--out", default=OUT)
    ap.add_argument("--print", action="store_true", dest="show")
    a = ap.parse_args()

    text = build(a.days)
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    tmp = a.out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, a.out)
    log(f"{len(text)} chars -> {a.out}")
    if a.show:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""GATE 0 — financial-tier classifier (load-bearing autonomy boundary).

Single source of truth: v3/tier_list.tsv (version-controlled, human-maintained).

CONTRACT (fail-safe toward FINANCIAL):
    classify(program) -> "GENERAL" | "FINANCIAL"
    A program is GENERAL **only** if it has an exact row in tier_list.tsv with
    tier=GENERAL AND reviewed_by is a real reviewer (not 'unreviewed'/'-').
    Everything else — unknown program, unreviewed row, blank, parse error,
    missing file — returns FINANCIAL. Misclassifying an exchange as GENERAL is
    the exact failure that puts an autonomous agent on a custody platform, so the
    default is always the restrictive tier.

Phase D consults this before deciding autonomous-active vs detect+stage-only.
"""
from __future__ import annotations
import os
import sys
import functools

TIER_LIST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tier_list.tsv")
GENERAL = "GENERAL"
FINANCIAL = "FINANCIAL"
_UNREVIEWED = {"", "-", "unreviewed", "none", "todo"}


@functools.lru_cache(maxsize=1)
def _load(path: str = TIER_LIST) -> dict:
    """program -> (tier, reviewed_by, seed_class). Cached; call _load.cache_clear() to reload."""
    rows: dict[str, tuple] = {}
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                parts = line.rstrip("\n").split("\t")
                if not parts or not parts[0]:
                    continue
                prog = parts[0]
                tier = (parts[1] if len(parts) > 1 else "").strip().upper()
                reviewer = (parts[2] if len(parts) > 2 else "").strip().lower()
                seed = (parts[4] if len(parts) > 4 else "").strip()
                rows[prog] = (tier, reviewer, seed)
    except OSError:
        return {}  # missing/unreadable list -> classify() yields FINANCIAL for all
    return rows


def classify(program: str | None) -> str:
    """Return GENERAL or FINANCIAL. Fail-safe: anything uncertain -> FINANCIAL."""
    if not program:
        return FINANCIAL
    row = _load().get(program)
    if row is None:
        return FINANCIAL  # default-unknown -> FINANCIAL
    tier, reviewer, _ = row
    if tier == GENERAL and reviewer not in _UNREVIEWED:
        return GENERAL
    return FINANCIAL


def is_financial(program: str | None) -> bool:
    return classify(program) == FINANCIAL


def audit() -> dict:
    rows = _load()
    general = [p for p, r in rows.items() if r[0] == GENERAL and r[1] not in _UNREVIEWED]
    fin_reviewed = [p for p, r in rows.items() if r[0] == FINANCIAL and r[1] not in _UNREVIEWED]
    unreviewed = [p for p, r in rows.items() if r[1] in _UNREVIEWED]
    return {
        "total": len(rows),
        "general_reviewed": len(general),
        "financial_reviewed": len(fin_reviewed),
        "unreviewed_default_financial": len(unreviewed),
        "general_programs": sorted(general),
    }


def _main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[1] == "classify":
        prog = " ".join(argv[2:]) if len(argv) > 2 else ""
        print(classify(prog))
        return 0 if classify(prog) == GENERAL else 3  # exit 3 = financial (scriptable gate)
    if len(argv) >= 2 and argv[1] == "audit":
        a = audit()
        for k in ("total", "general_reviewed", "financial_reviewed", "unreviewed_default_financial"):
            print(f"{k}: {a[k]}")
        if a["general_programs"]:
            print("GENERAL (autonomous-active) programs:")
            for p in a["general_programs"]:
                print(f"  - {p}")
        else:
            print("GENERAL (autonomous-active) programs: NONE (all financial/unreviewed) — "
                  "Phase D must not active-test any program until a human reclassifies here.")
        return 0
    print("usage: tier.py {classify <program> | audit}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv))

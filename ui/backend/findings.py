"""Read-only access to ~/recon/v3/findings.db (the finding state machine).

Reads go straight to SQLite (fast, WAL, mode=ro). Mutations go through the CLI
(state.py outcome, recon submit/fp) so the pipeline stays the source of truth.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from typing import Any

from . import config

# columns safe to surface in list views
LIST_COLS = (
    "id, dedup_key, host, url, program, signal_class, vuln_class, state, score, "
    "priority, confidence, review_tier, ai_verdict, ai_confidence, resolution, "
    "bounty, created_at, updated_at, state_changed_at"
)


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(f"file:{config.FINDINGS_DB}?mode=ro", uri=True, timeout=5)
    c.row_factory = sqlite3.Row
    return c


def _row(r: sqlite3.Row) -> dict[str, Any]:
    d = dict(r)
    for k in ("evidence", "ai_report"):
        if k in d and isinstance(d[k], str) and d[k]:
            try:
                d[k] = json.loads(d[k])
            except Exception:
                pass
    return d


def state_counts() -> dict[str, int]:
    with closing(_conn()) as c:
        return {
            r["state"]: r["c"]
            for r in c.execute("SELECT state, COUNT(*) c FROM findings GROUP BY state")
        }


def list_findings(
    *,
    state: str | None = None,
    program: str | None = None,
    vuln_class: str | None = None,
    verdict: str | None = None,
    q: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    where, params = [], []
    if state:
        where.append("state = ?"); params.append(state)
    if program:
        where.append("program = ?"); params.append(program)
    if vuln_class:
        where.append("vuln_class = ?"); params.append(vuln_class)
    if verdict:
        where.append("ai_verdict = ?"); params.append(verdict)
    if q:
        where.append("(host LIKE ? OR url LIKE ? OR program LIKE ?)")
        params += [f"%{q}%"] * 3
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    with closing(_conn()) as c:
        total = c.execute(f"SELECT COUNT(*) n FROM findings{clause}", params).fetchone()["n"]
        rows = c.execute(
            f"SELECT {LIST_COLS} FROM findings{clause} "
            "ORDER BY COALESCE(state_changed_at, updated_at, created_at) DESC "
            "LIMIT ? OFFSET ?",
            [*params, limit, offset],
        ).fetchall()
    return {"total": total, "limit": limit, "offset": offset, "items": [_row(r) for r in rows]}


def get_finding(fid: int) -> dict[str, Any] | None:
    with closing(_conn()) as c:
        r = c.execute("SELECT * FROM findings WHERE id = ?", (fid,)).fetchone()
        if not r:
            return None
        d = _row(r)
        try:
            audit = c.execute(
                "SELECT * FROM audit_log WHERE finding_id = ? ORDER BY id ASC", (fid,)
            ).fetchall()
            d["audit_log"] = [dict(a) for a in audit]
        except Exception:
            d["audit_log"] = []
        return d


def facets() -> dict[str, list[str]]:
    """Distinct values for filter dropdowns."""
    out: dict[str, list[str]] = {}
    with closing(_conn()) as c:
        for col in ("state", "program", "vuln_class", "ai_verdict"):
            out[col] = [
                r[col]
                for r in c.execute(
                    f"SELECT DISTINCT {col} FROM findings WHERE {col} IS NOT NULL AND {col} != '' "
                    f"ORDER BY {col}"
                )
                if r[col]
            ]
    return out


def recent_confirmed(limit: int = 8) -> list[dict[str, Any]]:
    with closing(_conn()) as c:
        rows = c.execute(
            f"SELECT {LIST_COLS} FROM findings WHERE state IN ('confirmed','reported','submitted') "
            "ORDER BY COALESCE(state_changed_at, updated_at, created_at) DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [_row(r) for r in rows]

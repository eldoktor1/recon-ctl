"""Parsers for the flat-file surface: briefings, notes, ignores, submissions."""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

from . import config

_DATE_RE = re.compile(r"(\d{4}-\d{2}-\d{2})")


def list_briefings() -> list[dict[str, Any]]:
    out = []
    try:
        for p in sorted(config.BRIEF_DIR.glob("*.md"), key=lambda x: x.stat().st_mtime, reverse=True):
            m = _DATE_RE.search(p.name)
            out.append({
                "name": p.name,
                "kind": _DATE_RE.sub("", p.stem).strip("_-") or p.stem,
                "date": m.group(1) if m else None,
                "mtime": int(p.stat().st_mtime),
                "size": p.stat().st_size,
            })
    except Exception:
        pass
    return out


def read_briefing(name: str) -> str | None:
    # prevent path traversal — only a bare filename in BRIEF_DIR
    if "/" in name or "\\" in name or ".." in name:
        return None
    p = config.BRIEF_DIR / name
    if not p.exists() or p.suffix != ".md":
        return None
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None


def latest_tonight() -> dict[str, Any] | None:
    briefs = [b for b in list_briefings() if b["kind"].startswith("tonight")]
    if not briefs:
        return None
    top = briefs[0]
    body = read_briefing(top["name"]) or ""
    lines = [l for l in body.splitlines() if l.strip()]
    return {**top, "preview": lines[:24], "line_count": len(lines)}


def _read_jsonl(path: Path, limit: int = 500) -> list[dict[str, Any]]:
    out = []
    try:
        if path.exists():
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except Exception:
                        pass
    except Exception:
        pass
    return out[-limit:]


def submissions(limit: int = 200) -> list[dict[str, Any]]:
    return list(reversed(_read_jsonl(config.SUBMISSIONS, limit)))


def notes(q: str | None = None, limit: int = 1000) -> list[dict[str, Any]]:
    """Permanent host notes (worked-knowledge), newest first, optional text search."""
    rows = _read_jsonl(config.HOST_NOTES, limit=50000)
    if q:
        ql = q.lower()
        rows = [r for r in rows if ql in (r.get("host", "") + " " + r.get("note", "") +
                                          " " + str(r.get("program", "") or "")).lower()]
    rows.sort(key=lambda r: r.get("created_at", ""), reverse=True)
    return rows[:limit]


def notes_stats() -> dict[str, Any]:
    rows = _read_jsonl(config.HOST_NOTES, limit=50000)
    hosts = {r.get("host") for r in rows if r.get("host")}
    by_source: dict[str, int] = {}
    for r in rows:
        s = r.get("source", "?")
        by_source[s] = by_source.get(s, 0) + 1
    return {"total": len(rows), "hosts": len(hosts), "by_source": by_source}


def reports(limit: int = 200) -> list[dict[str, Any]]:
    """Report review queue (~/recon/v3/reports/review_queue.jsonl)."""
    return list(reversed(_read_jsonl(config.REVIEW_QUEUE, limit)))


def active_ignores() -> list[dict[str, Any]]:
    now = time.time()
    out = []
    for r in _read_jsonl(config.IGNORED):
        added = r.get("added_at")
        ok = True
        # 7-day TTL if added_at is epoch-ish
        try:
            if isinstance(added, (int, float)) and now - float(added) > 7 * 86400:
                ok = False
        except Exception:
            pass
        if ok:
            out.append(r)
    return out

"""Parsers for the flat-file surface: briefings, notes, ignores, submissions."""
from __future__ import annotations

import importlib.util
import json
import re
import time
from pathlib import Path
from typing import Any

from . import config

# --- worked-and-killed suppression (shared source of truth with the briefing) ---
# tools/note_verdict.py classifies a host's notes as dead/open/none. A "dead"
# verdict (fp / by-design / exhausted / "do not re-serve", not re-armed) is what
# the nightly briefing already uses to stop re-serving corpses; we apply the SAME
# rule in the UI so a lead the operator marked not-actionable disappears here too.
_NV: Any = None


def _note_verdict():
    global _NV
    if _NV is None:
        try:
            spec = importlib.util.spec_from_file_location(
                "note_verdict", str(config.REPO_DIR / "tools" / "note_verdict.py"))
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)  # type: ignore[union-attr]
            _NV = mod
        except Exception:
            _NV = False
    return _NV or None


def killed_host_set() -> set[str]:
    """Hosts (+root_domains) whose notes verdict is DEAD — never re-serve."""
    nv = _note_verdict()
    if not nv:
        return set()
    try:
        return {h.lower() for h in nv.killed_hosts(str(config.HOST_NOTES))}
    except Exception:
        return set()


def benched_host_set() -> set[str]:
    """Hosts currently benched (active 7-day ignore) — hide until the TTL lapses."""
    return {(r.get("host") or "").lower() for r in active_ignores() if r.get("host")}

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


# --------------------------------------------------------------------------- structured briefing parser
# The briefings are consistent, well-structured Markdown (## sections, `- ` /
# `### ` items). We parse them into structured sections+items so the UI can
# render an INTERACTIVE worklist (clickable host chips, copy-command buttons,
# one-click verify) instead of a passive wall of Markdown. Each item keeps its
# `raw` Markdown block (rendered as the detail) plus extracted affordances.

_HOST_RE = re.compile(r"\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)\b", re.I)
_BACKTICK_RE = re.compile(r"`([^`]+)`")
# last labels that look like a TLD but are really file extensions / noise
_NON_TLD = {
    "txt", "css", "js", "php", "json", "jsp", "asp", "aspx", "html", "htm", "map",
    "md", "xml", "yml", "yaml", "png", "jpg", "jpeg", "svg", "gif", "go", "py",
    "sh", "ts", "tsx", "jsx", "conf", "ini", "log", "csv", "pdf", "zip",
}
_CMD_PREFIX_RE = re.compile(r"^(recon-|recon\s|bash\s|sqlmap|dalfox|nuclei|curl\s|puredns|ffuf|katana|gau)", re.I)
_SEV_BRACKET_RE = re.compile(r"\[(elite|critical|high|medium|low)\b", re.I)


def _valid_host(tok: str) -> str | None:
    tok = tok.strip().lower().rstrip(".")
    if not tok or " " in tok or "*" in tok:
        return None
    if not re.fullmatch(r"[a-z0-9.-]+", tok):
        return None
    parts = tok.split(".")
    if len(parts) < 2:
        return None
    tld = parts[-1]
    if tld in _NON_TLD or not tld.isalpha() or len(tld) < 2:
        return None
    # reject version-ish tokens (every label numeric) and single-char sld noise
    if all(p.isdigit() for p in parts[:-1]):
        return None
    return tok


def _clean_hostish(tok: str) -> str:
    tok = tok.strip()
    tok = re.sub(r"^https?://", "", tok)
    tok = tok.split()[0] if tok else tok
    return tok.split("/")[0].split("?")[0].split("#")[0]


def _extract_hosts(text: str) -> list[str]:
    hosts: list[str] = []
    # prefer backticked tokens (the briefings consistently backtick real hosts)
    for m in _BACKTICK_RE.finditer(text):
        h = _valid_host(_clean_hostish(m.group(1)))
        if h and h not in hosts:
            hosts.append(h)
    if not hosts:
        for m in _HOST_RE.finditer(text):
            h = _valid_host(m.group(1))
            if h and h not in hosts:
                hosts.append(h)
    return hosts[:6]


def _extract_commands(text: str) -> list[str]:
    cmds: list[str] = []
    for m in _BACKTICK_RE.finditer(text):
        c = m.group(1).strip()
        if _CMD_PREFIX_RE.match(c) and c not in cmds:
            cmds.append(c)
    return cmds[:5]


def _extract_severity(text: str) -> str | None:
    m = _SEV_BRACKET_RE.search(text)
    if m:
        return m.group(1).lower()
    if re.search(r"\bLEAD\b", text):
        return "lead"
    m2 = re.search(r"\b(P[0-3])\b", text)
    if m2:
        return m2.group(1).lower()
    return None


def _extract_program(text: str) -> str | None:
    m = re.search(r"(?im)^\s*[-*]?\s*program:\s*(.+)$", text)
    if m:
        return m.group(1).strip()[:60]
    m = re.search(r"\[(bugcrowd|hackerone|intigriti|yeswehack|h1|bc|ywh)\]", text, re.I)
    if m:
        return m.group(1).lower()
    return None


def _item_label(raw: str) -> str:
    first = next((l for l in raw.splitlines() if l.strip()), "")
    first = re.sub(r"^\s*[-*#>]+\s*", "", first)
    first = re.sub(r"[*`_]", "", first)
    return first.strip()[:160]


def _make_item(block: list[str]) -> dict[str, Any] | None:
    raw = "\n".join(block).strip()
    if not raw:
        return None
    return {
        "raw": raw,
        "label": _item_label(raw),
        "hosts": _extract_hosts(raw),
        "commands": _extract_commands(raw),
        "program": _extract_program(raw),
        "severity": _extract_severity(raw),
    }


_ORDERED_RE = re.compile(r"^\d+[.)]\s")


def _is_item_start(ls: str) -> bool:
    return ls.startswith("- ") or ls.startswith("* ") or bool(_ORDERED_RE.match(ls))


def _segment_items(lines: list[str]) -> list[dict[str, Any]]:
    """Split a section's lines into item blocks.

    Sections that use `### ` headers group everything under each header into one
    item (the tonight authed/GraphQL style). Sections without `### ` treat each
    top-level bullet (`- `/`* `) OR numbered list entry (`1.`) as its own item
    (the HUNT-THESE / 2IC-DIG / hunter styles).
    """
    has_h3 = any(l.lstrip().startswith("### ") for l in lines)
    blocks: list[list[str]] = []
    cur: list[str] | None = None
    if has_h3:
        for l in lines:
            if l.lstrip().startswith("### "):
                if cur:
                    blocks.append(cur)
                cur = [l]
            elif cur is not None:
                cur.append(l)
            # lines before the first ### are section intro — dropped from items
    else:
        for l in lines:
            ls = l.lstrip()
            indent = len(l) - len(ls)
            if _is_item_start(ls) and indent == 0:
                if cur:
                    blocks.append(cur)
                cur = [l]
            elif cur is not None and ls:
                cur.append(l)
            elif cur is not None and not ls:
                blocks.append(cur)
                cur = None
    if cur:
        blocks.append(cur)
    out = []
    for b in blocks:
        it = _make_item(b)
        if it:
            out.append(it)
    return out


def _split_section_header(header: str) -> tuple[str, str, int | None]:
    count = None
    m = re.search(r"[—-]\s*(\d+)\s*$", header)
    if m:
        count = int(m.group(1))
    emoji = ""
    mm = re.match(r"^\s*([^\w\s#`*\[\(]+)\s*", header)
    if mm:
        emoji = mm.group(1).strip()
        header = header[mm.end():]
    return emoji, header.strip(), count


def parse_briefing(name: str) -> dict[str, Any] | None:
    """Parse a briefing .md into interactive sections+items. Never raises — on
    any parse failure it falls back to a single raw-body section."""
    body = read_briefing(name)
    if body is None:
        return None
    meta = next((b for b in list_briefings() if b["name"] == name), {"name": name, "kind": name})
    try:
        lines = body.splitlines()
        title = ""
        sections: list[dict[str, Any]] = []
        # implicit pre-section catches bullets that live directly under the `# `
        # title with no `## ` header (the hunter-worklist style).
        implicit = {"emoji": "", "title": "", "declared_count": None, "_lines": []}
        cur: dict[str, Any] = implicit
        for line in lines:
            if line.startswith("## "):
                emoji, ttl, count = _split_section_header(line[3:].strip())
                cur = {"emoji": emoji, "title": ttl, "declared_count": count, "_lines": []}
                sections.append(cur)
            elif line.startswith("# ") and not title:
                title = re.sub(r"[*`]", "", line[2:]).strip()
            else:
                cur["_lines"].append(line)
        # keep the implicit section first only if it actually holds items
        if _segment_items(list(implicit["_lines"])):
            if not implicit["title"]:
                implicit["title"] = title or "worklist"
            sections.insert(0, implicit)
        killed, benched = killed_host_set(), benched_host_set()
        for i, s in enumerate(sections):
            items = _segment_items(s.pop("_lines"))
            live = 0
            for it in items:
                hs = [h.lower() for h in it["hosts"]]
                if any(h in killed for h in hs):
                    it["suppressed"], it["suppress_reason"] = True, "not-actionable"
                elif any(h in benched for h in hs):
                    it["suppressed"], it["suppress_reason"] = True, "benched"
                else:
                    it["suppressed"], it["suppress_reason"] = False, None
                    live += 1
            s["id"] = i
            s["items"] = items
            s["suppressed_count"] = len(items) - live
            s["count"] = s.get("declared_count") if s.get("declared_count") is not None else live
        return {
            "name": meta["name"], "kind": meta.get("kind"), "date": meta.get("date"),
            "mtime": meta.get("mtime"), "title": title, "sections": sections,
        }
    except Exception as e:
        return {
            "name": meta["name"], "kind": meta.get("kind"), "date": meta.get("date"),
            "title": "", "error": str(e),
            "sections": [{"id": 0, "emoji": "", "title": "raw", "count": 0,
                          "items": [{"raw": body, "label": "", "hosts": [], "commands": [], "program": None, "severity": None}]}],
        }


def latest_tonight_parsed() -> dict[str, Any] | None:
    briefs = [b for b in list_briefings() if b["kind"].startswith("tonight")]
    if not briefs:
        return None
    return parse_briefing(briefs[0]["name"])


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


def target_board() -> dict[str, Any]:
    """Under-hunted program board (briefings/targets_latest.json)."""
    p = config.BRIEF_DIR / "targets_latest.json"
    try:
        if p.exists():
            data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
            data["_mtime"] = int(p.stat().st_mtime)
            return data
    except Exception as e:
        return {"error": str(e), "programs": []}
    return {"programs": []}


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

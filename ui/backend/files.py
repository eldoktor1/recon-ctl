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


def noted_host_set() -> set[str]:
    """Every host that has ANY note (i.e. has been worked/SEEN) — for an 'unseen only' worklist
    drain that leaves only targets we haven't looked at yet."""
    out: set[str] = set()
    try:
        with open(config.HOST_NOTES, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except Exception:
                    continue
                h = (d.get("host") or "").lower()
                if h:
                    out.add(h)
    except Exception:
        pass
    return out


def killed_host_classes() -> dict[str, set[str]]:
    """{host -> set(vuln_classes)} for hosts killed only for SPECIFIC classes (class-scoped FP).

    Distinct from killed_host_set (which is host-wide dead). A class-scoped FP note should only
    suppress a lead whose bucket represents that same class — the host stays servable elsewhere.
    """
    nv = _note_verdict()
    if not nv:
        return {}
    try:
        return {h.lower(): set(c) for h, c in nv.killed_host_classes(str(config.HOST_NOTES)).items()}
    except Exception:
        return {}


def benched_host_set() -> set[str]:
    """Hosts currently benched (active 7-day ignore) — hide until the TTL lapses."""
    return {(r.get("host") or "").lower() for r in active_ignores() if r.get("host")}


def program_endpoints(hosts: list[str] | None, limit: int = 40) -> list[str]:
    """Best-effort sample of jsintel-discovered endpoints for a set of program hosts.

    Reads ~/recon/js_recon/endpoints.jsonl (the IDOR/BAC feedstock) and keeps rows whose
    host is in the set (or whose URL contains one). Never raises — missing file → []."""
    host_set = {(h or "").lower() for h in (hosts or []) if h}
    if not host_set:
        return []
    p = config.BASE_DIR / "js_recon" / "endpoints.jsonl"
    out: list[str] = []
    try:
        with p.open(encoding="utf-8", errors="replace") as f:
            for ln in f:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    d = json.loads(ln)
                except Exception:
                    continue
                if not isinstance(d, dict):
                    continue
                host = str(d.get("host") or d.get("hostname") or "").lower()
                url = d.get("url") or d.get("endpoint") or d.get("path") or ""
                if not url:
                    continue
                if host and host not in host_set:
                    if not any(hh in str(url).lower() for hh in host_set):
                        continue
                if not host and not any(hh in str(url).lower() for hh in host_set):
                    continue
                s = str(url)[:300]
                if s not in out:
                    out.append(s)
                if len(out) >= limit:
                    break
    except Exception:
        return out
    return out


# --- retained application source (app-model feedstock) ----------------------
# recon_jsintel.sh reconstructs leaked source maps (the ORIGINAL un-minified app source) and
# now RETAINS them under ~/recon/js_recon/src/<host>/. Endpoint strings say a route exists;
# the source says WHERE AUTHORISATION IS ENFORCED and WHO OWNS AN OBJECT — which is what a
# five-figure finding actually turns on. We never dump whole trees into a prompt: we extract
# the authz/ownership/role decision points and the API call sites, which is the signal.

# lines that reveal an authorisation / ownership / tenancy decision
_AUTHZ_RE = re.compile(
    r"\b(is[A-Z]\w*(?:Admin|Owner|Member|Staff|Manager)|hasRole|hasPermission|hasAccess|canEdit|canView|"
    r"can[A-Z]\w{2,20}|checkAccess|requireAuth|requireRole|authoriz\w*|permission|acl|"
    r"role\s*[=:!]|isAdmin|is_admin|owner_?id|ownerId|tenant_?id|tenantId|account_?id|accountId|"
    r"member_?id|memberId|org(?:anization)?_?id|orgId|user_?id\s*[=!]==|current_?user|currentUser|"
    r"subscription|entitlement|plan\s*[=:]|isPremium|is_premium)\b", re.I)
# API call sites — reveals METHOD + PATH + which params are caller-controlled
_CALL_RE = re.compile(
    r"""(?:fetch|axios(?:\.\w+)?|\$http|request|api(?:\.\w+)?)\s*\(\s*[`'"]([^`'"]{4,160})[`'"]"""
    r"""|method\s*:\s*[`'"](GET|POST|PUT|PATCH|DELETE)[`'"]""", re.I)
_SRC_EXT = (".js", ".jsx", ".ts", ".tsx", ".vue", ".mjs")
# dependency trees are not the target's code
_SRC_SKIP = re.compile(r"(^|/)(node_modules|vendor|dist|polyfill|webpack|core-js|lodash|moment)(/|$)", re.I)


def program_source(hosts: list[str] | None, max_files: int = 400,
                   max_excerpts: int = 90) -> dict[str, Any]:
    """Mine RETAINED reconstructed source for a program's hosts into app-model signal.

    Returns {hosts:[...], files:N, authz:[{file,line,code}], calls:[str], modules:[str]}.
    Best-effort and bounded — never raises, missing tree → empty result."""
    host_set = [(h or "").lower() for h in (hosts or []) if h]
    out: dict[str, Any] = {"hosts": [], "files": 0, "authz": [], "calls": [], "modules": []}
    root = config.BASE_DIR / "js_recon" / "src"
    if not host_set or not root.is_dir():
        return out
    seen_code: set[str] = set()
    calls: set[str] = set()
    mods: set[str] = set()
    nfiles = 0
    try:
        for h in host_set:
            d = root / h
            if not d.is_dir():
                continue
            out["hosts"].append(h)
            for p in sorted(d.rglob("*")):
                if nfiles >= max_files or len(out["authz"]) >= max_excerpts:
                    break
                if not p.is_file() or p.suffix.lower() not in _SRC_EXT:
                    continue
                rel = str(p.relative_to(d))
                if _SRC_SKIP.search(rel):
                    continue
                nfiles += 1
                # the module path itself is signal: components named Billing/Admin/Member/Auth
                mods.add(rel[:120])
                try:
                    txt = p.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue
                if len(txt) > 400_000:          # a single giant bundle — skip, it is not real source
                    continue
                for i, line in enumerate(txt.splitlines(), 1):
                    ls = line.strip()
                    if not ls or len(ls) > 400:
                        continue
                    if len(out["authz"]) < max_excerpts and _AUTHZ_RE.search(ls):
                        code = ls[:300]
                        k = code.lower()
                        if k not in seen_code:
                            seen_code.add(k)
                            out["authz"].append({"file": rel[:120], "line": i, "code": code})
                    if len(calls) < 120:
                        m = _CALL_RE.search(ls)
                        if m and m.group(1):
                            calls.add(m.group(1)[:160])
    except Exception:
        pass
    out["files"] = nfiles
    out["calls"] = sorted(calls)[:120]
    # surface the most telling module names first (auth/billing/admin/member beat generic ui)
    hot = re.compile(r"(auth|login|account|member|admin|billing|payment|subscri|permission|role|owner|tenant|oauth|gift|offer)", re.I)
    out["modules"] = ([m for m in sorted(mods) if hot.search(m)][:60]
                      + [m for m in sorted(mods) if not hot.search(m)][:20])
    return out


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

"""In-UI Claude co-pilot — argv builder + availability probe.

The console reuses the hunt spool exactly like a lane: the sandboxed web
process spawns a task whose argv runs `recon_claude_console.sh`, and the
unsandboxed runner executes it (Claude on the operator's Max OAuth, as d0k).
Output is stream-json (one event per line), tailed to the browser over the
existing task WebSocket. No pipeline logic here — just shaping the command.
"""
from __future__ import annotations

import json
import re
import uuid as _uuid

from . import config

_UUID_RE = re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$")


def new_session_id() -> str:
    return str(_uuid.uuid4())


def valid_session(sid: str | None) -> bool:
    return bool(sid) and bool(_UUID_RE.match(sid or ""))


def resolve_model(name: str | None) -> str:
    """Map a friendly name (opus/sonnet/haiku) to a model id.

    Empty/unknown -> the configured default (opus 4.8). Never returns '' so the
    console is deterministic regardless of what the client sends.
    """
    key = (name or config.CONSOLE_DEFAULT_MODEL).lower()
    return config.CONSOLE_MODELS.get(key, config.CONSOLE_MODELS[config.CONSOLE_DEFAULT_MODEL])


def build_argv(session_id: str, message: str, model: str | None = None) -> list[str]:
    argv = ["bash", str(config.CONSOLE_SH), session_id, message]
    resolved = resolve_model(model)
    # positional: <session> <message> [model] [perm]
    argv.append(resolved)            # may be "" (default model)
    argv.append(config.CONSOLE_PERM)
    return argv


# --------------------------------------------------------------------------- sessions
def _transcript(sid: str):
    return config.CLAUDE_PROJECT_DIR / f"{sid}.jsonl"


def _tool_input_summary(name: str, inp) -> str:
    if not isinstance(inp, dict):
        return ""
    if name == "Task":
        return f"[{inp.get('subagent_type', 'agent')}] {inp.get('description') or inp.get('prompt') or ''}"[:200]
    if name == "TodoWrite" and isinstance(inp.get("todos"), list):
        return f"{len(inp['todos'])} todos"
    # built-ins + MCP tools (burp/brave/…): first telling field wins, else JSON
    for k in ("command", "file_path", "notebook_path", "pattern", "query", "url",
              "request", "host", "method", "expression", "function", "selector",
              "uid", "value", "payload", "text", "port"):
        v = inp.get(k)
        if v:
            return (v if isinstance(v, str) else json.dumps(v))[:200]
    try:
        return json.dumps(inp)[:160]
    except Exception:
        return ""


def _result_text(body) -> str:
    """Text of a tool_result, with an image block (e.g. Brave screenshot) surfaced
    as a marker — the raw base64 is intentionally not embedded in history payloads."""
    if isinstance(body, str):
        return body
    txt = _first_text(body)
    if txt:
        return txt
    if isinstance(body, list) and any(
        isinstance(c, dict) and c.get("type") == "image" for c in body
    ):
        return "🖼 [screenshot captured — shown live]"
    return ""


def _first_text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        for c in content:
            if isinstance(c, dict) and c.get("type") == "text":
                return c.get("text", "")
    return ""


def _is_tool_result(content) -> bool:
    return isinstance(content, list) and any(
        isinstance(c, dict) and c.get("type") == "tool_result" for c in content
    )


def list_sessions() -> list[dict]:
    """Every Co-Pilot conversation = a `.started` marker + its claude transcript.

    Returns [{session_id, title, turns, updated}] newest-first. The marker dir is
    the registry (only console sessions get one), so main-session transcripts are
    never listed.
    """
    out: list[dict] = []
    mdir = config.CONSOLE_DIR
    if not mdir.exists():
        return out
    for marker in mdir.glob("*.started"):
        sid = marker.stem
        if not valid_session(sid):
            continue
        tr = _transcript(sid)
        title, turns, updated = "(new)", 0, marker.stat().st_mtime
        if tr.exists():
            updated = tr.stat().st_mtime
            title, turns = _summarize(tr)
        out.append({"session_id": sid, "title": title, "turns": turns, "updated": updated})
    out.sort(key=lambda x: -x["updated"])
    return out


def _summarize(tr) -> tuple[str, int]:
    title, turns = "", 0
    try:
        with tr.open() as f:
            for ln in f:
                try:
                    m = json.loads(ln)
                except Exception:
                    continue
                if m.get("type") != "user":
                    continue
                msg = m.get("message") or {}
                if msg.get("role") != "user":
                    continue
                content = msg.get("content")
                if _is_tool_result(content):
                    continue
                text = _first_text(content).strip()
                if text:
                    turns += 1
                    if not title:
                        title = text[:90]
    except Exception:
        pass
    return (title or "(untitled)", turns)


def load_transcript(sid: str, limit: int = 300) -> list[dict]:
    """Parse a transcript into frontend-shaped turns (user / assistant+blocks).

    Tool results are correlated back to their tool_use block so history shows
    what each command returned.
    """
    tr = _transcript(sid)
    if not tr.exists():
        return []
    rows = []
    for ln in tr.open():
        try:
            rows.append(json.loads(ln))
        except Exception:
            continue
    # pass 1: map tool_use_id -> result text
    results: dict[str, tuple[str, bool]] = {}
    for m in rows:
        msg = m.get("message") or {}
        content = msg.get("content")
        if isinstance(content, list):
            for c in content:
                if isinstance(c, dict) and c.get("type") == "tool_result":
                    tid = c.get("tool_use_id", "")
                    txt = _result_text(c.get("content"))
                    results[tid] = (str(txt)[:4000], bool(c.get("is_error")))
    # pass 2: build turns
    turns: list[dict] = []
    for m in rows:
        t = m.get("type")
        msg = m.get("message") or {}
        if t == "user" and msg.get("role") == "user":
            content = msg.get("content")
            if _is_tool_result(content):
                continue
            text = _first_text(content).strip()
            if text:
                turns.append({"role": "user", "blocks": [{"kind": "text", "text": text}]})
        elif t == "assistant" and isinstance(msg.get("content"), list):
            blocks = []
            for b in msg["content"]:
                if not isinstance(b, dict):
                    continue
                if b.get("type") == "text" and b.get("text", "").strip():
                    blocks.append({"kind": "text", "text": b["text"]})
                elif b.get("type") == "tool_use":
                    res = results.get(b.get("id", ""))
                    blk = {"kind": "tool", "name": b.get("name", ""),
                           "input": _tool_input_summary(b.get("name", ""), b.get("input"))}
                    if res is not None:
                        blk["result"], blk["error"] = res
                    else:
                        blk["result"] = ""
                    blocks.append(blk)
            if blocks:
                turns.append({"role": "assistant", "blocks": blocks, "meta": {}})
    return turns[-limit:]


def delete_session(sid: str) -> dict:
    """Remove a Co-Pilot conversation: its `.started` marker + claude transcript.

    Path-guarded — sid is already UUID-validated by the caller, and we confirm the
    transcript resolves inside the project dir before unlinking.
    """
    removed = []
    marker = config.CONSOLE_DIR / f"{sid}.started"
    try:
        if marker.exists():
            marker.unlink()
            removed.append("marker")
    except Exception:
        pass
    tr = _transcript(sid)
    try:
        if tr.exists() and tr.resolve().parent == config.CLAUDE_PROJECT_DIR.resolve():
            tr.unlink()
            removed.append("transcript")
    except Exception:
        pass
    return {"ok": True, "session_id": sid, "removed": removed}


def available() -> dict:
    """Frontend gate: is the console wired up on this box?"""
    bin_ok = False
    try:
        from pathlib import Path
        import os

        cb = Path(os.environ.get("CLAUDE_BIN", str(Path.home() / ".local/bin/claude")))
        bin_ok = cb.exists()
    except Exception:
        pass
    return {
        "available": config.CONSOLE_SH.exists(),
        "claude_bin": bin_ok,
        "models": list(config.CONSOLE_MODELS.keys()),
        "perm": config.CONSOLE_PERM,
    }

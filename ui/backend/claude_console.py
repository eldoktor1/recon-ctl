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


# --------------------------------------------------------------------------- providers
# Pluggable AI-provider registry. Claude is the ONLY turnkey (fully-wired) entry; other
# vendors are config-scaffolded — the operator brings a launcher via AI_PROVIDER_CMD that
# honours the same positional contract (`<session_id> <message> [model] [perm]`) and streams
# to the spool log. To add a provider WITHOUT touching this file: set AI_PROVIDER=<key>,
# AI_PROVIDER_CMD=<launcher>, AI_PROVIDER_MODELS=<m1,m2>. To add one WITH a first-class entry,
# append a dict of this shape to PROVIDERS:
#   {"key","label","wired"(bool),"models"(list[str]),"build"(fn(sid,msg,model)->argv),
#    "available"(fn()->bool)}
# HARD NOTE: any non-Claude provider must run under its vendor's own cyber-verification /
# authorization program to perform offensive recon at full capability. Claude ships wired;
# everything else is scaffolding until its launcher is supplied + verified.


def _claude_argv(session_id: str, message: str, model: str | None) -> list[str]:
    # positional: <session> <message> [model] [perm]
    return ["bash", str(config.CONSOLE_SH), session_id, message,
            resolve_model(model), config.CONSOLE_PERM]


def _claude_available() -> bool:
    return config.CONSOLE_SH.exists()


def _custom_argv(session_id: str, message: str, model: str | None) -> list[str]:
    """Generic launcher for a config-supplied provider (AI_PROVIDER_CMD). Same positional
    contract as the Claude console script; `model` passes through verbatim (vendor-defined)."""
    return ["bash", config.AI_PROVIDER_CMD, session_id, message, (model or ""), config.CONSOLE_PERM]


def _custom_available() -> bool:
    return bool(config.AI_PROVIDER_CMD)


# Registry — Claude populated + wired; a config-scaffolded provider is synthesised on demand.
PROVIDERS: dict[str, dict] = {
    "claude": {
        "key": "claude", "label": "Claude (Anthropic)", "wired": True,
        "models": list(config.CONSOLE_MODELS.keys()),
        "build": _claude_argv, "available": _claude_available,
    },
}


def _provider(key: str | None = None) -> dict:
    """Resolve the active provider spec. Falls back to the turnkey Claude entry so the console
    NEVER breaks on a mis-set AI_PROVIDER. A configured non-Claude key becomes a scaffolded,
    not-wired entry driven by AI_PROVIDER_CMD."""
    k = (key or config.AI_PROVIDER or "claude").lower()
    if k in PROVIDERS:
        return PROVIDERS[k]
    if config.AI_PROVIDER_CMD:
        return {"key": k, "label": k.title(), "wired": True,
                "models": config.AI_PROVIDER_MODELS or ["default"],
                "build": _custom_argv, "available": _custom_available}
    # unknown key, no launcher configured -> report it (not wired) but drive Claude.
    return {**PROVIDERS["claude"], "key": k, "label": k.title(), "wired": False}


def build_argv(session_id: str, message: str, model: str | None = None) -> list[str]:
    """Build the launch argv for the ACTIVE provider (Claude by default)."""
    p = _provider()
    builder = p.get("build") or _claude_argv
    return builder(session_id, message, model)


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


def _fallback_state() -> dict:
    """Runtime AI-failover state written by scripts/ai_invoke.sh.

    Reflects whether the pipeline is currently running on Claude or has failed over to the
    local Ollama model (WhiteRabbitNeo) because Claude hit a usage limit. Returns safe
    defaults (claude active, no fallback) if the state file is absent/unreadable.
    """
    default = {"active_provider": "claude", "fallback_active": False,
               "fallback_reason": "", "claude_reset_at": None}
    try:
        f = config.STATE_DIR / "ai_fallback.json"
        if not f.exists():
            return default
        d = json.loads(f.read_text())
        active = (d.get("active") or "claude").lower()
        return {
            "active_provider": active,
            "fallback_active": active != "claude",
            "fallback_reason": d.get("reason") or "",
            "claude_reset_at": d.get("claude_reset_at"),
        }
    except Exception:
        return default


def available() -> dict:
    """Frontend gate: is the console wired up, and which AI provider is active?

    `provider`/`providers` let the Settings UI show + (future) switch the model vendor. Claude
    stays the turnkey default; other providers report `wired:false` until their launcher exists.
    `active_provider`/`fallback_active` reflect the RUNTIME failover state (claude vs local
    Ollama) driven by scripts/ai_invoke.sh — distinct from the configured `provider`.
    """
    bin_ok = False
    try:
        from pathlib import Path
        import os

        cb = Path(os.environ.get("CLAUDE_BIN", str(Path.home() / ".local/bin/claude")))
        bin_ok = cb.exists()
    except Exception:
        pass
    active = _provider()
    try:
        active_wired = bool(active.get("wired")) and bool((active.get("available") or (lambda: False))())
    except Exception:
        active_wired = False
    # advertised list = the first-class registry + (if configured) the active custom provider
    listed = {k: {"key": v["key"], "label": v["label"], "wired": bool(v["wired"]),
                  "models": v.get("models", [])} for k, v in PROVIDERS.items()}
    if active["key"] not in listed:
        listed[active["key"]] = {"key": active["key"], "label": active["label"],
                                 "wired": bool(active.get("wired")), "models": active.get("models", [])}
    return {
        "available": config.CONSOLE_SH.exists(),
        "claude_bin": bin_ok,
        "models": active.get("models", list(config.CONSOLE_MODELS.keys())),
        "perm": config.CONSOLE_PERM,
        "provider": active["key"],
        "provider_label": active["label"],
        "provider_wired": active_wired,
        "providers": list(listed.values()),
        **_fallback_state(),
    }

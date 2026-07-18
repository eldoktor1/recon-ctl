"""Mutation + ops wrappers. All d0k-safe (no escalation): findings.db via ACL,
JSONL ledgers, killswitch/maintenance state files. Each returns a small result dict.
"""
from __future__ import annotations

from typing import Any

from . import config
from .runner import run_recon, run_state


async def outcome(fid: int, resolution: str, bounty: float = 0.0) -> dict[str, Any]:
    if resolution not in ("accepted", "dup", "na", "info"):
        return {"ok": False, "error": f"invalid resolution: {resolution}"}
    r = await run_state("outcome", str(fid), resolution, str(bounty))
    return {"ok": r.ok, "result": r.json() or r.stdout.strip(), "error": None if r.ok else r.stderr}


async def note(host: str, text: str) -> dict[str, Any]:
    r = await run_recon("note", host, text)
    return {"ok": r.ok, "result": r.stdout.strip(), "error": None if r.ok else r.stderr}


async def ignore(host: str, reason: str = "manual") -> dict[str, Any]:
    r = await run_recon("ignore", host, reason)
    return {"ok": r.ok, "result": r.stdout.strip(), "error": None if r.ok else r.stderr}


async def mark_fp(host: str, template_id: str) -> dict[str, Any]:
    r = await run_recon("fp", host, template_id)
    return {"ok": r.ok, "result": r.stdout.strip(), "error": None if r.ok else r.stderr}


async def scope(host: str) -> dict[str, Any]:
    r = await run_recon("scope", host, timeout=45)
    return {"ok": r.ok, "result": r.stdout.strip(), "error": None if r.ok else r.stderr}


async def rate(profile: str) -> dict[str, Any]:
    r = await run_recon("rate", profile)
    return {"ok": r.ok, "result": r.stdout.strip(), "error": None if r.ok else r.stderr}


async def maintenance(mode: str) -> dict[str, Any]:
    if mode not in ("on", "off", "status"):
        return {"ok": False, "error": "mode must be on|off|status"}
    r = await run_recon("maintenance", mode)
    return {"ok": r.ok, "result": r.stdout.strip(), "error": None if r.ok else r.stderr}


def killswitch_set(lane: str, on: bool) -> dict[str, Any]:
    """Create/remove a per-lane killswitch file (state/kill/v2_<lane>)."""
    lane = lane.strip()
    if lane.startswith("v2_"):          # strip the prefix, not the char-set
        lane = lane[3:]
    if not lane or not lane.replace("_", "").replace("-", "").isalnum():
        return {"ok": False, "error": "invalid lane name"}
    path = config.KILL_DIR / f"v2_{lane}"
    try:
        config.KILL_DIR.mkdir(parents=True, exist_ok=True)
        if on:
            path.write_text("ui\n")
        elif path.exists():
            path.unlink()
        return {"ok": True, "lane": lane, "killed": on}
    except Exception as e:
        return {"ok": False, "error": str(e)}

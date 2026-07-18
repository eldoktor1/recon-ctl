"""Async subprocess wrappers around the existing CLI surface.

We shell out to `bash recon_ctl.sh <sub>` (NOT the zsh recon-* aliases, which
404 under bash) and to `python3 engine/state.py <cmd>` for JSON. Nothing here
reimplements pipeline logic — it wraps it.
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass

from . import config


@dataclass
class CmdResult:
    ok: bool
    returncode: int
    stdout: str
    stderr: str

    def json(self):
        try:
            return json.loads(self.stdout)
        except Exception:
            return None


async def _run(argv: list[str], timeout: float = 60.0, cwd: str | None = None) -> CmdResult:
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd or str(config.REPO_DIR),
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        return CmdResult(False, 124, "", f"timeout after {timeout}s")
    return CmdResult(
        proc.returncode == 0,
        proc.returncode or 0,
        (out or b"").decode("utf-8", "replace"),
        (err or b"").decode("utf-8", "replace"),
    )


async def run_recon(sub: str, *args: str, timeout: float = 60.0) -> CmdResult:
    """`recon <sub> [args]` via the canonical bash dispatcher."""
    return await _run(["bash", str(config.RECON_CTL), sub, *map(str, args)], timeout=timeout)


async def run_state(cmd: str, *args: str, timeout: float = 30.0) -> CmdResult:
    """`python3 engine/state.py <cmd> [args]` — most emit JSON."""
    return await _run(["python3", str(config.STATE_PY), cmd, *map(str, args)], timeout=timeout)


async def run_observability(*args: str, timeout: float = 30.0) -> CmdResult:
    return await _run(["python3", str(config.OBSERVABILITY_PY), *map(str, args)], timeout=timeout)

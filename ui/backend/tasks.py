"""Background task manager for long-running, on-demand lanes (hunts, verify).

Each task is a detached async subprocess whose stdout/stderr is captured into a
ring buffer and streamed to WebSocket subscribers. Read-only w.r.t. the pipeline
except that it *runs pipeline commands* the operator explicitly launches (gated by
token + confirm + the fail-closed VPN check in the route layer).
"""
from __future__ import annotations

import asyncio
import itertools
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from . import config

_ids = itertools.count(1)


@dataclass
class Task:
    id: int
    label: str
    argv: list[str]
    state: str = "running"          # running | done | failed | stopped
    returncode: int | None = None
    lines: deque = field(default_factory=lambda: deque(maxlen=2000))
    subscribers: set[asyncio.Queue] = field(default_factory=set)
    proc: asyncio.subprocess.Process | None = None
    started_at: float = 0.0

    def snapshot(self) -> dict[str, Any]:
        return {
            "id": self.id, "label": self.label, "state": self.state,
            "returncode": self.returncode, "line_count": len(self.lines),
            "argv": self.argv,
        }


class TaskManager:
    def __init__(self) -> None:
        self.tasks: dict[int, Task] = {}

    def list(self) -> list[dict[str, Any]]:
        return [t.snapshot() for t in sorted(self.tasks.values(), key=lambda x: -x.id)]

    def get(self, tid: int) -> Task | None:
        return self.tasks.get(tid)

    async def spawn(self, label: str, argv: list[str]) -> Task:
        import time as _t

        tid = next(_ids)
        # started_at needs a wall clock; time.time is fine here (not a workflow script)
        t = Task(id=tid, label=label, argv=argv, started_at=_t.time())
        self.tasks[tid] = t
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=str(config.REPO_DIR),
        )
        t.proc = proc
        asyncio.create_task(self._pump(t))
        return t

    async def _pump(self, t: Task) -> None:
        assert t.proc and t.proc.stdout
        try:
            async for raw in t.proc.stdout:
                line = raw.decode("utf-8", "replace").rstrip("\n")
                t.lines.append(line)
                for q in list(t.subscribers):
                    try:
                        q.put_nowait(line)
                    except Exception:
                        pass
            await t.proc.wait()
            t.returncode = t.proc.returncode
            t.state = "done" if t.proc.returncode == 0 else "failed"
        except Exception as e:
            t.state = "failed"
            t.lines.append(f"[task error] {e}")
        finally:
            for q in list(t.subscribers):
                try:
                    q.put_nowait(None)  # sentinel: stream closed
                except Exception:
                    pass

    async def stop(self, tid: int) -> bool:
        t = self.tasks.get(tid)
        if not t or not t.proc or t.state != "running":
            return False
        try:
            t.proc.terminate()
            try:
                await asyncio.wait_for(t.proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                t.proc.kill()
            t.state = "stopped"
            return True
        except Exception:
            return False

    def subscribe(self, tid: int) -> asyncio.Queue | None:
        t = self.tasks.get(tid)
        if not t:
            return None
        q: asyncio.Queue = asyncio.Queue()
        # replay buffered lines first
        for line in list(t.lines):
            q.put_nowait(line)
        if t.state != "running":
            q.put_nowait(None)
        else:
            t.subscribers.add(q)
        return q

    def unsubscribe(self, tid: int, q: asyncio.Queue) -> None:
        t = self.tasks.get(tid)
        if t:
            t.subscribers.discard(q)


manager = TaskManager()

# On-demand lanes launchable from Hunt Control. (label -> recon subcommand + whether
# it sends target traffic, so the route layer can apply the fail-closed VPN gate.)
LANES: dict[str, dict[str, Any]] = {
    "hunter":   {"sub": "hunter",  "target": True,  "desc": "Claude IDOR/BAC hunter (per-target reasoning loop)"},
    "graphql":  {"sub": "graphql", "target": True,  "desc": "GraphQL introspection → schema worklist"},
    "wcd":      {"sub": "wcd",     "target": True,  "desc": "Web-cache deception/poisoning detect (safe, cache-busted)"},
    "buckets":  {"sub": "buckets", "target": True,  "desc": "Cloud-bucket exposure (provenance-seeded, read-only)"},
    "blindxss": {"sub": "blindxss","target": True,  "desc": "Blind/stored-XSS beacon plant + correlate"},
    "permute":  {"sub": "permute", "target": False, "desc": "Permutation-DNS (public resolvers, not target traffic)"},
    "uncover":  {"sub": "uncover", "target": False, "desc": "Surface expansion (Shodan/Censys dorks, budget-capped)"},
    "research": {"sub": "research","target": False, "desc": "Standing Claude research routine (web, not target)"},
    "portscan": {"sub": "portscan","target": True,  "desc": "Critical-port scan (reconrun/Mullvad)"},
}

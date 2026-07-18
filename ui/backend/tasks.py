"""Background task manager for on-demand lanes (hunts, verify).

The web process is sandboxed and cannot escalate, so it does NOT run lanes
directly. It writes a job to the spool (config.HUNT_*) for the unsandboxed
recon-ui-runner service to execute, then tails the runner's output file and
streams it to WebSocket subscribers. The public interface (spawn/list/get/stop/
subscribe) is unchanged.
"""
from __future__ import annotations

import asyncio
import itertools
import json
import time
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
    subscribers: set = field(default_factory=set)
    started_at: float = 0.0
    stop_requested: bool = False

    def snapshot(self) -> dict[str, Any]:
        return {"id": self.id, "label": self.label, "state": self.state,
                "returncode": self.returncode, "line_count": len(self.lines), "argv": self.argv}


class TaskManager:
    def __init__(self) -> None:
        self.tasks: dict[int, Task] = {}

    def list(self) -> list[dict[str, Any]]:
        return [t.snapshot() for t in sorted(self.tasks.values(), key=lambda x: -x.id)]

    def get(self, tid: int) -> Task | None:
        return self.tasks.get(tid)

    def _prune(self, keep: int = 60) -> None:
        if len(self.tasks) <= keep:
            return
        finished = sorted((t for t in self.tasks.values() if t.state != "running"), key=lambda x: x.id)
        for t in finished[: len(self.tasks) - keep]:
            self.tasks.pop(t.id, None)
            for p in (config.HUNT_OUT / f"{t.id}.log", config.HUNT_STATUS / f"{t.id}.json"):
                try: p.unlink(missing_ok=True)
                except Exception: pass

    async def spawn(self, label: str, argv: list[str]) -> Task:
        for d in (config.HUNT_QUEUE, config.HUNT_OUT, config.HUNT_STATUS, config.HUNT_STOP):
            d.mkdir(parents=True, exist_ok=True)
        tid = next(_ids)
        t = Task(id=tid, label=label, argv=argv, started_at=time.time())
        self.tasks[tid] = t
        # clear any stale spool files for this id (ids reset on web restart)
        for p in (config.HUNT_OUT / f"{tid}.log", config.HUNT_STATUS / f"{tid}.json"):
            try: p.unlink(missing_ok=True)
            except Exception: pass
        (config.HUNT_QUEUE / f"{tid}.job").write_text(json.dumps({"id": tid, "argv": argv, "label": label}))
        asyncio.create_task(self._tail(t))
        self._prune()
        return t

    async def _tail(self, t: Task) -> None:
        logp = config.HUNT_OUT / f"{t.id}.log"
        statusp = config.HUNT_STATUS / f"{t.id}.json"
        offset = 0
        buf = b""
        waited = 0.0

        def emit(line: str):
            t.lines.append(line)
            for q in list(t.subscribers):
                try: q.put_nowait(line)
                except Exception: pass

        def read_new():
            nonlocal offset, buf
            if not logp.exists():
                return
            try:
                with logp.open("rb") as f:
                    f.seek(offset)
                    chunk = f.read()
                    offset += len(chunk)
            except Exception:
                return
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                emit(line.decode("utf-8", "replace"))

        try:
            while True:
                read_new()
                st = None
                if statusp.exists():
                    try: st = json.loads(statusp.read_text())
                    except Exception: st = None
                if st and st.get("state") in ("done", "failed", "stopped"):
                    read_new()
                    if buf:
                        emit(buf.decode("utf-8", "replace")); buf = b""
                    t.returncode = st.get("returncode")
                    if t.state != "stopped":
                        t.state = st["state"]
                    break
                # runner missing? no status + no log after a grace period
                waited += 0.4
                if waited > 12 and not statusp.exists() and not logp.exists():
                    emit("[runner not available — install it: recon ui install]")
                    t.state = "failed"; t.returncode = -1
                    break
                await asyncio.sleep(0.4)
        finally:
            for q in list(t.subscribers):
                try: q.put_nowait(None)
                except Exception: pass

    async def stop(self, tid: int) -> bool:
        t = self.tasks.get(tid)
        if not t or t.state != "running":
            return False
        t.stop_requested = True
        t.state = "stopped"
        try:
            config.HUNT_STOP.mkdir(parents=True, exist_ok=True)
            (config.HUNT_STOP / str(tid)).write_text("stop")
            return True
        except Exception:
            return False

    def subscribe(self, tid: int):
        t = self.tasks.get(tid)
        if not t:
            return None
        q: asyncio.Queue = asyncio.Queue()
        for line in list(t.lines):
            q.put_nowait(line)
        if t.state != "running":
            q.put_nowait(None)
        else:
            t.subscribers.add(q)
        return q

    def unsubscribe(self, tid: int, q) -> None:
        t = self.tasks.get(tid)
        if t:
            t.subscribers.discard(q)


manager = TaskManager()

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

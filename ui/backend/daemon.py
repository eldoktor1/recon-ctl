"""Daemon + egress + telemetry status, aggregated from local state files.

Read-only: PID/heartbeat files, vpn_down marker, killswitch dir, self-audit JSON.
Never issues target traffic; never touches egress.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

from . import config


def _pid_alive(pid: int) -> bool:
    if not pid or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False           # no such process => dead
    except PermissionError:
        return True            # exists but owned by another user
    except Exception:
        return False


def daemon_status() -> dict[str, Any]:
    pid, alive, uptime = None, False, None
    try:
        if config.DAEMON_PID.exists():
            pid = int(config.DAEMON_PID.read_text().strip() or 0)
            alive = _pid_alive(pid)
            uptime = int(time.time() - config.DAEMON_PID.stat().st_mtime) if alive else None
    except Exception:
        pass
    # count supervised lane procs (best effort)
    lanes = _proc_count("recon_daemon.sh")
    return {
        "pid": pid,
        "alive": alive,
        "uptime_sec": uptime,
        "lane_procs": lanes,
        "maintenance": (config.STATE_DIR / "maintenance").exists(),
        "disabled": (config.STATE_DIR / "daemon_disabled").exists(),
        "keepalive_tripped": (config.STATE_DIR / "keepalive_tripped").exists(),
    }


def _proc_count(needle: str) -> int:
    try:
        import subprocess

        out = subprocess.run(["pgrep", "-fc", needle], capture_output=True, text=True, timeout=5)
        return int((out.stdout or "0").strip() or 0)
    except Exception:
        return 0


def vpn_status() -> dict[str, Any]:
    down = config.VPN_DOWN.exists()
    reason = None
    if down:
        try:
            reason = config.VPN_DOWN.read_text().strip()[:200] or "vpn_down marker present"
        except Exception:
            reason = "vpn_down marker present"
    return {"up": not down, "down": down, "reason": reason}


def killswitches() -> list[dict[str, Any]]:
    out = []
    try:
        if config.KILL_DIR.exists():
            for p in sorted(config.KILL_DIR.iterdir()):
                if p.is_file():
                    out.append({"lane": p.name, "killed": True,
                                "since": int(p.stat().st_mtime)})
    except Exception:
        pass
    return out


def selfaudit() -> dict[str, Any] | None:
    try:
        if config.SELFAUDIT_JSON.exists():
            data = json.loads(config.SELFAUDIT_JSON.read_text())
            data["_age_sec"] = int(time.time() - config.SELFAUDIT_JSON.stat().st_mtime)
            return data
    except Exception:
        pass
    return None


def queue_depth() -> dict[str, int]:
    out = {}
    qroot = config.BASE_DIR / "queue"
    for name in ("inbox", "processing", "done"):
        d = qroot / name
        try:
            out[name] = sum(1 for _ in d.iterdir()) if d.exists() else 0
        except Exception:
            out[name] = 0
    return out


def tail_file(path: Path, n: int = 200) -> list[str]:
    try:
        if not path.exists():
            return []
        with path.open("rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            block = min(size, n * 400)
            f.seek(size - block)
            data = f.read().decode("utf-8", "replace")
        return data.splitlines()[-n:]
    except Exception:
        return []

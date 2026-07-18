"""recon-ui hunt runner — executes lane jobs the web process cannot run itself.

The web service is sandboxed (NoNewPrivileges) so it can't sudo to reconrun for
target-facing lanes. This runner is a SEPARATE, unsandboxed systemd user service
that runs lanes in a daemon-equivalent environment. It consumes a file spool:

  queue/<id>.job   {id, argv, label}   (written by the web process)
  out/<id>.log     combined stdout+stderr (tailed by the web process over WS)
  status/<id>.json {state, pid, returncode}
  stop/<id>        touch-file -> terminate that job

Runs as d0k; sudo -> reconrun works because this service is not sandboxed.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

from . import config

RUNNING: dict[str, tuple] = {}   # id -> (Popen, logfile handle)


def _ensure_dirs() -> None:
    for d in (config.HUNT_QUEUE, config.HUNT_OUT, config.HUNT_STATUS, config.HUNT_STOP):
        d.mkdir(parents=True, exist_ok=True)


def _write_status(jid: str, **kw) -> None:
    p = config.HUNT_STATUS / f"{jid}.json"
    cur: dict = {}
    if p.exists():
        try:
            cur = json.loads(p.read_text())
        except Exception:
            pass
    cur.update(kw)
    p.write_text(json.dumps(cur))


def _start(job: dict) -> None:
    jid = str(job["id"])
    argv = job["argv"]
    if not isinstance(argv, list) or not argv:
        _write_status(jid, state="failed", returncode=-1)
        return
    logf = open(config.HUNT_OUT / f"{jid}.log", "ab", buffering=0)
    try:
        proc = subprocess.Popen(argv, stdout=logf, stderr=subprocess.STDOUT,
                                cwd=str(config.REPO_DIR), start_new_session=True)
    except Exception as e:
        logf.write(f"[runner] failed to start: {e}\n".encode())
        logf.close()
        _write_status(jid, state="failed", returncode=-1)
        return
    RUNNING[jid] = (proc, logf)
    _write_status(jid, state="running", pid=proc.pid)


def _poll() -> None:
    # 1. new jobs
    for jf in sorted(config.HUNT_QUEUE.glob("*.job")):
        try:
            job = json.loads(jf.read_text())
        except Exception:
            jf.unlink(missing_ok=True)
            continue
        jf.unlink(missing_ok=True)
        _start(job)

    # 2. stop signals
    for sf in config.HUNT_STOP.glob("*"):
        jid = sf.name
        sf.unlink(missing_ok=True)
        ent = RUNNING.get(jid)
        if ent:
            try:
                ent[0].terminate()
            except Exception:
                pass

    # 3. reap finished
    done = []
    for jid, (proc, logf) in RUNNING.items():
        rc = proc.poll()
        if rc is not None:
            try:
                logf.close()
            except Exception:
                pass
            _write_status(jid, state=("done" if rc == 0 else "failed"), returncode=rc)
            done.append(jid)
    for jid in done:
        RUNNING.pop(jid, None)


def main() -> int:
    _ensure_dirs()
    while True:
        try:
            _poll()
        except Exception as e:  # never die on a transient error
            sys.stderr.write(f"[runner] poll error: {e}\n")
        time.sleep(0.5)


if __name__ == "__main__":
    raise SystemExit(main())

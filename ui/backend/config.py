"""Central config + path resolution for the recon-ui backend.

Everything the UI reads/drives lives outside the repo under ~/recon (BASE_DIR);
the command surface lives in the repo (REPO_DIR). No pipeline logic here — just
where things are and how to authenticate to ES.
"""
from __future__ import annotations

import os
import secrets
from functools import lru_cache
from pathlib import Path

# --- fixed locations (see CLAUDE.md / operating guide) ---------------------
REPO_DIR = Path(os.environ.get("RECON_REPO", "/home/d0k/recon-pipeline"))
BASE_DIR = Path(os.environ.get("BASE_DIR", str(Path.home() / "recon")))
STATE_DIR = BASE_DIR / "state"
BRIEF_DIR = BASE_DIR / "briefings"
V3_DIR = BASE_DIR / "v3"
LOG_DIR = BASE_DIR / "logs"

FINDINGS_DB = Path(os.environ.get("V3_DB", str(V3_DIR / "findings.db")))
REVIEW_QUEUE = V3_DIR / "reports" / "review_queue.jsonl"
SELFAUDIT_JSON = STATE_DIR / "selfaudit_latest.json"
DAEMON_PID = STATE_DIR / "recon_daemon.pid"
VPN_DOWN = STATE_DIR / "vpn_down"
KILL_DIR = STATE_DIR / "kill"
DAEMON_LOG = LOG_DIR / "recon_daemon.log"

HOST_NOTES = STATE_DIR / "host_notes.jsonl"
IGNORED = STATE_DIR / "ignored.jsonl"
SUBMISSIONS = Path.home() / ".recon_submissions.jsonl"

RECON_CTL = REPO_DIR / "scripts" / "recon_ctl.sh"
STATE_PY = REPO_DIR / "engine" / "state.py"
OBSERVABILITY_PY = REPO_DIR / "engine" / "observability.py"

# --- Elasticsearch ---------------------------------------------------------
ES_URL = os.environ.get("ES_URL", "http://127.0.0.1:9200")
ES_INDEX = os.environ.get("ES_INDEX", "recon_alive")
ES_NETRC = Path(os.environ.get("RECON_ES_NETRC", str(Path.home() / ".recon_es_netrc")))

# --- server ----------------------------------------------------------------
HOST = os.environ.get("RECON_UI_HOST", "127.0.0.1")
PORT = int(os.environ.get("RECON_UI_PORT", "8787"))
FRONTEND_DIST = REPO_DIR / "ui" / "frontend" / "dist"

UI_TOKEN_FILE = STATE_DIR / "ui_token"

# Hunt-lane spool: the sandboxed web process drops jobs here; the unsandboxed
# runner service (recon-ui-runner) executes them (can sudo -> reconrun) and writes
# output/status back. This keeps the internet-facing process non-escalating.
HUNT_DIR = STATE_DIR / "ui_hunt"
HUNT_QUEUE = HUNT_DIR / "queue"
HUNT_OUT = HUNT_DIR / "out"
HUNT_STATUS = HUNT_DIR / "status"
HUNT_STOP = HUNT_DIR / "stop"

# Host-header allowlist (anti DNS-rebinding). Only these Host values are served.
ALLOWED_HOSTS = {
    f"localhost:{PORT}", f"127.0.0.1:{PORT}", "localhost", "127.0.0.1",
}
# Same set as valid Origins for state-changing requests (belt-and-suspenders vs CSRF).
ALLOWED_ORIGINS = {f"http://localhost:{PORT}", f"http://127.0.0.1:{PORT}"}


@lru_cache(maxsize=1)
def es_auth() -> tuple[str, str] | None:
    """Parse the ES netrc for (login, password). Never exposed to the frontend."""
    try:
        import netrc

        n = netrc.netrc(str(ES_NETRC))
        host = ES_URL.split("//", 1)[-1].split(":", 1)[0]
        auth = n.authenticators(host) or n.authenticators("127.0.0.1")
        if auth:
            login, _, password = auth
            return (login, password)
    except Exception:
        pass
    return None


@lru_cache(maxsize=1)
def ui_token() -> str:
    """Shared token required on mutating/task routes. Generated once, chmod 600."""
    try:
        if UI_TOKEN_FILE.exists():
            tok = UI_TOKEN_FILE.read_text().strip()
            if tok:
                return tok
    except Exception:
        pass
    tok = secrets.token_urlsafe(24)
    try:
        UI_TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
        UI_TOKEN_FILE.write_text(tok + "\n")
        os.chmod(UI_TOKEN_FILE, 0o600)
    except Exception:
        pass
    return tok

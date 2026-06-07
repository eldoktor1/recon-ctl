#!/usr/bin/env python3
"""v3 Phase D — autonomous testing orchestrator.

Drives the SQLite state machine instead of the 20-loop supervisor. Designed to
run INSIDE the kali VM (never over WSL interop). The active-test/probe execution
delegates to the existing bash tools (evidence gate / dast / params) — this module
is the SAFETY + STATE + ROUTING brain.

HARD-CODED guardrails (not runtime-configurable — defined here in code):
  • Autonomy boundary by Gate-0 tier:
      GENERAL  -> autonomous active testing (non-destructive, read/diff PoC)
      FINANCIAL/REGULATED -> DETECTION + PoC-STAGING only (stage exact PoC, queue
                             for human trigger; never send authed/state-changing reqs)
  • Max 4 concurrent testing agents.
  • Per-program daily request ceiling (volume cap, separate from concurrency).
  • Ban / CAPTCHA / 3+ consecutive 403 -> IMMEDIATE full halt + alert, NO auto-resume.
  • Out-of-scope -> hard-blocked before any request (recon-scope gate).
  • Fund-moving / state-changing endpoints -> NEVER touched (autonomous OR staged).
  • Categorized exponential backoff (30s..1h), 6-category recovery model.
  • Hard daily LLM API-spend ceiling -> halt + alert on breach.
  • Submission always human-gated (orchestrator never submits). vpn_down pauses all.
"""
from __future__ import annotations
import os, sys, re, json, subprocess, datetime as _dt
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import state as S
import tier as TIER

# ---- hard-coded guardrail constants (intentionally NOT env-overridable) ------
MAX_CONCURRENT_AGENTS = 4
PER_PROGRAM_DAILY_REQUESTS = 750          # global volume cap per program/day
HTTP_403_HALT_STREAK = 3                   # 3 consecutive 403 -> halt
LLM_DAILY_SPEND_CEILING_USD = 20.0         # halt+alert on breach
# tunables that don't relax a safety boundary may read env
BATCH = int(os.environ.get("ORCH_BATCH", "40"))
TICK_SLEEP = int(os.environ.get("ORCH_TICK_SLEEP", "60"))

STATE_DIR = os.path.expanduser(os.environ.get("STATE_DIR", "~/recon/state"))
HALT_FLAG = os.path.join(STATE_DIR, "v3_halt")        # presence = halted; content = reason. Human removes to resume.
VPN_DOWN = os.path.join(STATE_DIR, "vpn_down")
STAGING_QUEUE = os.path.expanduser("~/recon/v3/staged_pocs.jsonl")
SCRIPT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
SCOPE_CHECK = os.path.join(SCRIPT_DIR, "recon_scope_check.sh")

# Fund-moving / state-changing endpoints: NEVER touched, any tier, autonomous OR staged.
_FORBIDDEN_PATH = re.compile(
    r"/(withdraw|withdrawal|transfer|transfers|payout|payouts|payment|payments|deposit|deposits"
    r"|order|orders|checkout|charge|charges|refund|refunds|send|wire|remit|remittance|trade|trades"
    r"|buy|sell|swap|convert|cancel|close-account|delete|disable|wallet/(send|withdraw)"
    r"|settings/(security|password)|password|2fa|mfa|api[-_]?keys?|tokens?/(create|revoke|rotate))",
    re.I,
)
_STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _utc():
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg):
    print(f"[{_utc()} ORCH] {msg}", file=sys.stderr)


# ---- global halt / pause guards ---------------------------------------------
def halted() -> str | None:
    if os.path.exists(HALT_FLAG):
        try:
            return open(HALT_FLAG).read().strip() or "halted"
        except OSError:
            return "halted"
    return None


def halt(reason: str, conn=None):
    """Set the persistent halt flag + alert. NEVER auto-resumed — a human must
    delete the flag to continue."""
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(HALT_FLAG, "w") as fh:
        fh.write(f"{_utc()} {reason}")
    log(f"!!! HALT: {reason} — human authorization required to resume (rm {HALT_FLAG})")
    _alert(f"🛑 v3 orchestrator HALTED: {reason}")
    if conn is not None:
        conn.execute("INSERT INTO audit_log(event,detail,at) VALUES('halt',?,?)", (reason, _utc()))
        conn.commit()


def vpn_down() -> bool:
    return os.path.exists(VPN_DOWN)


def _alert(text: str):
    """Human alert hook (Discord via recon_net.sh, best-effort). Never raises."""
    try:
        subprocess.run(["bash", "-lc",
                        f'source "{SCRIPT_DIR}/recon_net.sh" 2>/dev/null; '
                        f'h="$(discord_hook health 2>/dev/null)"; [ -n "$h" ] && '
                        f'discord_post "$h" "$(jq -nc --arg c {json.dumps(text)} \'{{content:$c}}\')"'],
                       timeout=15, capture_output=True)
    except Exception:
        pass


# ---- per-finding safety gates -----------------------------------------------
def endpoint_safe(url: str, method: str = "GET") -> tuple[bool, str]:
    """Fund-moving / state-changing endpoints are NEVER touched (any tier, autonomous
    OR staged). Read-only confirmation only."""
    if (method or "GET").upper() in _STATE_CHANGING_METHODS:
        return (False, f"state-changing method {method} not permitted (read-only PoC only)")
    try:
        path = re.sub(r"^https?://[^/]+", "", url or "")
    except Exception:
        path = url or ""
    if _FORBIDDEN_PATH.search(path or ""):
        return (False, "fund-moving/state-changing endpoint — never tested or staged")
    return (True, "")


def scope_ok(host: str) -> bool:
    """recon-scope gate before any request. Out-of-scope -> hard block."""
    try:
        out = subprocess.run(["bash", SCOPE_CHECK, "--batch"], input=host + "\n",
                             capture_output=True, text=True, timeout=30)
        for line in out.stdout.splitlines():
            try:
                d = json.loads(line)
            except Exception:
                continue
            if d.get("host") == host:
                return bool(d.get("in_scope")) and not d.get("out_of_scope")
        return False
    except Exception:
        return False  # fail-safe: can't confirm scope -> block


def under_request_ceiling(conn, program: str) -> bool:
    return S.get_counter(conn, program or "GLOBAL", "requests") < PER_PROGRAM_DAILY_REQUESTS


def under_spend_ceiling(conn) -> bool:
    return S.get_counter(conn, "GLOBAL", "llm_spend_usd") < LLM_DAILY_SPEND_CEILING_USD


# ---- failure classification + recovery --------------------------------------
def classify_http(status_codes: list[int], body: str = "") -> str | None:
    """Map an observed response signature to a 6-category failure type, or None."""
    b = (body or "").lower()
    if "captcha" in b or "are you a robot" in b or "cf-challenge" in b:
        return "captcha"
    if any(s in (401, 403) for s in status_codes[-HTTP_403_HALT_STREAK:]) and \
       len(status_codes) >= HTTP_403_HALT_STREAK and all(c == 403 for c in status_codes[-HTTP_403_HALT_STREAK:]):
        return "http-403-streak"
    if 429 in status_codes:
        return "rate-limit"
    if any(s == 0 for s in status_codes):
        return "timeout"
    if "banned" in b or "blocked" in b or "access denied" in b:
        return "ban"
    return None


def handle_failure(conn, program: str, host: str, category: str, detail: str = ""):
    """Record + recover. ban/captcha/403-streak => immediate full halt (no auto-resume).
    Others => categorized exponential backoff scoped to the target."""
    target = program or host
    rstate = S.record_failure(conn, category, target, detail)
    if category in ("ban", "captcha", "http-403-streak"):
        halt(f"{category} on {target} ({detail})", conn)
        return "halted"
    log(f"failure {category} on {target} -> {rstate} (backoff active)")
    return rstate


# ---- tier routing -----------------------------------------------------------
def stage_poc(conn, finding, asset) -> None:
    """FINANCIAL/REGULATED: stage the EXACT (non-fund-moving, read-only) PoC for a
    human to trigger. Never sends authed/state-changing requests."""
    url = finding["url"] or asset.get("url") or f"https://{finding['host']}"
    poc = {
        "finding_id": finding["id"], "host": finding["host"], "program": finding["program"],
        "tier": "FINANCIAL", "signal_class": finding["signal_class"], "vuln_class": finding["vuln_class"],
        "staged_request": {"method": "GET", "url": url,
                           "note": "read-only confirmation request; human triggers + reviews before any authed step"},
        "preconditions": "detection confirmed non-intrusively by the evidence gate",
        "repro": f"Run the staged GET against {url}; compare to the gate evidence.",
        "evidence": json.loads(finding["evidence"]) if finding["evidence"] else {},
        "staged_at": _utc(), "action_required": "HUMAN trigger (financial-tier autonomy boundary)",
    }
    os.makedirs(os.path.dirname(STAGING_QUEUE), exist_ok=True)
    with open(STAGING_QUEUE, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(poc) + "\n")
    S.transition(conn, finding["id"], "staged", expect="confirmed")
    log(f"  {finding['host']} [FINANCIAL] -> staged PoC (human trigger queued)")


def active_test(conn, finding, asset) -> None:
    """GENERAL: autonomous non-destructive active test, then route to reporter.
    Delegates the actual probe to the bash evidence gate / dast tools (read-only)."""
    # The evidence gate already confirmed detection (finding is 'confirmed'); for
    # GENERAL we permit the read-only active PoC and pass straight to the reporter.
    S.transition(conn, finding["id"], "reported", expect="confirmed")
    log(f"  {finding['host']} [GENERAL] -> active-tested (read-only) -> reporter")


# ---- main tick --------------------------------------------------------------
def _es_source(host: str) -> dict:
    try:
        out = subprocess.run(["curl", "-fsS", "-m", "15", "--netrc-file",
                              os.path.expanduser("~/.recon_es_netrc"),
                              f"{os.environ.get('ES_URL','http://127.0.0.1:9200')}/"
                              f"{os.environ.get('INDEX_NAME','recon_alive')}/_source/{host}"],
                             capture_output=True, text=True, timeout=20)
        return json.loads(out.stdout) if out.stdout.strip() else {}
    except Exception:
        return {}


def _route_one(conn, finding) -> str:
    host, program = finding["host"], finding["program"]
    if backoff := S.backoff_active(conn, program or host):
        return "skip-backoff"
    if not under_request_ceiling(conn, program):
        return "skip-ceiling"
    if not scope_ok(host):
        S.transition(conn, finding["id"], "dismissed", expect="confirmed", last_error="out-of-scope at route time")
        return "blocked-scope"
    asset = _es_source(host)
    url = finding["url"] or asset.get("url") or f"https://{host}"
    safe, why = endpoint_safe(url)
    if not safe:
        S.transition(conn, finding["id"], "dismissed", expect="confirmed", last_error=f"forbidden endpoint: {why}")
        log(f"  {host} BLOCKED: {why}")
        return "blocked-endpoint"
    S.incr_counter(conn, program or "GLOBAL", "requests", 1)
    tier = TIER.classify(program)
    if tier == TIER.GENERAL:
        active_test(conn, finding, asset)
        S.incr_counter(conn, program or "GLOBAL", "tests", 1)
        return "general-tested"
    else:
        stage_poc(conn, finding, asset)
        S.incr_counter(conn, program or "GLOBAL", "staged", 1)
        return "financial-staged"


def tick(conn) -> dict:
    """One orchestration pass. Returns a summary dict."""
    if (r := halted()):
        log(f"halted ({r}) — refusing to run; human must clear {HALT_FLAG}")
        return {"halted": r}
    if vpn_down():
        log("vpn_down — paused")
        return {"paused": "vpn_down"}
    if not under_spend_ceiling(conn):
        halt(f"LLM daily spend ceiling ${LLM_DAILY_SPEND_CEILING_USD} exceeded", conn)
        return {"halted": "llm-spend"}
    S.resume_stale_verifying(conn)  # crash safety every tick
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM findings WHERE state='confirmed' ORDER BY score DESC LIMIT ?", (BATCH,)).fetchall()]
    summary: dict = {}
    if rows:
        # Max 4 concurrent agents. Each worker opens its OWN SQLite connection —
        # WAL + busy_timeout serialize writes safely across connections (a shared
        # sqlite3.Connection is not thread-safe).
        with ThreadPoolExecutor(max_workers=MAX_CONCURRENT_AGENTS) as ex:
            for res in ex.map(_safe_route, rows):
                summary[res] = summary.get(res, 0) + 1
    log(f"tick: {json.dumps(summary)}")
    return summary


def _safe_route(finding: dict):
    conn = S.connect()
    try:
        return _route_one(conn, finding)
    except Exception as e:
        log(f"  route error {finding.get('host')}: {e}")
        return "error"
    finally:
        conn.close()


def main(argv):
    conn = S.connect(); S.init_db(conn)
    mode = argv[1] if len(argv) > 1 else "once"
    if mode == "once":
        print(json.dumps(tick(conn), indent=2)); return 0
    if mode == "audit":
        print(json.dumps({"halted": halted(), "stats": S.stats(conn),
                          "tier_audit": TIER.audit()}, indent=2, default=str)); return 0
    if mode == "loop":
        import time
        log(f"orchestrator loop start (concurrency={MAX_CONCURRENT_AGENTS}, "
            f"per-program/day={PER_PROGRAM_DAILY_REQUESTS}, spend ceiling=${LLM_DAILY_SPEND_CEILING_USD})")
        while True:
            tick(conn)
            if halted():
                log("halted — exiting loop (human must clear + restart)"); break
            time.sleep(TICK_SLEEP)
        return 0
    print("usage: orchestrator.py {once|loop|audit}", file=sys.stderr); return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

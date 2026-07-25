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


# --------------------------------------------------------------------------- lane registry
# Canonical daemon-lane list (derived from scripts/recon_daemon.sh + docs/CLAUDE_OPERATING_GUIDE.md).
# This is the FULL C2 view of every supervised lane (~50), not just the 9 on-demand LANES in
# tasks.py. Each entry: (lane_token, description, target-facing?, script_stem). `lane_token` is the
# killswitch name (state/kill/v2_<token>) where one exists; `script_stem` is the process name used
# for best-effort running detection. Idle lanes still appear (killed/running just report state).
LANE_REGISTRY: list[tuple[str, str, bool, str]] = [
    # --- discovery / validation pipeline ---
    ("validate",       "Asset validation pipeline (httpx→ES→triage)",            True,  "recon_validate.sh"),
    ("discovery",      "Subdomain discovery (subfinder/CT/chaos)",               True,  "recon_discovery.sh"),
    ("scope_watch",    "Scope watcher (program scope diff)",                     False, "recon_scope_watch.sh"),
    ("scope",          "Scope DB refresh (per-asset pays/eligibility)",          False, "recon_scope_db.sh"),
    ("true_fresh",     "Fresh-blood feed (CT logs + crt.sh, renewals-filtered)", False, "recon_true_fresh.sh"),
    ("hot_seed",       "Hot-seed high-value hosts into the queue",               False, "recon_hot_seed.sh"),
    ("restale",        "Stale P0/P1 re-validate (re-queue aged hosts)",          False, "recon_restale.sh"),
    ("permute",        "Permutation-DNS (alterx→puredns, public resolvers)",     False, "recon_permute.sh"),
    ("uncover",        "Surface expansion (Shodan/Censys dorks, budget-capped)", False, "recon_uncover.sh"),
    # --- intel / research feeds ---
    ("cve",            "CVE/KEV intel feed",                                     False, "recon_cve_intel.sh"),
    ("vuln_feed",      "Vulnerability feed ingest",                              False, "recon_vuln_feed.sh"),
    ("nuclei_update",  "Nuclei template refresh (weekly)",                       False, "nuclei"),
    ("research",       "Standing Claude research routine (vulns/tooling/kb)",    False, "recon_research.sh"),
    ("targets",        "Under-Hunted Target Board (program EV scoring)",         False, "recon_targets.sh"),
    ("selfaudit",      "recon-audit self-audit (invariant checks, dry-run)",     False, "recon_selfaudit.sh"),
    ("briefing",       "6:30pm TONIGHT worklist briefing",                       False, "recon_briefing.sh"),
    # --- scanning / target-facing ---
    ("nuclei",         "Nuclei template scan",                                   True,  "recon_nuclei.sh"),
    ("exposure",       "Nuclei exposure/misconfig scan",                         True,  "recon_nuclei.sh"),
    ("evidence_gate",  "P0-candidate evidence gate (promote on real fire)",      True,  "recon_evidence_gate.sh"),
    ("portscan",       "Critical-port scan (~120 ports, P1+ hosts)",            True,  "recon_portscan.sh"),
    ("bypass",         "401/403 access-control bypass tester",                   True,  "recon_bypass.sh"),
    ("screenshot",     "Playwright screenshot capture",                          True,  "recon_screenshot.sh"),
    ("cloudrecon",     "Cloud cert-recon (Caduceus neighbor scan)",              True,  "recon_cloudrecon.sh"),
    ("dast",           "DAST param-fuzz / blind-XSS plant",                      True,  "recon_dast.sh"),
    ("params",         "Param discovery catalog (katana+gau+CDX crawl)",         True,  "recon_params.sh"),
    ("param_confirm",  "Param differential confirm (SSTI/redirect/SQLi)",        True,  "recon_param_confirm.sh"),
    ("xss_confirm",    "Headless XSS execution confirm (Playwright marker)",     True,  "recon_xss_confirm.sh"),
    ("active_checks",  "Fresh active checks (bounty modules)",                   True,  "recon_fresh_modules.sh"),
    ("js_scanner",     "JS scan (fresh-module JS harvest)",                      True,  "recon_fresh_modules.sh"),
    ("jsintel",        "JS-intel: hidden endpoints + verified secrets",          True,  "recon_jsintel.sh"),
    ("exposed_files",  "Exposed-file probe (.git/.env/actuator/swagger)",        True,  "recon_exposed_files.sh"),
    ("autoswagger",    "Autoswagger (OpenAPI/Swagger auth testing)",             True,  "recon_autoswagger.sh"),
    ("kr",             "Kiterunner API-route discovery (bare API gateways)",     True,  "recon_kr.sh"),
    # --- UNIQUE money pillars ---
    ("ai_hunter",      "Claude IDOR/BAC hunter (per-target reasoning loop)",     True,  "recon_ai_hunter.sh"),
    ("ai_analyze",     "Claude analyze triage (Haiku surface selection)",        False, "recon_ai_analyze.sh"),
    ("ai_vision",      "Claude vision screenshot triage (exposed-panel)",        False, "recon_ai_vision.sh"),
    ("graphql",        "GraphQL introspection → schema worklist",                True,  "recon_graphql.sh"),
    ("wcd",            "Web-cache deception/poisoning (safe, cache-busted)",     True,  "recon_wcd.sh"),
    ("buckets",        "Cloud-bucket exposure (provenance-seeded, read-only)",   True,  "recon_bucket_scanner.sh"),
    ("cognito",        "Cognito unauth-cred lane (Amplify→pool→creds)",          True,  "recon_cognito_nighthunt.sh"),
    ("blindxss",       "Blind/stored-XSS beacon plant + correlate",              True,  "recon_blindxss.sh"),
    ("nday",           "n-day racing (version-reason KEV/CVE matches)",          False, "recon_nday.sh"),
    ("ghleaks",        "GitHub leak scan (code-search + trufflehog)",            False, "recon_ghleaks.sh"),
    ("unauth_expose",  "Shadow-endpoint unauth data-exposure confirmer (U1)",    True,  "recon_unauth_expose.sh"),
    ("ssrf_oob",       "Unauth SSRF discovery, OOB-confirmed (U4)",              True,  "recon_ssrf_oob.sh"),
    ("domxss",         "DOM-XSS confirm (dalfox deep-domxss, U6)",               True,  "recon_domxss_confirm.sh"),
    # --- takeover / DNS ---
    ("takeover",       "Subdomain takeover watch (NXDOMAIN + unclaimed)",        True,  "recon_takeover_hunter.sh"),
    ("dangling_dns",   "Dangling-NS takeover (Hazy-Hawk class)",                 False, "recon_dangling_dns.sh"),
    ("baddns",         "BadDNS takeover augmenter (second-order/NSEC)",          True,  "recon_baddns.sh"),
    # --- reporting / safety brains ---
    ("reporter",       "v3 reporter → human review-queue artifacts",             True,  "reporter.py"),
    ("v3_digest",      "Observability daily audit digest",                       False, "observability.py"),
    ("vpnguard",       "VPN leak guard (fail-closed egress watchdog)",           False, "recon_vpnguard.sh"),
]


def _proc_snapshot() -> str:
    """One cheap process-table snapshot (all args), for best-effort lane liveness."""
    try:
        import subprocess
        out = subprocess.run(["ps", "-eo", "args="], capture_output=True, text=True, timeout=5)
        return out.stdout or ""
    except Exception:
        return ""


def _yield_index(yield_lanes: list[dict] | None) -> dict[str, dict]:
    """Index observability yield_audit lanes by their (normalised) name for lookup."""
    idx: dict[str, dict] = {}
    for l in yield_lanes or []:
        name = str(l.get("lane", "")).lower()
        if name:
            idx[name] = l
    return idx


def _match_yield(token: str, idx: dict[str, dict]) -> dict | None:
    """Best-effort match a registry token to a yield lane (exact, then substring)."""
    if token in idx:
        return idx[token]
    for name, l in idx.items():
        if token in name or name in token:
            return l
    return None


def lane_activity(yield_lanes: list[dict] | None = None) -> list[dict[str, Any]]:
    """Full daemon-lane activity view: killswitch state, yield, and best-effort liveness.

    Defensive by construction — any missing source degrades to a sensible default, never throws.
    `yield_lanes` is the observability yield_audit `lanes` list (the route supplies it); when
    absent, yield_count is 0 and last_yield_at null.
    """
    yidx = _yield_index(yield_lanes)
    procs = _proc_snapshot()
    kill_dir = config.KILL_DIR
    out: list[dict[str, Any]] = []
    for token, desc, target, stem in LANE_REGISTRY:
        killed, since = False, None
        try:
            kf = kill_dir / f"v2_{token}"
            if kf.exists():
                killed = True
                since = int(kf.stat().st_mtime)
        except Exception:
            pass
        yl = _match_yield(token, yidx)
        yield_count = 0
        if yl is not None:
            try:
                yield_count = int(yl.get("confirmed") or 0)
            except Exception:
                yield_count = 0
        running = bool(stem and stem in procs)
        out.append({
            "lane": token, "desc": desc, "target": target,
            "killed": killed, "killed_since": since,
            "yield_count": yield_count, "last_yield_at": None,
            "running": running,
        })
    return out


def lane_log(lane: str, tail: int = 200) -> list[str]:
    """Tail a lane's own log (LOG_DIR/<lane>.log) if present, else grep the shared daemon
    log for lines mentioning the lane token. `lane` is sanitised to defeat path traversal."""
    import re
    safe = re.sub(r"[^A-Za-z0-9_-]", "", lane or "")[:64]
    if not safe:
        return []
    dedicated = config.LOG_DIR / f"{safe}.log"
    if dedicated.exists():
        return tail_file(dedicated, tail)
    # fall back to the shared daemon log — grep for lines that mention the lane token
    token = safe.lower()
    lines = tail_file(config.DAEMON_LOG, 4000)
    hits = [ln for ln in lines if token in ln.lower()]
    return hits[-tail:]

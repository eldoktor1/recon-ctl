#!/usr/bin/env python3
"""recon-audit — the standing, automated self-audit of the recon pipeline.

Codifies the manual `docs/audit_*.md` battery into a repeatable set of invariant
checks. DRY-RUN by default: it only *detects* and reports. Under `--apply` it
auto-fixes ONLY a narrow, reversible data/state whitelist (see WHITELIST below);
everything else is detect-only -> a ready-to-paste Claude-Code fix-prompt + an
#ops alarm.

  selfaudit.py            -> dry-run; writes the report + selfaudit_latest.json
  selfaudit.py --apply    -> dry-run + the whitelist remediation (operator-only)
  selfaudit.py --json     -> print the machine-readable result to stdout

HARD FIX-AUTHORITY BOUNDARY (enforced here, non-negotiable): this routine MUST
NEVER edit code/config logic, touch nftables/iptables/Mullvad/egress, clear
$STATE_DIR/vpn_down, disable a safety gate, auto-submit/ignore/fp, or restart the
daemon. The ONLY mutations it may perform are the item-2 whitelist below.

Output shape mirrors docs/audit_2026-06-11.md (severity-grouped markdown).
"""
from __future__ import annotations
import os, sys, json, re, subprocess, time, datetime as _dt

# ---------------------------------------------------------------------------
# Config (all overridable via env so the daemon/watchdog/operator agree)
# ---------------------------------------------------------------------------
HOME       = os.path.expanduser("~")
BASE_DIR   = os.path.expanduser(os.environ.get("BASE_DIR", "~/recon"))
STATE_DIR  = os.path.join(BASE_DIR, "state")
REPO_DIR   = os.environ.get("RECON_REPO_DIR") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ES_URL     = os.environ.get("ES_URL", "http://127.0.0.1:9200")
ES_INDEX   = os.environ.get("RECON_ES_INDEX", "recon_alive")
V3_DB      = os.path.expanduser(os.environ.get("V3_DB", os.path.join(BASE_DIR, "v3/findings.db")))
VPN_CHECK  = os.path.join(REPO_DIR, "scripts", "recon_vpn_check.sh")

DOCS_DIR   = os.path.join(REPO_DIR, "docs")
LATEST_JSON = os.path.join(STATE_DIR, "selfaudit_latest.json")
ACTIONS_LOG = os.path.join(STATE_DIR, "selfaudit_actions.jsonl")

# thresholds (hours unless noted)
SCOPE_MAX_AGE_H   = float(os.environ.get("AUDIT_SCOPE_MAX_AGE_H", "26"))  # scope_db cadence is 24h (SCOPE_DB_INTERVAL) — 8h guaranteed a daily false-warn; 26h = 2h margin
KEV_MAX_AGE_H     = float(os.environ.get("AUDIT_KEV_MAX_AGE_H", "12"))
VULNFEED_MAX_AGE_H = float(os.environ.get("AUDIT_VULNFEED_MAX_AGE_H", "3"))
LOCK_STALE_MIN    = float(os.environ.get("AUDIT_LOCK_STALE_MIN", "120"))
SELFAUDIT_INTERVAL_H = float(os.environ.get("AUDIT_INTERVAL_H", "6"))
OPS_COOLDOWN_H    = float(os.environ.get("AUDIT_OPS_COOLDOWN_H", "12"))
ES_MIN_DOCS       = int(os.environ.get("AUDIT_ES_MIN_DOCS", "1000"))
QUEUE_BACKLOG_WARN = int(os.environ.get("AUDIT_QUEUE_BACKLOG_WARN", "2000"))
DRAIN_STALE_MIN   = float(os.environ.get("AUDIT_DRAIN_STALE_MIN", "20"))   # validate lock older => not draining
DAEMON_CHILD_FLOOR = int(os.environ.get("AUDIT_DAEMON_CHILD_FLOOR", "12")) # supervise subshells expected

# append-only / growth stores -> (path, threshold_MB, auto_rotatable)
# auto_rotatable=False for LOAD-BEARING ledgers (dedup memory / permanent
# worked-knowledge): rotating them would break the pipeline, so they are
# detect-only even under --apply. Only plain logs are auto-rotated.
GROWTH_STORES = [
    (os.path.join(STATE_DIR, "known_hosts.txt"),      400, False),  # ever-seen dedup ledger — NEVER auto-rotate
    (os.path.join(STATE_DIR, "true_fresh.jsonl"),     200, False),
    (os.path.join(STATE_DIR, "ignored.jsonl"),         50, False),  # TTL logic depends on it
    (os.path.join(STATE_DIR, "host_notes.jsonl"),      50, False),  # permanent worked-knowledge
    (os.path.join(BASE_DIR,  "vuln/vuln_targets.jsonl"), 250, False),  # regenerated each cycle; flag only
    (os.path.join(BASE_DIR,  "vuln/vuln_feed.jsonl"),  200, False),
    (os.path.join(BASE_DIR,  "cve/kev_targets.jsonl"), 100, False),
    (os.path.join(BASE_DIR,  "logs/recon_daemon.log"), 200, True),   # plain log — safe to archive
    (os.path.join(BASE_DIR,  "logs/watchdog.log"),      50, True),
]

# scripts retired in prior audits — flag if a reference survives but the file is gone (audit F2/F3)
RETIRED_SCRIPTS = [
    "recon_killswitch.sh", "recon_dast.sh", "recon_ai_idor.sh", "recon_ai_monitor.sh",
    "wait_es.sh", "orchestrator.py", "tier.py", "recon_leads_digest.sh",
]

SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3, "OK": 4}
SEV_EMOJI = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡", "INFO": "🔵", "OK": "✅"}


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _today() -> str:
    return _now().strftime("%Y-%m-%d")


def _iso() -> str:
    return _now().strftime("%Y-%m-%dT%H:%M:%SZ")


def _age_h(path: str):
    try:
        return round((time.time() - os.path.getmtime(path)) / 3600.0, 2)
    except Exception:
        return None


def _size_mb(path: str):
    try:
        return round(os.path.getsize(path) / 1048576.0, 1)
    except Exception:
        return None


def finding(cid, severity, status, detail, remediation_class="human", **extra):
    """status: ok|warn|fail|na ; remediation_class: auto|claude-code|human|none."""
    d = {"id": cid, "severity": severity, "status": status, "detail": detail,
         "remediation_class": remediation_class}
    d.update(extra)
    return d


# ===========================================================================
# CHECKS  (each returns one finding dict; pure detection, no mutation)
# ===========================================================================
def chk_vpn() -> dict:
    vpn_down = os.path.join(STATE_DIR, "vpn_down")
    flag = os.path.isfile(vpn_down)
    word, rc = "no-checker", 2
    if os.path.isfile(VPN_CHECK):
        try:
            p = subprocess.run(["bash", VPN_CHECK, "--cached"], capture_output=True,
                               text=True, timeout=20, env={**os.environ, "STATE_DIR": STATE_DIR})
            word, rc = (p.stdout.strip() or "?"), p.returncode
        except Exception as e:
            word, rc = f"checker-error:{e}", 2
    # coherence: vpn_down set => scanning is paused (correct). Egress confirmed but
    # flag still set => the guard hasn't cleared a stuck flag (warn; NEVER auto-clear).
    if flag and rc == 0:
        return finding("vpn.coherence", "MEDIUM", "warn",
                       f"egress reports Mullvad ({word}) but $STATE_DIR/vpn_down is still set "
                       "— scanning is paused on a possibly-stuck flag. Only vpnguard may clear it.",
                       remediation_class="human")
    if flag:
        return finding("vpn.coherence", "INFO", "ok",
                       f"vpn_down set and egress not confirmed ({word}) — pipeline correctly paused.",
                       remediation_class="none")
    if rc != 0:
        return finding("vpn.egress", "HIGH", "fail",
                       f"VPN/egress NOT confirmed on Mullvad ({word}) and no vpn_down flag set "
                       "— scanners may egress off-VPN. Investigate vpnguard.",
                       remediation_class="human")
    return finding("vpn.egress", "OK", "ok", f"Mullvad egress confirmed ({word}); vpn_down clear.",
                   remediation_class="none")


def chk_scope_fresh() -> dict:
    prog = os.path.join(BASE_DIR, "scope/programs.json")
    pat  = os.path.join(BASE_DIR, "scope/inscope_patterns.tsv")
    age = _age_h(prog)
    pat_ok = os.path.isfile(pat) and os.path.getsize(pat) > 0
    if age is None:
        return finding("scope.fresh", "HIGH", "fail", f"scope/programs.json missing ({prog}).",
                       remediation_class="claude-code")
    if not pat_ok:
        return finding("scope.fresh", "HIGH", "fail", "inscope_patterns.tsv missing/empty — scope gate is blind.",
                       remediation_class="claude-code")
    if age > SCOPE_MAX_AGE_H:
        return finding("scope.fresh", "MEDIUM", "warn",
                       f"scope/programs.json is {age}h old (> {SCOPE_MAX_AGE_H}h) — scope-db (24h cadence) may be stalled.",
                       remediation_class="claude-code")
    return finding("scope.fresh", "OK", "ok", f"scope fresh ({age}h); inscope_patterns.tsv non-empty.",
                   remediation_class="none")


def chk_feed_stale() -> list:
    out = []
    kev = os.path.join(BASE_DIR, "cve/kev.json")
    a = _age_h(kev)
    if a is None:
        out.append(finding("feed.kev", "MEDIUM", "warn", f"cve/kev.json missing ({kev}).", remediation_class="claude-code"))
    elif a > KEV_MAX_AGE_H:
        out.append(finding("feed.kev", "MEDIUM", "warn", f"cve/kev.json {a}h old (> {KEV_MAX_AGE_H}h) — cve-kev loop stalled?", remediation_class="claude-code"))
    else:
        out.append(finding("feed.kev", "OK", "ok", f"kev.json fresh ({a}h).", remediation_class="none"))
    vf = os.path.join(BASE_DIR, "vuln/vuln_feed.jsonl")
    a = _age_h(vf)
    if a is None:
        out.append(finding("feed.vuln", "MEDIUM", "warn", f"vuln/vuln_feed.jsonl missing ({vf}).", remediation_class="claude-code"))
    elif a > VULNFEED_MAX_AGE_H:
        out.append(finding("feed.vuln", "MEDIUM", "warn", f"vuln/vuln_feed.jsonl {a}h old (> {VULNFEED_MAX_AGE_H}h) — vuln-feed loop stalled?", remediation_class="claude-code"))
    else:
        out.append(finding("feed.vuln", "OK", "ok", f"vuln_feed.jsonl fresh ({a}h).", remediation_class="none"))
    return out


def _es_get(path: str):
    import urllib.request, base64
    pw = ""
    try:
        pw = open(os.path.join(HOME, ".recon_es_pass"), encoding="utf-8").read().strip()
    except Exception:
        pass
    headers = {}
    if pw:
        headers["Authorization"] = "Basic " + base64.b64encode(f"elastic:{pw}".encode()).decode()
    req = urllib.request.Request(f"{ES_URL}{path}", headers=headers)
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r)


def chk_es() -> dict:
    try:
        h = _es_get("/_cluster/health")
        status = h.get("status", "?")
        c = _es_get(f"/{ES_INDEX}/_count")
        docs = int(c.get("count", -1))
    except Exception as e:
        return finding("es.health", "HIGH", "fail", f"ES unreachable / {ES_INDEX} not queryable: {e}",
                       remediation_class="human")
    if status == "red":
        return finding("es.health", "HIGH", "fail", f"ES cluster RED; {ES_INDEX} docs={docs}.",
                       remediation_class="human")
    if docs < ES_MIN_DOCS:
        return finding("es.health", "HIGH", "fail",
                       f"{ES_INDEX} doc count collapsed to {docs} (< {ES_MIN_DOCS}) — index may have been wiped/reindexed wrong.",
                       remediation_class="human")
    return finding("es.health", "OK", "ok", f"ES {status}; {ES_INDEX} docs={docs}.", remediation_class="none")


def _sql(query: str):
    p = subprocess.run(["sqlite3", "-readonly", V3_DB, query], capture_output=True, text=True, timeout=20)
    if p.returncode != 0:
        raise RuntimeError(p.stderr.strip() or "sqlite3 error")
    return p.stdout.strip()


def chk_sqlite() -> list:
    out = []
    if not os.path.isfile(V3_DB):
        return [finding("db.open", "HIGH", "fail", f"findings.db missing ({V3_DB}).", remediation_class="human")]
    try:
        integ = _sql("PRAGMA integrity_check;")
        if integ != "ok":
            out.append(finding("db.integrity", "HIGH", "fail", f"findings.db integrity_check: {integ[:200]}", remediation_class="human"))
        else:
            out.append(finding("db.integrity", "OK", "ok", "findings.db opens; integrity_check ok.", remediation_class="none"))
    except Exception as e:
        return [finding("db.open", "HIGH", "fail", f"findings.db unreadable: {e}", remediation_class="human")]
    # reporter-feed sanity: confirmed+real rows must carry evidence
    try:
        bad = _sql("SELECT COUNT(*) FROM findings WHERE state='confirmed' AND ai_verdict='real' "
                   "AND (evidence IS NULL OR evidence='');")
        n = int(bad or 0)
        if n > 0:
            out.append(finding("db.reporter_feed", "MEDIUM", "warn",
                               f"{n} confirmed+real finding(s) lack evidence — reporter would emit an empty PoC.",
                               remediation_class="claude-code"))
        else:
            out.append(finding("db.reporter_feed", "OK", "ok", "no evidence-less confirmed+real rows.", remediation_class="none"))
    except Exception as e:
        out.append(finding("db.reporter_feed", "LOW", "warn", f"reporter-feed query failed: {e}", remediation_class="human"))
    # FP-signature / knowledge_base freshness: tables present + JSON columns parse
    out.append(_chk_fp_kb())
    return out


def _chk_fp_kb() -> dict:
    try:
        fp = int(_sql("SELECT COUNT(*) FROM false_positive_signatures;") or 0)
        kb = int(_sql("SELECT COUNT(*) FROM knowledge_base;") or 0)
    except Exception as e:
        return finding("db.fp_kb", "MEDIUM", "warn",
                       f"false_positive_signatures / knowledge_base not queryable: {e}", remediation_class="claude-code")
    # JSON-validity of the findings evidence column (the concrete JSON store)
    bad_json = 0
    try:
        rows = _sql("SELECT evidence FROM findings WHERE evidence IS NOT NULL AND evidence!='' LIMIT 200;")
        for line in rows.splitlines():
            if not line.strip():
                continue
            try:
                json.loads(line)
            except Exception:
                bad_json += 1
    except Exception:
        pass
    if bad_json > 0:
        return finding("db.fp_kb", "LOW", "warn",
                       f"fp_sigs={fp} kb={kb} present, but {bad_json}/200 sampled evidence rows are not valid JSON.",
                       remediation_class="claude-code")
    return finding("db.fp_kb", "OK", "ok",
                   f"false_positive_signatures ({fp}) + knowledge_base ({kb}) queryable; sampled evidence JSON valid.",
                   remediation_class="none")


def chk_lane_yield() -> list:
    """Reuse engine/observability.yield_audit — flag any RUNNING lane producing 0 confirmed/0 real."""
    out = []
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import state as S
        import observability as OBS
        conn = S.connect(); S.init_db(conn)
        ya = OBS.yield_audit(conn)
    except Exception as e:
        return [finding("yield.audit", "LOW", "warn", f"per-lane yield audit unavailable: {e}", remediation_class="human")]
    sz = ya.get("silent_zero", [])
    if sz:
        for l in sz:
            crit = " (CRITICAL value-engine lane)" if l.get("critical") else ""
            out.append(finding(f"yield.{re.sub(r'[^a-z0-9]+','_',l['lane'].lower()).strip('_')}",
                               "MEDIUM" if not l.get("critical") else "HIGH", "warn",
                               f"lane '{l['lane']}' SILENT-ZERO over {ya.get('window_d')}d "
                               f"({l.get('input')} {l.get('input_label')}, 0 confirmed, 0 real){crit}.",
                               remediation_class="claude-code"))
    else:
        out.append(finding("yield.audit", "OK", "ok",
                           f"no silent-zero lanes over {ya.get('window_d')}d window.", remediation_class="none"))
    # explicit portscan probe (known offender; not a catalog lane in yield_audit)
    try:
        cutoff = (_now() - _dt.timedelta(days=14)).strftime("%Y-%m-%dT%H:%M:%SZ")
        pc = int(_sql(f"SELECT COUNT(*) FROM findings WHERE created_at>='{cutoff}' "
                      "AND (signal_class LIKE 'portscan%' OR vuln_class LIKE '%port%');") or 0)
        running = os.path.isfile(os.path.join(STATE_DIR, "portscan.lock"))
        if running and pc == 0:
            out.append(finding("yield.portscan", "MEDIUM", "warn",
                               "portscan lane is scheduled (portscan.lock present) but produced 0 findings in 14d — silent-zero offender.",
                               remediation_class="claude-code"))
        else:
            out.append(finding("yield.portscan", "OK", "ok", f"portscan produced {pc} finding(s)/14d.", remediation_class="none"))
    except Exception:
        pass
    return out


def chk_dangling_refs() -> dict:
    """Flag references to RETIRED scripts whose file no longer exists (audit F2/F3)."""
    scan_dirs = [os.path.join(REPO_DIR, d) for d in ("scripts", "tools", "engine")]
    # which retired names are actually gone from disk?
    existing = set()
    for d in scan_dirs:
        for root, _, files in os.walk(d):
            for f in files:
                existing.add(f)
    gone = [s for s in RETIRED_SCRIPTS if s not in existing]
    hits = {}
    for name in gone:
        refs = []
        try:
            p = subprocess.run(
                # exclude the auditor's own files — they NAME retired scripts as data, not refs
                ["grep", "-rnI", "--include=*.sh", "--include=*.py",
                 "--exclude=selfaudit.py", "--exclude=recon_selfaudit.sh",
                 name, *scan_dirs],
                capture_output=True, text=True, timeout=30)
            for line in p.stdout.splitlines():
                refs.append(line.split(":", 2)[0])
        except Exception:
            pass
        refs = sorted(set(r for r in refs))
        if refs:
            hits[name] = refs
    if hits:
        detail = "; ".join(f"{n} (gone) still referenced by {', '.join(os.path.relpath(r, REPO_DIR) for r in v[:4])}"
                           for n, v in hits.items())
        return finding("refs.dangling", "MEDIUM", "fail",
                       f"dangling references to deleted scripts: {detail}", remediation_class="claude-code",
                       hits={n: [os.path.relpath(r, REPO_DIR) for r in v] for n, v in hits.items()})
    return finding("refs.dangling", "OK", "ok", "no references to retired/deleted scripts.", remediation_class="none")


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def chk_daemon() -> list:
    out = []
    pidf = os.path.join(STATE_DIR, "recon_daemon.pid")
    pid = None
    try:
        pid = int(open(pidf).read().strip())
    except Exception:
        pid = None
    if pid is None:
        out.append(finding("daemon.pid", "MEDIUM", "warn", "recon_daemon.pid missing/empty — daemon not started?", remediation_class="human"))
        return out
    if not _pid_alive(pid):
        out.append(finding("daemon.pid", "MEDIUM", "warn",
                           f"recon_daemon.pid={pid} but no live process (post-reboot stale PID).",
                           remediation_class="auto", pid=pid))
        return out
    out.append(finding("daemon.pid", "OK", "ok", f"daemon alive (pid={pid}).", remediation_class="none"))
    # child supervise loops: each `supervise_loop ... &` is a backgrounded SUBSHELL of the
    # daemon (the function name never appears in argv), so count direct children of the pid.
    try:
        ps = subprocess.run(["pgrep", "-P", str(pid)], capture_output=True, text=True, timeout=10)
        nchild = len([x for x in ps.stdout.split() if x.strip()])
        if nchild < DAEMON_CHILD_FLOOR:
            out.append(finding("daemon.loops", "MEDIUM", "warn",
                               f"daemon has only {nchild} child loops (< {DAEMON_CHILD_FLOOR} expected) — loops may have died.",
                               remediation_class="human"))
        else:
            out.append(finding("daemon.loops", "OK", "ok", f"{nchild} supervised child loops alive.", remediation_class="none"))
    except Exception:
        pass
    return out


def _validate_draining() -> bool:
    """validate loops hold flock on validate*.lock; the lock mtime refreshes each cycle.
    A fresh validate lock = validate is actively cycling (a reliable drain signal even
    though the loop itself is a sleeping subshell with no greppable argv)."""
    import glob
    for lock in glob.glob(os.path.join(STATE_DIR, "validate*.lock")):
        a = _age_h(lock)
        if a is not None and a * 60.0 < DRAIN_STALE_MIN:
            return True
    return False


def chk_queue() -> dict:
    import glob
    def _count(sub, pat="*.txt"):
        return len(glob.glob(os.path.join(BASE_DIR, "queue", sub, pat)))
    inbox = _count("inbox")
    proc = _count("processing")
    draining = _validate_draining()
    # BROKEN = inbox piled up AND validate is NOT cycling (stale lock). STARVED = empty
    # inbox + nothing draining (idle, not a fault). A big inbox while validate cycles is
    # a backlog warning, never a page.
    if inbox >= QUEUE_BACKLOG_WARN and not draining:
        return finding("queue.state", "HIGH", "fail",
                       f"queue BROKEN: inbox={inbox} and validate not draining (no validate*.lock newer than {DRAIN_STALE_MIN}min).",
                       remediation_class="human")
    if inbox >= QUEUE_BACKLOG_WARN:
        return finding("queue.state", "MEDIUM", "warn",
                       f"queue backlog high (inbox={inbox} >= {QUEUE_BACKLOG_WARN}); validate IS cycling — watch it drain.",
                       remediation_class="human")
    if inbox == 0 and not draining:
        return finding("queue.state", "INFO", "ok", "queue STARVED (empty inbox, validate idle) — idle, not broken.", remediation_class="none")
    return finding("queue.state", "OK", "ok", f"queue healthy (inbox={inbox}, processing={proc}, validate cycling).", remediation_class="none")


def chk_spool() -> dict:
    failed = os.path.join(BASE_DIR, "spool", "failed")
    try:
        n = len([f for f in os.listdir(failed)]) if os.path.isdir(failed) else 0
    except Exception:
        n = 0
    prev_f = os.path.join(STATE_DIR, ".selfaudit_spool_failed_prev")
    prev = None
    try:
        prev = int(open(prev_f).read().strip())
    except Exception:
        prev = None
    try:
        open(prev_f, "w").write(str(n))
    except Exception:
        pass
    if n == 0:
        return finding("spool.backlog", "OK", "ok", "spool/failed empty.", remediation_class="none")
    growing = prev is not None and n > prev
    sev = "MEDIUM" if growing else "LOW"
    return finding("spool.backlog", sev, "warn",
                   f"spool/failed has {n} item(s)" + (f" (was {prev} last run — GROWING)" if growing else "")
                   + " — retryable to ES ingest.",
                   remediation_class="auto", failed_count=n)


def chk_perms() -> list:
    out = []
    # firstblood/ owned by reconrun
    fb = os.path.join(BASE_DIR, "firstblood")
    try:
        import pwd
        st = os.stat(fb)
        owner = pwd.getpwuid(st.st_uid).pw_name
        if owner != "reconrun":
            out.append(finding("perm.firstblood", "MEDIUM", "warn",
                               f"firstblood/ owned by {owner}, expected reconrun.", remediation_class="auto", path=fb))
        else:
            out.append(finding("perm.firstblood", "OK", "ok", "firstblood/ owned by reconrun.", remediation_class="none"))
    except Exception as e:
        out.append(finding("perm.firstblood", "LOW", "warn", f"firstblood/ stat failed: {e}", remediation_class="human"))
    # ~/.recon_es_pass chmod 600
    esp = os.path.join(HOME, ".recon_es_pass")
    try:
        mode = os.stat(esp).st_mode & 0o777
        if mode != 0o600:
            out.append(finding("perm.es_pass", "MEDIUM", "warn",
                               f"~/.recon_es_pass mode is {oct(mode)}, expected 0o600.", remediation_class="auto", path=esp))
        else:
            out.append(finding("perm.es_pass", "OK", "ok", "~/.recon_es_pass is 0600.", remediation_class="none"))
    except Exception as e:
        out.append(finding("perm.es_pass", "LOW", "warn", f"~/.recon_es_pass stat failed: {e}", remediation_class="human"))
    return out


def chk_growth() -> list:
    out = []
    for path, thresh_mb, rotatable in GROWTH_STORES:
        mb = _size_mb(path)
        if mb is None:
            continue
        if mb > thresh_mb:
            out.append(finding(f"growth.{os.path.basename(path)}",
                               "LOW", "warn",
                               f"{os.path.relpath(path, BASE_DIR)} is {mb}MB (> {thresh_mb}MB threshold)"
                               + (" — auto-rotatable log." if rotatable else " — load-bearing ledger; rotation needs a brain."),
                               remediation_class="auto" if rotatable else "claude-code",
                               path=path, size_mb=mb, rotatable=rotatable))
    if not out:
        out.append(finding("growth.stores", "OK", "ok", "no append-only store past its growth threshold.", remediation_class="none"))
    return out


def run_checks() -> list:
    checks = []
    checks.append(chk_vpn())
    checks.append(chk_scope_fresh())
    checks.extend(chk_feed_stale())
    checks.append(chk_es())
    checks.extend(chk_sqlite())
    checks.extend(chk_lane_yield())
    checks.append(chk_dangling_refs())
    checks.extend(chk_daemon())
    checks.append(chk_queue())
    checks.append(chk_spool())
    checks.extend(chk_perms())
    checks.extend(chk_growth())
    return checks


# ===========================================================================
# AUTO-REMEDIATION  (item-2 whitelist ONLY — idempotent, reversible, logged)
# ===========================================================================
def _log_action(check_id, action, before, after):
    rec = {"ts": _iso(), "check_id": check_id, "action": action,
           "before": before, "after": after, "reverted": False}
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(ACTIONS_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
    except Exception:
        pass
    return rec


def _lock_has_holder(path: str) -> bool:
    for tool in (["fuser", "-s", path], ["lsof", "-t", path]):
        try:
            p = subprocess.run(tool, capture_output=True, text=True, timeout=8)
            if p.returncode == 0 and (tool[0] == "fuser" or p.stdout.strip()):
                return True
        except FileNotFoundError:
            continue
        except Exception:
            return True  # uncertain -> treat as held (fail-safe; never remove a live lock)
    return False


def remediate(checks: list) -> list:
    """Apply ONLY the whitelist. Each action idempotent + reversible + logged."""
    actions = []
    by_id = {c["id"]: c for c in checks}

    # 1) stale validate.*.lock with no live owner, older than LOCK_STALE_MIN
    import glob
    for lock in glob.glob(os.path.join(STATE_DIR, "validate.*.lock")):
        try:
            age_min = (time.time() - os.path.getmtime(lock)) / 60.0
        except Exception:
            continue
        if age_min < LOCK_STALE_MIN:
            continue
        if _lock_has_holder(lock):
            continue
        try:
            os.remove(lock)
            actions.append(_log_action("lock.stale", "remove_stale_validate_lock", lock, "removed"))
        except Exception:
            pass

    # 2) clear daemon PID file IFF the PID is dead (never start anything)
    c = by_id.get("daemon.pid")
    if c and c.get("remediation_class") == "auto" and c.get("pid"):
        pidf = os.path.join(STATE_DIR, "recon_daemon.pid")
        if os.path.isfile(pidf) and not _pid_alive(int(c["pid"])):
            try:
                os.remove(pidf)
                actions.append(_log_action("daemon.pid", "clear_dead_pid_file", str(c["pid"]), "removed"))
            except Exception:
                pass

    # 3) re-apply known-good perms (only if drifted)
    c = by_id.get("perm.es_pass")
    if c and c.get("status") == "warn" and c.get("path"):
        try:
            before = oct(os.stat(c["path"]).st_mode & 0o777)
            os.chmod(c["path"], 0o600)
            actions.append(_log_action("perm.es_pass", "chmod_600", before, "0o600"))
        except Exception:
            pass
    c = by_id.get("perm.firstblood")
    if c and c.get("status") == "warn" and c.get("path"):
        # chown to reconrun needs root — try sudo -n, degrade gracefully (no failure)
        try:
            p = subprocess.run(["sudo", "-n", "chown", "reconrun:reconrun", c["path"]],
                               capture_output=True, text=True, timeout=15)
            if p.returncode == 0:
                actions.append(_log_action("perm.firstblood", "chown_reconrun", "drifted", "reconrun:reconrun"))
            else:
                actions.append(_log_action("perm.firstblood", "chown_reconrun_NEEDS_SUDO", "drifted", "skipped (no passwordless sudo)"))
        except Exception:
            pass

    # 4) retry spool/failed -> pending (the validate/ingest loop re-picks pending)
    c = by_id.get("spool.backlog")
    if c and c.get("remediation_class") == "auto" and c.get("failed_count", 0) > 0:
        failed = os.path.join(BASE_DIR, "spool", "failed")
        pending = os.path.join(BASE_DIR, "spool", "pending")
        moved = 0
        try:
            os.makedirs(pending, exist_ok=True)
            for f in os.listdir(failed):
                src = os.path.join(failed, f)
                if os.path.isfile(src):
                    os.replace(src, os.path.join(pending, f))
                    moved += 1
            if moved:
                actions.append(_log_action("spool.backlog", "retry_failed_to_pending", f"{moved} in failed/", f"{moved} -> pending/"))
        except Exception:
            pass

    # 5) rotate (archive, never delete) auto-rotatable logs past threshold
    arch = os.path.join(BASE_DIR, "archive")
    for c in checks:
        if not c["id"].startswith("growth.") or c.get("remediation_class") != "auto":
            continue
        path = c.get("path")
        if not path or not c.get("rotatable") or not os.path.isfile(path):
            continue
        try:
            os.makedirs(arch, exist_ok=True)
            stamp = _now().strftime("%Y%m%dT%H%M%SZ")
            dest = os.path.join(arch, f"{os.path.basename(path)}.{stamp}")
            os.replace(path, dest)
            # recreate an empty file so the writer keeps appending
            open(path, "a").close()
            actions.append(_log_action(c["id"], "rotate_log_to_archive", f"{path} ({c.get('size_mb')}MB)", dest))
        except Exception:
            pass

    return actions


# ===========================================================================
# REPORT + FIX-PROMPTS + #ops
# ===========================================================================
def render_report(checks: list, actions: list, apply_mode: bool) -> str:
    by_sev = {}
    for c in checks:
        by_sev.setdefault(c["severity"], []).append(c)
    n_high = len([c for c in checks if c["severity"] == "HIGH" and c["status"] != "ok"])
    n_med = len([c for c in checks if c["severity"] == "MEDIUM" and c["status"] != "ok"])
    L = [f"# recon self-audit — {_today()}  (generated {_iso()})", ""]
    L.append(f"Automated invariant battery (the standing version of docs/audit_*.md). "
             f"Mode: **{'APPLY' if apply_mode else 'DRY-RUN'}**. "
             f"Unresolved: **{n_high} HIGH**, {n_med} MEDIUM. "
             f"{'No' if not actions else len(actions)} auto-remediation action(s) this run.")
    L.append("")
    L.append("Legend: **🔴 HIGH** (page-worthy) · **🟠 MEDIUM** · **🟡 LOW** · **🔵 INFO** · **✅ OK**. "
             "remediation_class: `auto` (whitelist, --apply only) · `claude-code` (fix-prompt) · `human`.")
    for sev in ("HIGH", "MEDIUM", "LOW", "INFO", "OK"):
        rows = by_sev.get(sev, [])
        if not rows:
            continue
        L.append(f"\n## {SEV_EMOJI[sev]} {sev}")
        for c in rows:
            mark = {"ok": "✅", "warn": "⚠️", "fail": "❌", "na": "—"}.get(c["status"], "·")
            L.append(f"- {mark} **{c['id']}** [{c['remediation_class']}] — {c['detail']}")
    if actions:
        L.append("\n## 🔧 Auto-remediation actions (this run)")
        for a in actions:
            L.append(f"- `{a['check_id']}` {a['action']}: {a['before']} → {a['after']}")
    L.append("")
    return "\n".join(L) + "\n"


def write_fixprompts(checks: list) -> str | None:
    cc = [c for c in checks if c["remediation_class"] == "claude-code" and c["status"] != "ok"]
    if not cc:
        return None
    path = os.path.join(DOCS_DIR, f"selfaudit_fixprompt_{_today()}.md")
    L = [f"# recon-audit fix-prompts — {_today()}", "",
         "Each block is ready to paste into Claude Code. recon-audit DETECTED these but "
         "**never auto-applies** code/config fixes (hard fix-authority boundary).", ""]
    for c in cc:
        L.append(f"## {c['id']}  ({c['severity']})")
        L.append(f"> {c['detail']}")
        L.append("")
        L.append("```")
        L.append(f"In the recon-pipeline repo, address self-audit finding `{c['id']}`:")
        L.append(f"  {c['detail']}")
        if c.get("hits"):
            for name, refs in c["hits"].items():
                L.append(f"  - {name} is referenced by: {', '.join(refs)} — either restore the script or remove the dead references.")
        L.append("Make the minimal fix. Do NOT touch egress/scope/safety gates or restart the daemon.")
        L.append(f"Accept: re-run `recon-audit` and confirm `{c['id']}` reports ✅ OK.")
        L.append("```")
        L.append("")
    try:
        os.makedirs(DOCS_DIR, exist_ok=True)
        open(path, "w", encoding="utf-8").write("\n".join(L) + "\n")
    except Exception:
        return None
    return path


def _ops_hook() -> str:
    for p in (os.path.join(HOME, ".recon_discord_ops"),
              os.path.join(os.environ.get("RECON_DISCORD_DIR", os.path.join(STATE_DIR, "discord")), "ops")):
        try:
            if os.path.isfile(p):
                h = open(p, encoding="utf-8").read().strip()
                if h:
                    return h
        except Exception:
            pass
    return ""


def _ops_post(hook: str, msg: str) -> bool:
    # Discord/Cloudflare 403s the default Python-urllib User-Agent, so a UA is REQUIRED
    # (this is why the bash discord_post via curl works but a bare urllib post silently fails).
    import urllib.request
    try:
        req = urllib.request.Request(hook, data=json.dumps({"content": msg[:1900]}).encode(),
                                     headers={"Content-Type": "application/json",
                                              "User-Agent": "recon-audit/1.0 (+selfaudit)"})
        with urllib.request.urlopen(req, timeout=15) as r:
            return 200 <= getattr(r, "status", 200) < 300
    except Exception:
        return False


def ops_alarm(checks: list, fixprompt_path: str | None, dry: bool = False) -> dict:
    """ONE #ops alarm summarizing claude-code/human findings. Dedup + cooldown: re-alarm
    only when the open-finding fingerprint changes OR the cooldown elapses. dry=True builds
    and previews the exact line WITHOUT posting (and without touching the cooldown marker)."""
    actionable = [c for c in checks if c["status"] != "ok" and c["remediation_class"] in ("claude-code", "human")]
    if not actionable:
        # recovered -> clear the marker so the next outage alarms immediately
        try:
            os.remove(os.path.join(STATE_DIR, ".selfaudit_ops_alarm"))
        except Exception:
            pass
        return {"fired": False, "reason": "no actionable findings"}
    import hashlib
    fp = hashlib.sha1(("|".join(sorted(c["id"] for c in actionable))).encode()).hexdigest()[:12]
    n_high = len([c for c in actionable if c["severity"] == "HIGH"])
    cc = len([c for c in actionable if c["remediation_class"] == "claude-code"])
    hum = len([c for c in actionable if c["remediation_class"] == "human"])
    ids = ", ".join(c["id"] for c in actionable[:8])
    msg = (f"🩺 **recon-audit {_today()}** — {len(actionable)} open finding(s): "
           f"{n_high} HIGH · {cc} claude-code · {hum} human. [{ids}]"
           + (f"\nFix-prompts: `{os.path.relpath(fixprompt_path, REPO_DIR)}`" if fixprompt_path else ""))
    if dry:
        print(f"[selfaudit] #ops PREVIEW (not sent):\n{msg}", file=sys.stderr)
        return {"fired": False, "reason": "dry preview", "fingerprint": fp, "message": msg}
    mark = os.path.join(STATE_DIR, ".selfaudit_ops_alarm")
    prev_fp, prev_ts = None, 0.0
    try:
        d = json.loads(open(mark).read())
        prev_fp, prev_ts = d.get("fp"), float(d.get("ts", 0))
    except Exception:
        pass
    now = time.time()
    if fp == prev_fp and (now - prev_ts) < OPS_COOLDOWN_H * 3600:
        return {"fired": False, "reason": "cooldown/dedup", "fingerprint": fp, "message": msg}
    hook = _ops_hook()
    if not hook:
        return {"fired": False, "reason": "no #ops webhook", "fingerprint": fp, "message": msg}
    if _ops_post(hook, msg):
        try:
            open(mark, "w").write(json.dumps({"fp": fp, "ts": int(now)}))
        except Exception:
            pass
        return {"fired": True, "fingerprint": fp, "message": msg}
    return {"fired": False, "reason": "post failed", "fingerprint": fp, "message": msg}


# ===========================================================================
def main(argv) -> int:
    apply_mode = "--apply" in argv
    as_json = "--json" in argv
    no_ops = "--no-ops" in argv  # for testing without firing Discord

    checks = run_checks()
    actions = remediate(checks) if apply_mode else []
    if apply_mode and actions:
        # re-run detection so the report/JSON reflect the post-fix state
        checks = run_checks()

    fixprompt_path = write_fixprompts(checks)
    ops = ops_alarm(checks, fixprompt_path, dry=no_ops)

    n_high_unresolved = len([c for c in checks if c["severity"] == "HIGH" and c["status"] != "ok"])
    result = {
        "generated_at": _iso(), "day": _today(), "apply_mode": apply_mode,
        "summary": {
            "total": len(checks),
            "high_unresolved": n_high_unresolved,
            "by_status": {s: len([c for c in checks if c["status"] == s]) for s in ("ok", "warn", "fail", "na")},
        },
        "checks": checks, "actions": actions,
        "fixprompt_file": fixprompt_path, "ops_alarm": ops,
        "exit_high": n_high_unresolved > 0,
    }

    # machine-readable
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(LATEST_JSON, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, default=str)
    except Exception as e:
        print(f"[selfaudit] WARN: could not write {LATEST_JSON}: {e}", file=sys.stderr)

    report = render_report(checks, actions, apply_mode)
    try:
        os.makedirs(DOCS_DIR, exist_ok=True)
        with open(os.path.join(DOCS_DIR, f"audit_{_today()}.md"), "w", encoding="utf-8") as f:
            f.write(report)
    except Exception as e:
        print(f"[selfaudit] WARN: could not write report: {e}", file=sys.stderr)

    if as_json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(report)
        print(f"[selfaudit] {LATEST_JSON} written; HIGH unresolved={n_high_unresolved}; "
              f"ops={ops.get('fired')}; fixprompts={fixprompt_path}", file=sys.stderr)

    return 1 if result["exit_high"] else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

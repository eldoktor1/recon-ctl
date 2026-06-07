#!/usr/bin/env python3
r"""v3 Phase B — finding-state machine over SQLite (complement to ES).

SQLite = finding STATE truth; ES = asset truth. Guarded, atomic transitions +
WAL give the transactional per-finding lifecycle that flat-file JSONL/ES could
not (the stale-priority / survivors-only bug class). Crash-safe: stale
`verifying` rows resume cleanly on startup — never strand, never double-fire.

Lifecycle:
    discovered -> scored -> verifying -> confirmed -> reported -> submitted
                                     \-> lead_exhausted
                                     \-> dismissed
"""
from __future__ import annotations
import os
import sqlite3
import hashlib
import json
import time
import datetime as _dt

DB_PATH = os.environ.get("V3_DB", os.path.expanduser("~/recon/v3/findings.db"))
SCHEMA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "db", "schema.sql")

TERMINAL = {"submitted", "dismissed", "lead_exhausted"}
# allowed (from -> {to}) — every transition is validated against this
EDGES = {
    "discovered":     {"scored", "dismissed"},
    "scored":         {"verifying", "lead_exhausted", "dismissed"},
    "verifying":      {"confirmed", "scored", "lead_exhausted", "dismissed"},
    "confirmed":      {"reported", "staged", "dismissed", "scored"},  # staged = financial PoC-staging; scored = freshness bounce
    "staged":         {"reported", "dismissed", "scored"},            # human triggers staged PoC -> reported
    "reported":       {"submitted", "dismissed", "confirmed"},        # confirmed = bounce-back on re-validation fail
    "lead_exhausted": {"scored", "dismissed"},                        # re-open on a new signal
    "submitted":      set(),
    "dismissed":      {"scored"},
}


def _utc() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def connect(db_path: str = DB_PATH) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=30, isolation_level=None)  # autocommit; we BEGIN explicitly
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    with open(SCHEMA, "r", encoding="utf-8") as fh:
        conn.executescript(fh.read())


def fp_signature(host: str, signal_class: str | None, vuln_class: str | None) -> str:
    """Stable signature for FP/dup matching — same logical finding => same sig."""
    raw = f"{(host or '').lower()}|{signal_class or ''}|{vuln_class or ''}"
    return hashlib.sha1(raw.encode("utf-8", "ignore")).hexdigest()[:20]


def _audit(conn, finding_id, event, frm=None, to=None, detail=None):
    conn.execute(
        "INSERT INTO audit_log(finding_id,event,from_state,to_state,detail,at) VALUES(?,?,?,?,?,?)",
        (finding_id, event, frm, to, detail, _utc()),
    )


# ---- findings ---------------------------------------------------------------
def upsert_finding(conn, host, *, url=None, program=None, tier="FINANCIAL",
                   signal_class=None, vuln_class=None, score=0, priority=None,
                   state="scored", ttl_at=None) -> int:
    """Insert or refresh a finding. Returns finding id. Does NOT regress state of
    an existing in-flight finding (only updates score/priority/metadata)."""
    dedup = f"{(host or '').lower()}|{signal_class or ''}|{vuln_class or ''}"
    sig = fp_signature(host, signal_class, vuln_class)
    now = _utc()
    with conn:
        conn.execute("BEGIN")
        row = conn.execute("SELECT id,state FROM findings WHERE dedup_key=?", (dedup,)).fetchone()
        if row is None:
            cur = conn.execute(
                """INSERT INTO findings(dedup_key,host,url,program,tier,signal_class,vuln_class,
                   state,score,priority,fp_signature,created_at,updated_at,state_changed_at,ttl_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (dedup, host, url, program, tier, signal_class, vuln_class, state,
                 score, priority, sig, now, now, now, ttl_at),
            )
            fid = cur.lastrowid
            _audit(conn, fid, "discovered", None, state, f"score={score}")
            return fid
        conn.execute(
            """UPDATE findings SET url=COALESCE(?,url), program=COALESCE(?,program),
               tier=?, score=?, priority=?, updated_at=? WHERE id=?""",
            (url, program, tier, score, priority, now, row["id"]),
        )
        return row["id"]


def transition(conn, finding_id: int, to_state: str, *, expect: str | None = None,
               **fields) -> bool:
    """Atomic, guarded state change. If `expect` is given, only fires when the row
    is currently in that state (optimistic lock → no double-fire under concurrency
    or after a crash). Returns True if it fired."""
    now = _utc()
    sets = ["state=?", "state_changed_at=?", "updated_at=?"]
    vals = [to_state, now, now]
    # verifying_since is the crash-resume key: set on entry, clear on exit
    if to_state == "verifying":
        sets.append("verifying_since=?"); vals.append(now)
    else:
        sets.append("verifying_since=NULL")
    for k, v in fields.items():
        if k in {"score", "priority", "evidence", "attempts", "last_error", "ttl_at", "max_attempts"}:
            sets.append(f"{k}=?")
            vals.append(json.dumps(v) if k == "evidence" and not isinstance(v, str) else v)
    where = "id=?"; vals.append(finding_id)
    if expect is not None:
        if to_state not in EDGES.get(expect, set()):
            raise ValueError(f"illegal transition {expect} -> {to_state}")
        where += " AND state=?"; vals.append(expect)
    with conn:
        conn.execute("BEGIN")
        cur = conn.execute(f"UPDATE findings SET {', '.join(sets)} WHERE {where}", vals)
        if cur.rowcount == 1:
            _audit(conn, finding_id, "transition", expect, to_state, fields.get("last_error"))
            return True
        return False  # lost the race / wrong expected state


def claim_for_verify(conn, limit: int = 30) -> list[sqlite3.Row]:
    """Atomically move up to `limit` 'scored' findings to 'verifying' and return
    them — the verification queue pull. Concurrency-safe (each row claimed once)."""
    claimed = []
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        rows = conn.execute(
            "SELECT * FROM findings WHERE state='scored' ORDER BY score DESC LIMIT ?", (limit,)
        ).fetchall()
        now = _utc()
        for r in rows:
            cur = conn.execute(
                "UPDATE findings SET state='verifying',verifying_since=?,state_changed_at=?,updated_at=? "
                "WHERE id=? AND state='scored'", (now, now, now, r["id"]))
            if cur.rowcount == 1:
                _audit(conn, r["id"], "transition", "scored", "verifying", "claimed")
                claimed.append(r)
    return claimed


def resume_stale_verifying(conn, stale_secs: int = 3600) -> int:
    """CRASH SAFETY: any finding stuck in 'verifying' longer than stale_secs (the
    orchestrator died mid-probe) is reset to 'scored' to be re-claimed. Idempotent
    probes + guarded promotion (verifying->confirmed) mean this never double-fires."""
    cutoff = (_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(seconds=stale_secs)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with conn:
        conn.execute("BEGIN")
        cur = conn.execute(
            "UPDATE findings SET state='scored',verifying_since=NULL,state_changed_at=? "
            "WHERE state='verifying' AND (verifying_since IS NULL OR verifying_since < ?)",
            (_utc(), cutoff))
        n = cur.rowcount
        if n:
            conn.execute("INSERT INTO audit_log(event,detail,at) VALUES('resume',?,?)",
                         (f"reset {n} stale verifying -> scored", _utc()))
    return n


# ---- false-positive signatures ---------------------------------------------
def record_fp(conn, signature: str, reason: str = "", source: str = "dismissed") -> None:
    now = _utc()
    with conn:
        conn.execute("BEGIN")
        conn.execute(
            """INSERT INTO false_positive_signatures(signature,reason,source,created_at,last_seen_at)
               VALUES(?,?,?,?,?)
               ON CONFLICT(signature) DO UPDATE SET reason=excluded.reason, source=excluded.source""",
            (signature, reason, source, now, now))


def is_fp(conn, signature: str) -> bool:
    """Query BEFORE scanning. Records a suppression hit so the FP list shows its value."""
    row = conn.execute("SELECT id FROM false_positive_signatures WHERE signature=?", (signature,)).fetchone()
    if row is None:
        return False
    with conn:
        conn.execute("UPDATE false_positive_signatures SET hit_count=hit_count+1,last_seen_at=? WHERE id=?",
                     (_utc(), row["id"]))
    return True


# ---- failure patterns (rate-limit / ban recovery) ---------------------------
_BACKOFF = {  # categorized exponential backoff seconds, capped at 1h (Phase D model)
    "rate-limit": [30, 120, 600, 1800, 3600],
    "http-403-streak": [60, 300, 1800, 3600],
    "timeout": [30, 120, 600],
    "dns-fail": [300, 1800, 3600],
    "ban": [3600], "captcha": [3600],   # ban/captcha → effectively halt (Phase D alerts + no auto-resume)
}


def record_failure(conn, pattern_type: str, target: str, detail: str = "") -> str:
    """Upsert a failure, advance categorized backoff, return recovery_state.
    ban/captcha return 'halted' (Phase D turns that into full stop + human alert)."""
    now = _utc()
    with conn:
        conn.execute("BEGIN")
        row = conn.execute("SELECT * FROM failure_patterns WHERE pattern_type=? AND target=?",
                           (pattern_type, target)).fetchone()
        count = (row["count"] + 1) if row else 1
        ladder = _BACKOFF.get(pattern_type, [60, 600, 3600])
        backoff = ladder[min(count - 1, len(ladder) - 1)]
        rstate = "halted" if pattern_type in ("ban", "captcha") else "backoff"
        until = (_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(seconds=backoff)).strftime("%Y-%m-%dT%H:%M:%SZ")
        if row:
            conn.execute("UPDATE failure_patterns SET count=?,detail=?,recovery_state=?,backoff_until=?,last_at=? WHERE id=?",
                         (count, detail, rstate, until, now, row["id"]))
        else:
            conn.execute("INSERT INTO failure_patterns(pattern_type,target,detail,count,recovery_state,backoff_until,first_at,last_at) VALUES(?,?,?,?,?,?,?,?)",
                         (pattern_type, target, detail, count, rstate, until, now, now))
    return rstate


def backoff_active(conn, target: str) -> bool:
    """True if target is inside a backoff window or halted — caller must skip it."""
    row = conn.execute(
        "SELECT recovery_state,backoff_until FROM failure_patterns WHERE target=? "
        "AND recovery_state IN ('backoff','halted') ORDER BY last_at DESC LIMIT 1", (target,)).fetchone()
    if row is None:
        return False
    if row["recovery_state"] == "halted":
        return True
    return bool(row["backoff_until"] and row["backoff_until"] > _utc())


# ---- counters (per-program volume + LLM spend, Phase D ceilings) ------------
def incr_counter(conn, scope: str, metric: str, by: float = 1.0, day: str | None = None) -> float:
    day = day or _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")
    with conn:
        conn.execute("BEGIN")
        conn.execute(
            "INSERT INTO run_counters(day,scope,metric,value) VALUES(?,?,?,?) "
            "ON CONFLICT(day,scope,metric) DO UPDATE SET value=value+excluded.value",
            (day, scope, metric, by))
        row = conn.execute("SELECT value FROM run_counters WHERE day=? AND scope=? AND metric=?",
                           (day, scope, metric)).fetchone()
    return row["value"] if row else by


def get_counter(conn, scope: str, metric: str, day: str | None = None) -> float:
    day = day or _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")
    row = conn.execute("SELECT value FROM run_counters WHERE day=? AND scope=? AND metric=?",
                       (day, scope, metric)).fetchone()
    return row["value"] if row else 0.0


def review_tier_for(confidence: float) -> str:
    return "immediate" if confidence >= 0.85 else ("batch" if confidence >= 0.70 else "weekly")


def record_confirmed(conn, host, *, url=None, program=None, signal_class=None,
                     vuln_class=None, score=0, evidence=None, confidence=0.0) -> int:
    """Authoritative gate write: a probe fired → finding is CONFIRMED. Upserts and
    forces state=confirmed (the gate already verified non-intrusively). Tier comes
    from Gate 0. Idempotent on dedup_key."""
    import tier as _tier
    tier = _tier.classify(program)
    dedup = f"{(host or '').lower()}|{signal_class or ''}|{vuln_class or ''}"
    sig = fp_signature(host, signal_class, vuln_class)
    ev = evidence if isinstance(evidence, str) else json.dumps(evidence or {})
    rt = review_tier_for(confidence)
    now = _utc()
    with conn:
        conn.execute("BEGIN")
        cur = conn.execute(
            """INSERT INTO findings(dedup_key,host,url,program,tier,signal_class,vuln_class,
               state,score,confidence,review_tier,fp_signature,evidence,created_at,updated_at,state_changed_at,verifying_since)
               VALUES(?,?,?,?,?,?,?, 'confirmed',?,?,?,?,?,?,?,?,NULL)
               ON CONFLICT(dedup_key) DO UPDATE SET state='confirmed', url=COALESCE(excluded.url,url),
                 program=excluded.program, tier=excluded.tier, score=excluded.score,
                 confidence=excluded.confidence, review_tier=excluded.review_tier,
                 evidence=excluded.evidence, updated_at=excluded.updated_at,
                 state_changed_at=excluded.state_changed_at, verifying_since=NULL""",
            (dedup, host, url, program, tier, signal_class, vuln_class, score, confidence, rt, sig, ev, now, now, now))
        fid = conn.execute("SELECT id FROM findings WHERE dedup_key=?", (dedup,)).fetchone()["id"]
        _audit(conn, fid, "promote", None, "confirmed", f"confidence={confidence} tier={tier} review={rt}")
    return fid


def stats(conn) -> dict:
    out = {"by_state": {}, "fp_signatures": 0, "failures_active": 0}
    for r in conn.execute("SELECT state,COUNT(*) c FROM findings GROUP BY state"):
        out["by_state"][r["state"]] = r["c"]
    out["fp_signatures"] = conn.execute("SELECT COUNT(*) c FROM false_positive_signatures").fetchone()["c"]
    out["failures_active"] = conn.execute(
        "SELECT COUNT(*) c FROM failure_patterns WHERE recovery_state IN ('backoff','halted')").fetchone()["c"]
    return out


def _main(argv):
    import sys
    conn = connect()
    init_db(conn)
    cmd = argv[1] if len(argv) > 1 else "stats"
    a = argv[2:]
    if cmd == "init":
        print(f"initialized {DB_PATH}")
    elif cmd == "resume":
        print(f"resumed (stale verifying -> scored): {resume_stale_verifying(conn)}")
    elif cmd == "stats":
        print(json.dumps(stats(conn), indent=2))
    elif cmd == "check-fp":   # check-fp <host> <signal_class> [vuln_class] ; prints FP|OK, exit 0=FP
        sig = fp_signature(a[0], a[1] if len(a) > 1 else "", a[2] if len(a) > 2 else "")
        hit = is_fp(conn, sig)
        print("FP" if hit else "OK")   # robust signal (callers match stdout, not just exit)
        return 0 if hit else 1
    elif cmd == "record-fp":  # record-fp <host> <signal_class> [vuln_class] [reason] [source]
        sig = fp_signature(a[0], a[1] if len(a) > 1 else "", a[2] if len(a) > 2 else "")
        record_fp(conn, sig, a[3] if len(a) > 3 else "", a[4] if len(a) > 4 else "gate-exhausted")
        print(sig)
    elif cmd == "record-confirmed":  # host url program signal_class vuln_class score confidence evidence_json
        record_confirmed(conn, a[0], url=a[1], program=a[2], signal_class=a[3],
                         vuln_class=(a[4] or None), score=int(a[5] or 0),
                         confidence=float(a[6] or 0), evidence=(a[7] if len(a) > 7 else "{}"))
        print("confirmed")
    else:
        print("usage: state.py {init|resume|stats|check-fp|record-fp|record-confirmed ...}", file=sys.stderr); return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(__import__("sys").argv))

#!/usr/bin/env python3
"""
transition.py — mint on CHANGE, not on STATE.

Why this exists
---------------
An evaluation on 2026-08-17 found 316 false positives in 320 minted findings, and zero
`real` verdicts in 65 days. The cause was structural, not a tuning error:

    The lanes fire on a STATE.  "Port 6379 is open."  "This CNAME points to S3."
    "This response contains a token-shaped string."

A state is always true, so it fires forever, and on any large estate ~95% of the hosts
matching it are that way by design. That is the entire false-positive population.

Professional continuous-monitoring setups fire on a TRANSITION instead — the thing that
did not exist yesterday and exists today. EdOverflow's classic setup gets zero false
positives *by construction* because the whole mechanism is `git commit`: git will not
commit an unmodified file, so only new data can ever raise an alert. Assetnote rescans
hourly and sells the diff, not the scan.

The model here is the same:

    first sighting  -> record the baseline, stay SILENT
    changed         -> MINT (this is news)
    unchanged       -> suppress

Staying silent on a first sighting is deliberate, and it is the part that does the work.
Something already exposed when we started watching has been exposed for months — every
other hunter has already found it, so it is a duplicate by definition. The exposure that
appeared *today* is the one nobody has reported yet. Suppressing first-sight noise and
alerting on new exposure is the same trade the motto already makes: be first to fresh
surface.

Lanes that confirm a PRIMITIVE rather than observe a state are exempt (see ALWAYS_MINT).
A public-writable bucket, an unauth Cognito credential issuance, an auth bypass or an
authdiff differential are not "states that happen to be true" — they are tests that fired,
and a test firing is news the first time.

Disable with RECON_TRANSITION_GATE=0. Fails OPEN: any error here allows the mint through,
because losing a real finding is worse than one extra false positive.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone

DB_PATH = os.environ.get(
    "TRANSITION_DB",
    os.path.join(os.path.expanduser("~"), "recon", "v3", "observations.db"),
)

# Signal classes that confirm a PRIMITIVE (a test fired) rather than observe a state.
# These mint on first sight — that is exactly when they are news.
ALWAYS_MINT = {
    "authdiff",         # unauth == authed differential
    "bucket-exposure",  # public-WRITE / ACL-write, not mere existence
    "cognito-unauth",   # credentials actually issued
    "wcd-purge",        # cache purge reachable unauthenticated
    "auth-bypass",      # a bypass demonstrably worked
    "xss",              # payload executed in a headless browser
    "sqli",             # injection differential fired
}

# State-observation lanes. Every one of these has a lifetime `real` rate of zero.
# They keep enumerating; they only mint when what they see CHANGES.
STATE_LANES = {
    "portscan", "takeover", "takeover-dangling-ns", "unauth-data-exposure",
    "exposed-actuator", "info-disclosure", "ai-hunter", "n-day", "data-leak",
    "exposure", "graphql",
}


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def connect(path: str = DB_PATH) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path, timeout=20)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS observations (
            obs_key      TEXT PRIMARY KEY,   -- lane|host|vuln_class
            lane         TEXT NOT NULL,
            host         TEXT NOT NULL,
            vuln_class   TEXT,
            fingerprint  TEXT NOT NULL,      -- hash of the OBSERVED VALUE
            first_seen   TEXT NOT NULL,
            last_seen    TEXT NOT NULL,
            last_changed TEXT,
            seen_count   INTEGER NOT NULL DEFAULT 1,
            change_count INTEGER NOT NULL DEFAULT 0,
            last_value   TEXT                -- truncated, for the diff in the alert
        )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_obs_lane ON observations(lane)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_obs_host ON observations(host)")
    conn.commit()
    return conn


def _fingerprint(evidence: str) -> tuple[str, str]:
    """Reduce the evidence blob to the part that represents WHAT WAS OBSERVED, so that
    re-running the same scan produces the same fingerprint while a genuine change does
    not. Timestamps, scan ids and run counters are stripped — they change every cycle
    and would make every observation look new."""
    val = evidence or ""
    try:
        o = json.loads(val)
        if isinstance(o, dict):
            drop = {"at", "ts", "time", "timestamp", "scanned_at", "matched_at", "date",
                    "run_id", "scan_id", "elapsed", "duration", "seen_at", "created_at"}
            o = {k: v for k, v in sorted(o.items()) if k.lower() not in drop}
            val = json.dumps(o, sort_keys=True, default=str)
    except Exception:
        pass
    return hashlib.sha256(val.encode("utf-8", "replace")).hexdigest()[:32], val[:500]


def check(lane: str, host: str, vuln_class: str, evidence: str,
          conn: sqlite3.Connection | None = None) -> dict:
    """Decide whether this observation is news.

    Returns {"mint": bool, "status": new|changed|same|always, "reason": str}.
    """
    lane = (lane or "").strip()
    host = (host or "").strip().lower()
    vc = (vuln_class or "").strip()

    if lane in ALWAYS_MINT:
        return {"mint": True, "status": "always",
                "reason": f"{lane} confirms a primitive — news on first sight"}

    own = conn is None
    conn = conn or connect()
    try:
        key = f"{lane}|{host}|{vc}"
        fp, val = _fingerprint(evidence)
        now = _utc()
        row = conn.execute("SELECT * FROM observations WHERE obs_key=?", (key,)).fetchone()

        if row is None:
            conn.execute(
                """INSERT INTO observations(obs_key,lane,host,vuln_class,fingerprint,
                   first_seen,last_seen,last_changed,seen_count,change_count,last_value)
                   VALUES(?,?,?,?,?,?,?,NULL,1,0,?)""",
                (key, lane, host, vc, fp, now, now, val))
            conn.commit()
            gated = lane in STATE_LANES
            return {"mint": not gated, "status": "new",
                    "reason": ("baseline recorded — a state already true when we started "
                               "watching has been true for months and is a duplicate; "
                               "will mint if it CHANGES")
                    if gated else "first sighting on an ungated lane"}

        if row["fingerprint"] == fp:
            conn.execute(
                "UPDATE observations SET last_seen=?, seen_count=seen_count+1 WHERE obs_key=?",
                (now, key))
            conn.commit()
            return {"mint": False, "status": "same",
                    "reason": f"unchanged since {row['first_seen']} "
                              f"(seen {row['seen_count'] + 1}x) — not news"}

        conn.execute(
            """UPDATE observations SET fingerprint=?, last_seen=?, last_changed=?,
               seen_count=seen_count+1, change_count=change_count+1, last_value=?
               WHERE obs_key=?""",
            (fp, now, now, val, key))
        conn.commit()
        return {"mint": True, "status": "changed",
                "reason": f"CHANGED since {row['last_changed'] or row['first_seen']} "
                          f"(change #{row['change_count'] + 1}) — this is news"}
    finally:
        if own:
            conn.close()


def stats(conn: sqlite3.Connection | None = None) -> dict:
    own = conn is None
    conn = conn or connect()
    try:
        out = {"total": conn.execute("SELECT count(*) FROM observations").fetchone()[0],
               "by_lane": {}}
        for r in conn.execute(
                """SELECT lane, count(*) n, sum(change_count) ch, sum(seen_count) seen
                   FROM observations GROUP BY 1 ORDER BY n DESC"""):
            out["by_lane"][r["lane"]] = {
                "tracked": r["n"], "changes": r["ch"] or 0, "observations": r["seen"] or 0,
                "suppressed": (r["seen"] or 0) - (r["ch"] or 0) - r["n"]}
        return out
    finally:
        if own:
            conn.close()


def _main(argv: list[str]) -> int:
    if not argv:
        print("usage: transition.py check <lane> <host> <vuln_class> <evidence_json>\n"
              "       transition.py stats", file=sys.stderr)
        return 2
    cmd = argv[0]
    if cmd == "stats":
        print(json.dumps(stats(), indent=2))
        return 0
    if cmd == "check":
        if os.environ.get("RECON_TRANSITION_GATE") == "0":
            print(json.dumps({"mint": True, "status": "disabled",
                              "reason": "RECON_TRANSITION_GATE=0"}))
            return 0
        lane, host, vc = (argv[1:4] + ["", "", ""])[:3]
        ev = argv[4] if len(argv) > 4 else ""
        try:
            print(json.dumps(check(lane, host, vc, ev)))
        except Exception as e:
            # fail OPEN — never lose a finding to a bug in the gate
            print(json.dumps({"mint": True, "status": "error", "reason": str(e)[:200]}))
        return 0
    print(f"unknown command {cmd!r}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))

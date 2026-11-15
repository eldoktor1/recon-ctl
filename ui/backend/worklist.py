"""The worklist: confirmed vulns only, behind one strict gate.

WHY (operator 2026-11-14): the old worklist parsed the prose briefings (2IC_tonight, hunter,
freshchain, tonight) and turned every bullet with a hostname into a lead row. A briefing bullet
is a NOTE, not a vuln: rows read "credential endpoints properly gated. SECURE.", "leakchain
clean", "FP, properly delegated". 80 rows were on the board and every one was a false positive.
That is the opposite of the job, which is to show only serious, real vulns.

So the worklist no longer reads briefings at all. Its only source is findings.db, and only
rows a lane MINTED (state = confirmed). Under the CHAIN-TO-IMPACT LAW a mint already means
recovered impact; this module then throws out anything that still smells like an FP. Each
discarded row is counted under the reason that dropped it, so the page can say what it held
back without listing it.

Two tiers come out:
  ready  - ai_verdict = real (survived the consensus panel). File it.
  check  - minted, not yet judged real. Look before filing.

Gate, in order (first match wins):
  1. Claude verdict fp
  2. host worked and killed by a DEAD note, or class-FP'd for this vuln class
  3. host benched (active ignore)
  4. same fp_signature as a finding already dismissed as an FP
  5. product-class: the same API route (2+ path segments, ids collapsed) minted on more than
     FANOUT_MAX hosts
  6. below SERIOUS_MIN_SCORE (the impact layer's floor for recovered impact)
  7. unjudged and older than STALE_DAYS (CONFIRMED past its freshness is STALE, a LEAD)
A `real` verdict skips gates 2, 3 and 6: a consensus-real finding IS the "new signal" a kill
note says it waits for, and its severity was already argued by the panel. It does not skip 1,
4 or 5, which are what an FP or a duplicate looks like.

Read-only. Mutations still go through the CLI.
"""
from __future__ import annotations

import json
import re
import sqlite3
from collections import Counter, defaultdict
from contextlib import closing
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from . import config, files

# engine/impact.py severity_for scores recovered impact 11-20 (PII 11+, API creds 15, DB creds
# 18, signing keys 19, cloud keys 20); a confirmed takeover and an executed blind XSS are 15.
# Below 10 is a state or a version string, not a vuln.
SERIOUS_MIN_SCORE = 10
STALE_DAYS = 14
FANOUT_MAX = 5

COLS = ("id, host, url, program, signal_class, vuln_class, state, score, ai_verdict, "
        "ai_confidence, ai_reason, fp_signature, evidence, ai_report, created_at, "
        "state_changed_at")

_ID_SEG = re.compile(r"^(?:\d+|[0-9a-f]{8,}|[0-9a-f-]{32,36})$", re.I)


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(f"file:{config.FINDINGS_DB}?mode=ro", uri=True, timeout=5)
    c.row_factory = sqlite3.Row
    return c


def _ts(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def _json(v: Any) -> dict:
    if isinstance(v, str) and v:
        try:
            v = json.loads(v)
        except ValueError:
            return {}
    return v if isinstance(v, dict) else {}


def _template(url: str | None) -> str:
    """Path with id-like segments collapsed, so /u/123 and /u/456 count as one endpoint.

    Returns "" (not an endpoint, never fan-out gated) for a path under 2 segments. A takeover
    or a root exposure lives at "/", and "/.env" on six unrelated hosts is six bugs, not one
    product. Only a real API route (/proxy/users/{id}, the UniFi case) is a product fingerprint."""
    if not url:
        return ""
    try:
        path = urlsplit(url).path or "/"
    except ValueError:
        return ""
    segs = [s for s in path.split("/") if s]
    if len(segs) < 2:
        return ""
    return "/" + "/".join("{id}" if _ID_SEG.match(s) else s for s in segs)


def _cls(r: sqlite3.Row) -> str:
    return (r["vuln_class"] or r["signal_class"] or "").lower()


def _class_killed(host: str, vclass: str, killed_cls: dict[str, set[str]]) -> bool:
    # note_verdict classes are coarse (xss, secret, takeover, graphql); findings carry finer
    # names (graphql-introspection, s3-open-bucket), so match on containment.
    return any(k and k in vclass for k in killed_cls.get(host, ()))


def _severity(score: int) -> str:
    return "critical" if score >= 18 else "high" if score >= 14 else "medium"


def _impact(r: sqlite3.Row) -> str:
    rep, ev = _json(r["ai_report"]), _json(r["evidence"])
    for v in (rep.get("title"), ev.get("impact"), r["ai_reason"]):
        if isinstance(v, str) and v.strip():
            return v.strip()
    return f"{_cls(r) or 'finding'} on {r['host']}"


def build(now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    with closing(_conn()) as c:
        rows = c.execute(f"SELECT {COLS} FROM findings").fetchall()

    fp_sigs = {r["fp_signature"] for r in rows
               if r["fp_signature"] and (r["ai_verdict"] == "fp" or r["state"] == "dismissed")}
    fanout: dict[tuple[str, str], set[str]] = defaultdict(set)
    for r in rows:
        if tmpl := _template(r["url"]):
            fanout[(_cls(r), tmpl)].add((r["host"] or "").lower())

    killed = files.killed_host_set()
    killed_cls = files.killed_host_classes()
    benched = files.benched_host_set()

    held: Counter[str] = Counter()
    ready: list[dict[str, Any]] = []
    check: list[dict[str, Any]] = []
    for r in rows:
        if r["state"] != "confirmed":
            continue
        host = (r["host"] or "").lower()
        vclass = _cls(r)
        real = r["ai_verdict"] == "real"
        score = int(r["score"] or 0)
        minted = _ts(r["state_changed_at"]) or _ts(r["created_at"])
        age_days = (now - minted).days if minted else None
        tmpl = _template(r["url"])
        fan = len(fanout.get((vclass, tmpl), ())) if tmpl else 0

        if r["ai_verdict"] == "fp":
            reason = "Claude verdict FP"
        elif not real and host in killed:
            reason = "host worked and killed"
        elif not real and _class_killed(host, vclass, killed_cls):
            reason = "class marked FP on this host"
        elif not real and host in benched:
            reason = "host benched"
        elif r["fp_signature"] in fp_sigs:
            reason = "matches a dismissed FP"
        elif fan > FANOUT_MAX:
            reason = "product-class (same endpoint on many hosts)"
        elif not real and score < SERIOUS_MIN_SCORE:
            reason = "below the serious-impact floor"
        elif not real and age_days is not None and age_days > STALE_DAYS:
            reason = f"stale, unjudged for over {STALE_DAYS} days"
        else:
            reason = ""
        if reason:
            held[reason] += 1
            continue

        item = {
            "id": r["id"], "host": r["host"], "url": r["url"], "program": r["program"],
            "vuln_class": vclass or None, "score": score, "severity": _severity(score),
            "verdict": r["ai_verdict"], "confidence": r["ai_confidence"],
            "impact": _impact(r), "minted_at": r["state_changed_at"] or r["created_at"],
            "age_days": age_days,
        }
        (ready if real else check).append(item)

    for lst in (ready, check):
        lst.sort(key=lambda i: (-i["score"], i["age_days"] if i["age_days"] is not None else 1e9))

    newest = max((r["created_at"] for r in rows if r["created_at"]), default=None)
    return {
        "ready": ready,
        "check": check,
        "held": dict(held.most_common()),
        "held_total": sum(held.values()),
        "filed": sum(1 for r in rows if r["state"] in ("reported", "submitted")),
        "newest_mint": newest,
        "gate": {"serious_min_score": SERIOUS_MIN_SCORE, "stale_days": STALE_DAYS,
                 "fanout_max": FANOUT_MAX},
    }

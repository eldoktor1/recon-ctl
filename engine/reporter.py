#!/usr/bin/env python3
"""v3 Phase C — Reporter.

Confirmed findings (SQLite state truth) + asset data (ES) -> a submission-ready
report per platform, written to a human review queue. NEVER submits or touches a
platform API (auto-submission is explicitly out of scope).

Pipeline per confirmed finding:
  1. dup pre-check  — own submission history + (pluggable) platform known-issues
  2. freshness gate — if evidence older than TTL, RE-PROBE; a since-patched bug is
                      bounced back (confirmed -> scored) and NOT reported
  3. render         — internal Finding -> platform formatter
  4. emit           — write report file + review-queue row; state confirmed -> reported
"""
from __future__ import annotations
import os, sys, json, subprocess, datetime as _dt

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import state as S
import formatters as F

ES_URL = os.environ.get("ES_URL", "http://127.0.0.1:9200")
INDEX = os.environ.get("INDEX_NAME", "recon_alive")
NETRC = os.path.expanduser("~/.recon_es_netrc")
REPORTS_DIR = os.environ.get("V3_REPORTS", os.path.expanduser("~/recon/v3/reports"))
REVIEW_QUEUE = os.path.join(REPORTS_DIR, "review_queue.jsonl")
SUBS = os.path.expanduser("~/.recon_submissions.jsonl")
REVALIDATE_TTL_SECS = int(os.environ.get("REPORT_REVALIDATE_TTL", str(3 * 86400)))  # 3d
NUCLEI = os.environ.get("NUCLEI_BIN", "nuclei")

_NUCLEI_TAGS = {  # mirror the gate's non-intrusive classes for re-probe
    "version": "tech,detect,version,cve,exposure",
    "unauth-surface": "exposure,exposed-panel,unauth,misconfig,default-login",
    "content-leak": "exposure,disclosure,files,listing,backup,config",
}


def _utc():
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _es_source(host: str) -> dict:
    """Asset truth from ES (program/platform/url/root_domain). Override in tests via
    reporter._es_source = lambda h: {...}."""
    try:
        out = subprocess.run(
            ["curl", "-fsS", "-m", "15", "--netrc-file", NETRC, f"{ES_URL}/{INDEX}/_source/{host}"],
            capture_output=True, text=True, timeout=20)
        return json.loads(out.stdout) if out.stdout.strip() else {}
    except Exception:
        return {}


# ---- 1. duplicate pre-check -------------------------------------------------
def _load_subs():
    subs = []
    if os.path.exists(SUBS):
        with open(SUBS, "r", encoding="utf-8", errors="ignore") as fh:
            for ln in fh:
                ln = ln.strip()
                if ln:
                    try:
                        subs.append(json.loads(ln))
                    except Exception:
                        pass
    return subs


def dup_check(host: str, root_domain: str, vuln_class: str, subs=None) -> tuple[str, str]:
    """Own-history dup pre-check. Returns (status, detail). Platform known-issue
    lookup is a pluggable hook (most platforms need authed API; default unknown)."""
    subs = _load_subs() if subs is None else subs
    for s in subs:
        if s.get("status") in ("rejected", "duplicate"):
            continue
        if s.get("host") == host and (not vuln_class or s.get("vuln_class") == vuln_class):
            return ("likely-dup", f"own history: same host+class already submitted ({s.get('submitted_date','?')})")
    for s in subs:
        if s.get("status") in ("rejected", "duplicate"):
            continue
        if root_domain and s.get("root_domain") == root_domain and s.get("vuln_class") == vuln_class:
            return ("likely-dup", f"own history: same root_domain+class submitted ({s.get('root_domain')})")
    plat = platform_known_issue(host, vuln_class)
    return plat if plat else ("no-known-dup", "no match in own submission history")


def platform_known_issue(host: str, vuln_class: str):
    """Hook: where a platform exposes known-issues/recent-activity (authed), check
    here. Default: unavailable -> None (caller falls back to no-known-dup)."""
    return None


# ---- 2. freshness re-validation --------------------------------------------
def _age_secs(ts: str) -> float:
    try:
        t = _dt.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_dt.timezone.utc)
        return (_dt.datetime.now(_dt.timezone.utc) - t).total_seconds()
    except Exception:
        return 1e9


def reprobe(url: str, signal_class: str) -> bool:
    """Non-intrusive re-probe (reuse nuclei). True if the indicator still fires."""
    tags = _NUCLEI_TAGS.get(signal_class)
    if not tags or not url:
        return True  # classes we can't cheaply re-probe (xss/bypass) -> trust prior confirm
    try:
        out = subprocess.run(
            [NUCLEI, "-u", url, "-tags", tags, "-etags", "intrusive,dos,fuzz,xss,rce",
             "-silent", "-jsonl", "-nc", "-duc", "-rl", "50"],
            capture_output=True, text=True, timeout=120)
        return bool(out.stdout.strip())
    except Exception:
        return True  # probe error -> don't drop a real finding; human reviews


# ---- 3+4. build, render, emit ----------------------------------------------
def _build_finding(row, asset) -> F.Finding:
    ev = {}
    if row["evidence"]:
        try:
            ev = json.loads(row["evidence"])
        except Exception:
            ev = {"response": str(row["evidence"])}
    return F.Finding(
        host=row["host"],
        url=row["url"] or asset.get("url") or f"https://{row['host']}",
        program=row["program"] or asset.get("triage_program") or "",
        platform=asset.get("triage_platform") or "",
        vuln_class=row["vuln_class"] or "info-disclosure",
        signal_class=row["signal_class"] or "",
        evidence=ev,
        confirmed_at=row["state_changed_at"],
        scope_confirmation=(f"Program: {row['program'] or asset.get('triage_program','?')} · "
                            f"in_scope={asset.get('triage_in_scope','?')} · pays={asset.get('triage_pays','?')}"),
    )


def run(conn, limit: int = 50) -> dict:
    os.makedirs(REPORTS_DIR, exist_ok=True)
    # Report only Claude-validated 'real' findings; un-reviewed high-confidence ones
    # fall through (so we don't lose findings if AI review lags / is off). 'fp' are
    # already dismissed; 'needs-human' are held out of the auto queue by design.
    fallback = float(os.environ.get("REPORT_CONF_FALLBACK", "0.85"))
    rows = conn.execute(
        "SELECT * FROM findings WHERE state='confirmed' AND "
        "(ai_verdict='real' OR (ai_verdict IS NULL AND confidence >= ?)) "
        "ORDER BY (ai_verdict='real') DESC, confidence DESC LIMIT ?",
        (fallback, limit)).fetchall()
    subs = _load_subs()
    out = {"reported": 0, "bounced_stale": 0, "flagged_dup": 0}
    for row in rows:
        asset = _es_source(row["host"])
        root = asset.get("root_domain", "")
        # freshness gate
        ev = json.loads(row["evidence"]) if row["evidence"] else {}
        revalidated = ""
        if _age_secs(row["state_changed_at"]) > REVALIDATE_TTL_SECS:
            if not reprobe(row["url"] or asset.get("url", ""), row["signal_class"] or ""):
                S.transition(conn, row["id"], "scored", expect="confirmed",
                             last_error="evidence stale: re-probe no longer fires (since-patched?)")
                out["bounced_stale"] += 1
                continue
            revalidated = _utc()
        # dup pre-check
        dstatus, ddetail = dup_check(row["host"], root, row["vuln_class"], subs)
        if dstatus == "likely-dup":
            out["flagged_dup"] += 1
        f = _build_finding(row, asset)
        f.dup_status, f.dup_detail, f.revalidated_at = dstatus, ddetail, revalidated
        report = F.render(f)
        safe = "".join(ch if ch.isalnum() or ch in ".-_" else "_" for ch in row["host"])
        path = os.path.join(REPORTS_DIR, f"{safe}__{row['vuln_class']}.{(f.platform or 'generic')}.md")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(report)
        with open(REVIEW_QUEUE, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"finding_id": row["id"], "host": row["host"], "program": f.program,
                                 "platform": f.platform, "vuln_class": row["vuln_class"],
                                 "ai_verdict": (row["ai_verdict"] or "unreviewed"),
                                 "ai_confidence": row["ai_confidence"], "ai_reason": row["ai_reason"],
                                 "dup_status": dstatus, "report": path, "queued_at": _utc(),
                                 "action_required": "HUMAN review + submit (never auto-submitted)"}) + "\n")
        S.transition(conn, row["id"], "reported", expect="confirmed")
        out["reported"] += 1
    return out


if __name__ == "__main__":
    c = S.connect(); S.init_db(c)
    print(json.dumps(run(c), indent=2))

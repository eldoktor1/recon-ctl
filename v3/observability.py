#!/usr/bin/env python3
"""v3 Phase E — Observability: the morning-after audit digest.

A queryable, auditable daily report of what the autonomous system did unattended —
NOT Discord pings. Because it runs against live targets while you're away, audit is
non-negotiable. Sourced entirely from the SQLite state store (audit_log, findings,
run_counters, failure_patterns, false_positive_signatures).

  observability.py [YYYY-MM-DD]   -> writes ~/recon/v3/digests/digest_<day>.md + prints
  observability.py json [day]     -> machine-readable
"""
from __future__ import annotations
import os, sys, json, datetime as _dt

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import state as S
try:
    from orchestrator import (PER_PROGRAM_DAILY_REQUESTS, LLM_DAILY_SPEND_CEILING_USD,
                              halted as _halted)
except Exception:
    PER_PROGRAM_DAILY_REQUESTS, LLM_DAILY_SPEND_CEILING_USD = 750, 20.0
    def _halted(): return None

DIGEST_DIR = os.path.expanduser(os.environ.get("V3_DIGESTS", "~/recon/v3/digests"))


def _today():
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")


def collect(conn, day: str) -> dict:
    like = day + "%"
    q = lambda sql, *a: conn.execute(sql, a).fetchall()

    # lifecycle activity today (from audit_log transitions)
    trans = {}
    for r in q("SELECT to_state, COUNT(*) c FROM audit_log WHERE event='transition' AND at LIKE ? GROUP BY to_state", like):
        trans[r["to_state"]] = r["c"]

    # dismissals with reasons today
    dismiss_reasons = [dict(r) for r in q(
        "SELECT f.host, f.last_error FROM audit_log a JOIN findings f ON f.id=a.finding_id "
        "WHERE a.event='transition' AND a.to_state='dismissed' AND a.at LIKE ? LIMIT 50", like)]

    # halts today + current halt
    halts = [dict(r) for r in q("SELECT detail, at FROM audit_log WHERE event='halt' AND at LIKE ?", like)]

    # per-program volume + global spend (run_counters)
    vol = [dict(r) for r in q(
        "SELECT scope, value FROM run_counters WHERE day=? AND metric='requests' AND scope!='GLOBAL' "
        "ORDER BY value DESC LIMIT 25", day)]
    near_ceiling = [v for v in vol if v["value"] >= 0.8 * PER_PROGRAM_DAILY_REQUESTS]
    spend = S.get_counter(conn, "GLOBAL", "llm_spend_usd", day)
    tests = sum(r["value"] for r in q("SELECT value FROM run_counters WHERE day=? AND metric='tests'", day))

    # FP suppression
    fp_total = q("SELECT COUNT(*) c FROM false_positive_signatures", )[0]["c"]
    fp_hits_today = q("SELECT COUNT(*) c, COALESCE(SUM(hit_count),0) s FROM false_positive_signatures WHERE last_seen_at LIKE ?", like)[0]

    # active failures / backoffs
    fails = [dict(r) for r in q(
        "SELECT pattern_type,target,count,recovery_state,backoff_until FROM failure_patterns "
        "WHERE recovery_state IN ('backoff','halted') ORDER BY last_at DESC LIMIT 25")]

    # current state distribution + queues
    state_dist = {r["state"]: r["c"] for r in q("SELECT state,COUNT(*) c FROM findings GROUP BY state")}
    review_queue = [dict(r) for r in q(
        "SELECT host,program,vuln_class FROM findings WHERE state='reported' ORDER BY score DESC LIMIT 50")]

    return {
        "day": day, "generated_at": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "halted_now": _halted(),
        "activity": {
            "tested": int(tests),
            "confirmed": trans.get("confirmed", 0),
            "reported": trans.get("reported", 0),
            "dismissed": trans.get("dismissed", 0),
            "lead_exhausted": trans.get("lead_exhausted", 0),
        },
        "halts_today": halts,
        "dismiss_reasons": dismiss_reasons,
        "api_spend_usd": round(spend, 4), "spend_ceiling_usd": LLM_DAILY_SPEND_CEILING_USD,
        "per_program_volume": vol, "near_ceiling": near_ceiling,
        "per_program_ceiling": PER_PROGRAM_DAILY_REQUESTS,
        "fp_skipped": {"signatures_total": fp_total,
                       "suppressed_today_sigs": fp_hits_today["c"], "suppressions_cumulative": fp_hits_today["s"]},
        "failures_active": fails,
        "state_distribution": state_dist,
        "review_queue_awaiting_submit": review_queue,
    }


def render(d: dict) -> str:
    a = d["activity"]
    L = []
    L.append(f"# v3 autonomous digest — {d['day']}  (generated {d['generated_at']})")
    if d["halted_now"]:
        L.append(f"\n## 🛑 HALTED RIGHT NOW: {d['halted_now']}\n(human must clear the halt flag to resume — no auto-resume)")
    L.append("\n## Activity")
    L.append(f"- tested (active): **{a['tested']}**")
    L.append(f"- confirmed (gate fired): **{a['confirmed']}**")
    L.append(f"- queued for report/review: **{a['reported']}**")
    L.append(f"- dismissed: **{a['dismissed']}**  ·  lead-exhausted: **{a['lead_exhausted']}**")
    L.append("\n## Safety / spend")
    L.append(f"- LLM API spend: **${d['api_spend_usd']}** / ${d['spend_ceiling_usd']} ceiling")
    halts = d["halts_today"]
    L.append(f"- halts today: **{len(halts)}**" + ("" if not halts else ""))
    for h in halts:
        L.append(f"    - {h['at']} — {h['detail']}")
    if d["failures_active"]:
        L.append(f"- active failures/backoffs: **{len(d['failures_active'])}**")
        for f in d["failures_active"][:10]:
            L.append(f"    - {f['pattern_type']} on {f['target']} (x{f['count']}, {f['recovery_state']}"
                     + (f", until {f['backoff_until']}" if f['backoff_until'] else "") + ")")
    L.append("\n## Per-program request volume (cap "
             f"{d['per_program_ceiling']}/day)")
    if d["near_ceiling"]:
        L.append("- ⚠️ NEAR/OVER CEILING: " + ", ".join(f"{v['scope']} ({int(v['value'])})" for v in d["near_ceiling"]))
    for v in d["per_program_volume"][:15]:
        L.append(f"    - {v['scope']}: {int(v['value'])}")
    fp = d["fp_skipped"]
    L.append("\n## Noise suppression (FP signatures)")
    L.append(f"- FP signatures on file: **{fp['signatures_total']}**  ·  "
             f"hit today: {fp['suppressed_today_sigs']}  ·  cumulative suppressions: {int(fp['suppressions_cumulative'])}")
    L.append("\n## Queues")
    L.append(f"- findings awaiting HUMAN review+submit: **{len(d['review_queue_awaiting_submit'])}**")
    for s in d["review_queue_awaiting_submit"][:15]:
        L.append(f"    - {s['host']} [{s['program']}] {s['vuln_class']}")
    L.append("\n## State distribution")
    L.append("  " + json.dumps(d["state_distribution"]))
    if d["dismiss_reasons"]:
        L.append("\n## Dismissals (why)")
        for r in d["dismiss_reasons"][:20]:
            L.append(f"    - {r['host']}: {r['last_error'] or '-'}")
    return "\n".join(L) + "\n"


def _discord_digest(d: dict) -> None:
    """Best-effort COMPACT daily summary to #digest. The full auditable record is the
    .md file (source of truth); this is just the once-a-day heads-up the operator
    asked for. Reads the shared webhook (per-user file or shared discord dir). No API."""
    import urllib.request
    hook = ""
    for p in (os.path.expanduser("~/.recon_discord_digest"),
              os.path.join(os.environ.get("RECON_DISCORD_DIR", "/home/d0k/recon/state/discord"), "digest")):
        try:
            if os.path.isfile(p):
                hook = open(p, encoding="utf-8").read().strip()
                if hook:
                    break
        except Exception:
            pass
    if not hook:
        return
    a, fp = d["activity"], d["fp_skipped"]
    msg = (f"\U0001F4CA **v3 digest {d['day']}**\n"
           f"confirmed {a['confirmed']} · reported {a['reported']} · dismissed {a['dismissed']} "
           f"· lead-exhausted {a['lead_exhausted']}\n"
           f"review queue: {len(d['review_queue_awaiting_submit'])} awaiting submit\n"
           f"FP suppressed today: {fp['suppressed_today_sigs']} · LLM spend ${d['api_spend_usd']}"
           + (f"\n\U0001F6D1 HALTED: {d['halted_now']}" if d["halted_now"] else ""))
    try:
        req = urllib.request.Request(hook, data=json.dumps({"content": msg[:1900]}).encode(),
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=15)
    except Exception:
        pass


def main(argv):
    conn = S.connect(); S.init_db(conn)
    as_json = len(argv) > 1 and argv[1] == "json"
    day = (argv[2] if as_json and len(argv) > 2 else (argv[1] if len(argv) > 1 and not as_json else None)) or _today()
    d = collect(conn, day)
    if as_json:
        print(json.dumps(d, indent=2, default=str)); return 0
    os.makedirs(DIGEST_DIR, exist_ok=True)
    path = os.path.join(DIGEST_DIR, f"digest_{day}.md")
    out = render(d)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(out)
    print(out)
    print(f"\n[written: {path}]", file=sys.stderr)
    _discord_digest(d)   # compact #digest ping (best-effort; .md is the source of truth)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

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
import os, sys, json, re, datetime as _dt

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import state as S
try:
    from orchestrator import (PER_PROGRAM_DAILY_REQUESTS, LLM_DAILY_SPEND_CEILING_USD,
                              halted as _halted)
except Exception:
    PER_PROGRAM_DAILY_REQUESTS, LLM_DAILY_SPEND_CEILING_USD = 750, 20.0
    def _halted(): return None

DIGEST_DIR = os.path.expanduser(os.environ.get("V3_DIGESTS", "~/recon/v3/digests"))

# ---- per-lane yield self-audit (so no lane fails silently) -------------------
ES_URL            = os.environ.get("ES_URL", "http://127.0.0.1:9200")
STATE_DIR         = os.path.expanduser(os.environ.get("RECON_STATE_DIR", "~/recon/state"))
OBS_YIELD_WINDOW_D = int(os.environ.get("OBS_YIELD_WINDOW_D", "14"))
ENDPOINTS_STORE   = os.path.expanduser(os.environ.get("JS_ENDPOINT_STORE", "~/recon/js_recon/endpoints.jsonl"))
IDOR_WORKLIST     = os.path.expanduser(os.environ.get("IDOR_WORKLIST", "~/recon/idor_worklist.jsonl"))
# the param catalog feeds BOTH param_confirm (ssti/sqli/redirect/open-redirect) and xss_confirm (xss)
_PARAM_OUT_CLASSES = ("ssti", "sqli", "redirect", "open-redirect", "xss", "reflected-xss")
PARAM_STATUS      = os.path.join(STATE_DIR, "param_confirm_status.json")  # heartbeat: written only on a tested>0 cycle
OBS_PARAM_ACTIVE_DAYS = float(os.environ.get("OBS_PARAM_ACTIVE_DAYS", "3"))


def _today():
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")


def _es_pw() -> str:
    """ES password, netrc-FIRST then the legacy ~/.recon_es_pass. Parses the netrc file by
    hand (NOT the stdlib netrc module — that rejects a file it doesn't OWN, which would block
    reconrun on the d0k-owned, ACL-shared ~/.recon_es_netrc). Direct read honours the ACL, so
    this works regardless of which user runs the engine (the recon_validate #11/reconrun lesson)."""
    try:
        toks = open(os.path.expanduser("~/.recon_es_netrc"), encoding="utf-8").read().split()
        if "password" in toks:
            return toks[toks.index("password") + 1]
    except Exception:
        pass
    try:
        return open(os.path.expanduser("~/.recon_es_pass"), encoding="utf-8").read().strip()
    except Exception:
        return ""


def _es_count(index: str) -> int:
    """ES doc count for a catalog index. -1 on unreachable/missing (caller must NOT
    treat -1 as silent-zero — an unknown source is not proof of wasted resources)."""
    import urllib.request, base64
    try:
        pw = _es_pw()
        tok = base64.b64encode(f"elastic:{pw}".encode()).decode()
        req = urllib.request.Request(f"{ES_URL}/{index}/_count", headers={"Authorization": "Basic " + tok})
        with urllib.request.urlopen(req, timeout=8) as r:
            return int(json.load(r).get("count", -1))
    except Exception:
        return -1


def _linecount(path: str) -> int:
    """Lines in a JSONL store. 0 if the file is ABSENT (definitive zero production);
    -1 only on a real read error (transient — don't false-alarm)."""
    if not os.path.exists(path):
        return 0
    try:
        with open(path, "rb") as f:
            return sum(1 for _ in f)
    except Exception:
        return -1


def _count_to_test(path: str) -> int:
    """IDOR worklist depth = leads still status='to-test'. 0 if absent."""
    if not os.path.exists(path):
        return 0
    try:
        n = 0
        with open(path, "r", errors="ignore") as f:
            for line in f:
                if '"status":"to-test"' in line or '"status": "to-test"' in line:
                    n += 1
        return n
    except Exception:
        return -1


def _file_age_days(path: str):
    try:
        return round((_dt.datetime.now().timestamp() - os.path.getmtime(path)) / 86400.0, 1)
    except Exception:
        return None


def _param_lane_active() -> bool:
    """Is the param-confirm lane actually PROBING candidates? recon_param_confirm writes
    PARAM_STATUS only on a cycle that tested>0, so a fresh file = a live lane. A strict,
    FP-averse confirm lane (reflection≠XSS, error-diff SQLi) legitimately confirms 0 for
    long stretches — 'live but nothing met the bar' is HEALTHY, not silent-zero. Only an
    INACTIVE lane (no tested>0 cycle in OBS_PARAM_ACTIVE_DAYS = genuinely starved, the
    pre-de-starvation state) is a real silent-zero."""
    age = _file_age_days(PARAM_STATUS)
    return age is not None and age <= OBS_PARAM_ACTIVE_DAYS


def yield_audit(conn, window_d: int = OBS_YIELD_WINDOW_D) -> dict:
    """Per-lane production self-audit over a rolling window. For every lane reports
    confirmed produced vs reals (ai_verdict='real') vs fps. A lane that spent resources
    (input source non-empty) yet produced 0 confirmed AND 0 real is SILENT-ZERO. The
    VALUE-ENGINE lanes — jsintel endpoint production + the IDOR worklist depth — are
    monitored first-class and flagged CRITICAL when zero, because the whole IDOR pillar
    depends on them. No lane can fail silently again."""
    cutoff = (_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=window_d)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _counts(where: str, params: tuple):
        r = conn.execute(
            "SELECT COUNT(*) c, COALESCE(SUM(ai_verdict='real'),0) r, COALESCE(SUM(ai_verdict='fp'),0) f "
            "FROM findings WHERE created_at>=? AND " + where, (cutoff, *params)).fetchone()
        return int(r["c"]), int(r["r"]), int(r["f"])

    lanes = []

    # 1) DB lanes that DID produce findings (per signal_class) — the "what's producing" view
    for row in conn.execute(
            "SELECT COALESCE(signal_class,'(none)') lane, COUNT(*) c, "
            "COALESCE(SUM(ai_verdict='real'),0) r, COALESCE(SUM(ai_verdict='fp'),0) f "
            "FROM findings WHERE created_at>=? GROUP BY signal_class ORDER BY c DESC", (cutoff,)):
        lanes.append({"lane": row["lane"], "kind": "db", "input_label": "findings", "input": None,
                      "confirmed": int(row["c"]), "real": int(row["r"]), "fp": int(row["f"]),
                      "silent_zero": False, "critical": False})

    # 2) input-fed lanes — these can fail INVISIBLY (no findings row to GROUP BY), the whole point
    # params: ES recon_params catalog -> param_confirm + xss_confirm findings
    cat = _es_count("recon_params")
    ph = "(" + ",".join("?" * len(_PARAM_OUT_CLASSES)) + ")"
    pc, pr, pf = _counts(f"signal_class IN {ph}", _PARAM_OUT_CLASSES)
    p_active = _param_lane_active()
    lanes.append({"lane": "params", "kind": "catalog", "input_label": "recon_params catalog (ES)",
                  "input": cat, "confirmed": pc, "real": pr, "fp": pf,
                  "age_days": _file_age_days(PARAM_STATUS), "active": p_active,
                  # silent-zero ONLY when the lane isn't even probing — a live-but-unconfirmed
                  # FP-averse lane is healthy (see _param_lane_active).
                  "silent_zero": (cat > 0 and pc == 0 and pr == 0 and not p_active), "critical": False})

    # jsintel: endpoints.jsonl production feeds the IDOR pillar (+ its verified-secret findings)
    ep = _linecount(ENDPOINTS_STORE)
    jc, jr, jf = _counts("vuln_class LIKE 'verified-secret%'", ())
    lanes.append({"lane": "jsintel(endpoints)", "kind": "value-engine",
                  "input_label": "endpoints.jsonl produced", "input": ep,
                  "age_days": _file_age_days(ENDPOINTS_STORE),
                  "confirmed": jc, "real": jr, "fp": jf,
                  "silent_zero": (ep == 0), "critical": True})

    # idor_worklist: to-test depth = the leads the operator/2IC will test (+ any BAC findings)
    depth = _count_to_test(IDOR_WORKLIST)
    ic, ir, idf = _counts("vuln_class IN ('broken-access-control','idor','bola')", ())
    lanes.append({"lane": "idor_worklist", "kind": "value-engine",
                  "input_label": "to-test leads", "input": depth,
                  "age_days": _file_age_days(IDOR_WORKLIST),
                  "confirmed": ic, "real": ir, "fp": idf,
                  "silent_zero": (depth == 0), "critical": True})

    silent = [l for l in lanes if l["silent_zero"]]
    return {"window_d": window_d, "since": cutoff, "lanes": lanes, "silent_zero": silent}


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
        "ai_accuracy": S.ai_accuracy(conn),
        "yield_audit": yield_audit(conn),
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
    ai = d.get("ai_accuracy") or {}
    if ai.get("reviewed_total"):
        L.append("\n## 🧠 Claude accuracy (self-audit)")
        vd = ai.get("verdict_distribution", {})
        vd_line = " · ".join(f"{k} {v['count']} (avg conf {v['avg_conf']})" for k, v in vd.items())
        L.append(f"- {ai['reviewed_total']} findings reviewed · " + (vd_line or "no verdicts yet"))
        rd = ai.get("real_disposition", {})
        prec = rd.get("precision_when_decided")
        prec_s = f"{prec:.0%}" if isinstance(prec, (int, float)) else "n/a (no human decisions yet)"
        L.append(f"- 'real' precision (human-decided): **{prec_s}** — accepted "
                 f"{rd.get('accepted_submitted',0)} · rejected {rd.get('rejected_dismissed',0)} · "
                 f"pending {rd.get('pending_human',0)}")
        L.append(f"- big-model escalations: {ai.get('escalations',0)}  ·  AI-learned FP signatures: "
                 f"{ai.get('fp_signatures_from_ai',0)}  ·  KB lessons: {ai.get('kb_lessons',0)} "
                 f"(retrieved {ai.get('kb_retrievals',0)}×)")
    ya = d.get("yield_audit") or {}
    if ya.get("lanes"):
        L.append(f"\n## 🔬 Per-lane yield (last {ya['window_d']}d) — is each lane actually producing?")
        sz = ya.get("silent_zero", [])
        if sz:
            L.append("- 🔴 **SILENT-ZERO** (resources spent, nothing out — fix or retire): " + ", ".join(
                (("⚠️CRITICAL " if l["critical"] else "") +
                 f"{l['lane']} ({l['input']} {l['input_label']}, 0 confirmed, 0 real)") for l in sz))
        else:
            L.append("- ✅ no silent-zero lanes")
        L.append("")
        L.append(f"    {'lane':<22} {'input':>8}  {'conf':>4} {'real':>4} {'fp':>4}  status")
        for l in ya["lanes"]:
            inp = "—" if l.get("input") is None else str(l["input"])
            if l["silent_zero"]:
                st = "🔴 SILENT-ZERO" + (" (CRITICAL)" if l["critical"] else "")
            elif l["confirmed"] > 0 and l["real"] == 0:
                st = "⚠️ no reals" + (" · CRITICAL lane" if l["critical"] else "")
            else:
                st = "ok" + (" · CRITICAL lane" if l["critical"] else "")
            age = l.get("age_days")
            age_s = f"  (src age {age}d)" if age is not None else ""
            L.append(f"    {l['lane']:<22} {inp:>8}  {l['confirmed']:>4} {l['real']:>4} {l['fp']:>4}  {st}{age_s}")
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
    ai = d.get("ai_accuracy") or {}
    rd = ai.get("real_disposition", {})
    prec = rd.get("precision_when_decided")
    ai_line = ""
    if ai.get("reviewed_total"):
        prec_s = f"{prec:.0%}" if isinstance(prec, (int, float)) else "n/a"
        ai_line = (f"\n\U0001F9E0 Claude: {ai['reviewed_total']} reviewed · 'real' precision {prec_s} "
                   f"· {ai.get('escalations',0)} escalations")
    msg = (f"\U0001F4CA **v3 digest {d['day']}**\n"
           f"confirmed {a['confirmed']} · reported {a['reported']} · dismissed {a['dismissed']} "
           f"· lead-exhausted {a['lead_exhausted']}\n"
           f"review queue: {len(d['review_queue_awaiting_submit'])} awaiting submit\n"
           f"FP suppressed today: {fp['suppressed_today_sigs']} · LLM spend ${d['api_spend_usd']}"
           + ai_line
           + (f"\n\U0001F6D1 HALTED: {d['halted_now']}" if d["halted_now"] else ""))
    try:
        req = urllib.request.Request(hook, data=json.dumps({"content": msg[:1900]}).encode(),
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=15)
    except Exception:
        pass


def _ops_hook() -> str:
    """#ops webhook — per-user file or the shared discord dir (same resolution as #digest)."""
    for p in (os.path.expanduser("~/.recon_discord_ops"),
              os.path.join(os.environ.get("RECON_DISCORD_DIR", "/home/d0k/recon/state/discord"), "ops")):
        try:
            if os.path.isfile(p):
                h = open(p, encoding="utf-8").read().strip()
                if h:
                    return h
        except Exception:
            pass
    return ""


def _ops_post(hook: str, msg: str) -> bool:
    import urllib.request
    try:
        req = urllib.request.Request(hook, data=json.dumps({"content": msg[:1900]}).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as r:
            return 200 <= getattr(r, "status", 200) < 300
    except Exception:
        return False


def silent_zero_alarm(d: dict) -> None:
    """Fire #ops ONCE per silent-zero lane per window (anti-spam — same pattern as
    recon_watchdog.sh's 2IC alert: a per-lane marker, re-alert only after the window).
    Action-only message; value-engine lanes (jsintel / idor_worklist) flagged CRITICAL.
    The marker auto-expires after the window, so a lane that goes silent again re-alerts."""
    ya = d.get("yield_audit") or {}
    sz = ya.get("silent_zero", [])
    if not sz:
        return
    window_s = int(ya.get("window_d", OBS_YIELD_WINDOW_D)) * 86400
    hook = _ops_hook()
    now = _dt.datetime.now(_dt.timezone.utc).timestamp()
    os.makedirs(STATE_DIR, exist_ok=True)
    for l in sz:
        slug = re.sub(r'[^a-z0-9]+', '_', l["lane"].lower()).strip('_') or "lane"
        mark = os.path.join(STATE_DIR, f".obs_silentzero_{slug}")
        try:
            last = float(open(mark, encoding="utf-8").read().strip())
        except Exception:
            last = 0.0
        if now - last < window_s:
            print(f"[obs] silent-zero {l['lane']} — alert suppressed (cooldown, within {ya.get('window_d')}d window)", file=sys.stderr)
            continue
        crit = "🚨 CRITICAL " if l["critical"] else ""
        msg = (f"{crit}lane **{l['lane']}** SILENT-ZERO {ya.get('window_d')}d "
               f"({l['input']} {l['input_label']}, 0 confirmed, 0 real) — fix or retire")
        if not hook:
            print(f"[obs] silent-zero {l['lane']} — #ops webhook unset, not delivered", file=sys.stderr)
            continue
        if _ops_post(hook, msg):
            try:
                open(mark, "w", encoding="utf-8").write(str(int(now)))
            except Exception:
                pass
            print(f"[obs] #ops silent-zero alert fired: {l['lane']}", file=sys.stderr)
        else:
            print(f"[obs] silent-zero {l['lane']} — #ops post FAILED (will retry next run)", file=sys.stderr)


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
    _discord_digest(d)        # compact #digest ping (best-effort; .md is the source of truth)
    silent_zero_alarm(d)      # action-only #ops alert per silent-zero lane (anti-spam, once/window)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

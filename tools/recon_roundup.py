#!/usr/bin/env python3
"""
recon_roundup.py — the reliable "what do we have tonight" reconciler.

The Discord digest renders findings.db state + candidate lists verbatim, but it
never reconciles them against what the human/2IC already concluded. Result: items
already SUBMITTED (builds.myharmony H1#3800848) or ruled OUT-OF-SCOPE
(klesy-test.sbb.ch) keep re-appearing as "Ready to submit", while genuinely
actionable value buried in host_notes (e.g. the Topper orderById unauth IDOR)
never surfaces. Reading one card = miss things in both directions.

This tool pulls EVERY actionable source and annotates each item against the three
ground-truth ledgers (submission ledger, host_notes, findings.db fp tables), so
the only things that show as ACTIONABLE are things that are actually open.

Read-only. No network. No writes. Safe to run any time.
"""
import json, os, re, sqlite3, sys, glob, datetime

HOME = os.path.expanduser("~")
V3_DB = os.environ.get("V3_DB", os.path.join(HOME, "recon/v3/findings.db"))
LEDGER = os.path.join(HOME, ".recon_submissions.jsonl")
NOTES = os.path.join(HOME, "recon/state/host_notes.jsonl")
BRIEF_DIR = os.path.join(HOME, "recon/briefings")

# note text that means "do not re-surface as actionable"
OOS_RE = re.compile(r"\b(out[- ]of[- ]scope|OOS|do[- ]not[- ]submit)\b", re.I)
FP_RE = re.compile(r"\b(false[- ]positive|by[- ]design|\bFP\b|dup(licate)?|N/?A\b)\b", re.I)
SUBMITTED_RE = re.compile(r"\b(WORKED/OPEN|submitted|H1 #?\d{6,}|report(ed)? to)\b", re.I)
EXHAUST_RE = re.compile(r"\b(exhausted|no bug|clean|secure FP|dead)\b", re.I)


def load_jsonl(p):
    out = []
    if not os.path.exists(p):
        return out
    for line in open(p, encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            pass
    return out


def host_key(h):
    return (h or "").strip().lower()


def main():
    ledger = load_jsonl(LEDGER)
    notes = load_jsonl(NOTES)

    sub_by_host = {}
    for r in ledger:
        sub_by_host.setdefault(host_key(r.get("host")), []).append(r)

    notes_by_host = {}
    for r in notes:
        notes_by_host.setdefault(host_key(r.get("host")), []).append(r)

    # findings.db actionable rows
    findings = []
    if os.path.exists(V3_DB):
        c = sqlite3.connect(V3_DB)
        c.row_factory = sqlite3.Row
        q = ("SELECT id,host,url,program,vuln_class,signal_class,state,ai_verdict,"
             "COALESCE(ai_confidence,confidence) cf,ai_reason "
             "FROM findings WHERE (ai_verdict IN ('real','needs-human') "
             "OR signal_class='verified-secret') AND state IN ('confirmed','reported') "
             "ORDER BY cf DESC")
        findings = [dict(r) for r in c.execute(q)]

    actionable, submitted, oos, fp, worked = [], [], [], [], []

    for f in findings:
        hk = host_key(f["host"])
        hnotes = notes_by_host.get(hk, [])
        notetext = " || ".join((n.get("note") or "") for n in hnotes)
        subs = sub_by_host.get(hk, [])

        status, why = "ACTIONABLE", ""
        if subs:
            status = "SUBMITTED"
            why = "; ".join("%s [%s] %s" % (s.get("vuln_class"), s.get("status"),
                            (s.get("submitted_date") or "")[:10]) for s in subs)
        elif SUBMITTED_RE.search(notetext):
            status = "SUBMITTED"
            m = re.search(r"H1 #?\d{6,}", notetext)
            why = "note: " + (m.group(0) if m else "marked submitted in host_notes")
        elif OOS_RE.search(notetext):
            status = "OOS"
            why = "host_notes: out-of-scope / do-not-submit"
        elif FP_RE.search(notetext):
            status = "FP"
            why = "host_notes: FP / by-design / dup"
        elif EXHAUST_RE.search(notetext):
            status = "WORKED"
            why = "host_notes: worked/exhausted (recheck if signal changed)"

        f["_status"], f["_why"], f["_notetext"] = status, why, notetext
        {"ACTIONABLE": actionable, "SUBMITTED": submitted, "OOS": oos,
         "FP": fp, "WORKED": worked}[status].append(f)

    # ---- render ----
    W = 74
    print("=" * W)
    print("RECON ROUNDUP — reconciled actionable board  (%s)"
          % datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%MZ"))
    print("findings.db actionable rows: %d  |  ledger entries: %d  |  noted hosts: %d"
          % (len(findings), len(ledger), len(notes_by_host)))
    print("=" * W)

    def block(title, rows):
        print("\n%s (%d)" % (title, len(rows)))
        print("-" * W)
        for f in rows:
            print("• [%s] %s  (%s)  conf=%s" % (f["id"], f["host"], f["program"], f["cf"]))
            print("    %s / %s / state=%s verdict=%s" %
                  (f["vuln_class"], f["signal_class"], f["state"], f["ai_verdict"]))
            if f["_why"]:
                print("    ↳ %s" % f["_why"])
            reason = (f["ai_reason"] or "").replace("\n", " ")
            if len(reason) > 220:
                reason = reason[:217] + "..."
            print("    reason: %s" % reason)

    block("🎯 ACTIONABLE — open, needs a decision/submit", actionable)
    block("🔍 needs-human / worked — recheck if changed", worked)
    print("\n📤 already SUBMITTED (tracking, not actionable) (%d)" % len(submitted))
    print("-" * W)
    for f in submitted:
        print("• %s (%s) — %s — %s" % (f["host"], f["program"], f["vuln_class"], f["_why"]))
    print("\n⛔ suppressed: OOS=%d  FP=%d" % (len(oos), len(fp)))
    for f in oos + fp:
        print("   %-42s %-20s %s" % (f["host"], f["_status"], f["vuln_class"]))

    # ---- candidate briefings today (leads to verify) ----
    today = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    print("\n" + "=" * W)
    print("🧪 CANDIDATE LEAD LISTS (today %s) — verify before trusting" % today)
    print("-" * W)
    for kind in ("graphql_candidates", "wcd_candidates", "xss_candidates",
                 "sqli_candidates", "idor_candidates", "2IC_tonight", "tonight",
                 "hunter", "fresh"):
        matches = sorted(glob.glob(os.path.join(BRIEF_DIR, "%s_%s*.md" % (kind, today))))
        if matches:
            for m in matches:
                sz = os.path.getsize(m)
                print("   %-24s %s (%d B)" % (kind, os.path.basename(m), sz))
        else:
            # fall back to latest of this kind
            allm = sorted(glob.glob(os.path.join(BRIEF_DIR, "%s_*.md" % kind)))
            if allm:
                print("   %-24s (none today; latest: %s)" % (kind, os.path.basename(allm[-1])))
    print("\nRead a candidate file for its ranked hosts; each host still passes")
    print("host_notes/ledger checks before you invest.")


if __name__ == "__main__":
    main()

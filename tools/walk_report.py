#!/usr/bin/env python3
"""walk_report.py — render a PROGRAM WALK status board (STRIDE + WSTG) as a self-contained HTML page.

Reads a program workspace and emits EVERY sub-step with its recorded outcome, so the board is a
drill-down record ("what did each test find?"), not a scoreboard of counts. Every category and every
step collapses, so a 97-test walk stays navigable. Regenerate after any batch of steps and republish
to the SAME artifact URL.

    python3 tools/walk_report.py <workspace-key> [out.html]

Doctrine: docs/knowledge/process-stride-wstg.md ("Standing rules of this workflow").
"""
import sys, os, re, html, datetime
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ui"))
from backend import workspace as W  # noqa: E402

CAT_ORDER = ["INFO", "CONF", "IDNT", "ATHN", "ATHZ", "SESS",
             "INPV", "ERRH", "CRYP", "BUSL", "CLNT", "APIT"]
STRIDE_NAMES = {"S": "Spoofing", "T": "Tampering", "R": "Repudiation",
                "I": "Information disclosure", "D": "Denial of service",
                "E": "Elevation of privilege"}
PILL = {"done": "p-ok", "finding": "p-stop", "na": "p-idle",
        "manual": "p-warn", "in-progress": "p-live", "todo": "p-idle", "open": "p-live"}

e = html.escape



def board_html(ws, A, e, _rich):
    """Render the per-lead state board from ws["board"].

    The board is the answer to "what is the state of every lead" and is the first thing a
    reader wants. It lives in the WORKSPACE, not in the HTML: an earlier version of this
    document carried it as hand-authored markup, which meant every regeneration silently
    deleted 27 cards while reporting success.

    Group counts are DERIVED from the cards present. A stored count drifts the moment a card
    is added, and a board that miscounts its own contents is worse than no board.
    """
    board = ws.get("board") or {}
    groups = board.get("groups") or []
    if not groups:
        return False

    intro = board.get("intro")
    if intro:
        A(f'<section class="card sum"><h2><span class="pill {e(intro.get("pill_class","p-live"))}">'
          f'{e(intro.get("pill","board"))}</span> {e(intro.get("title",""))}</h2>'
          f'<div class="pt"><p>{intro.get("body","")}</p></div></section>')

    for grp in groups:
        cards = grp.get("cards") or []
        cls = (grp.get("grp_class") or "").strip()
        op = " open" if grp.get("open") else ""
        A(f'<section class="card"><details class="grp {cls}"{op}><summary class="grp-h">'
          f'<span class="cat">{e(grp.get("cat",""))}</span>'
          f'<span class="catname">{grp.get("name","")}</span>'
          f'<span class="count">{len(cards)}</span>'
          f'<span class="chev" aria-hidden="true"></span></summary><div class="grp-b">')
        for c in cards:
            pill = ""
            if c.get("pill"):
                pill = f'<span class="pill {e(c.get("pill_class") or "p-idle")}">{c["pill"]}</span>'
            lead = f'<p class="slead">{c["lead"]}</p>' if c.get("lead") else ""
            _cneg = any(k in (c.get("pill") or "").lower()
                        for k in ("closed", "negative", "by design", "n/a", "na "))
            A(f'<details class="step{" neg" if _cneg else ""}" id="{e(c.get("id",""))}"><summary class="step-h">'
              f'<span class="sid">{e(c.get("id",""))}</span>'
              f'<span class="stitle">{c.get("title","")}</span>{pill}{lead}'
              f'<span class="chev" aria-hidden="true"></span></summary><div class="snote">')
            for seg in c.get("segments") or []:
                if "lede" in seg:
                    A(f'<div class="seg lede">{seg["lede"]}</div>')
                else:
                    A(f'<div class="seg"><span class="lab {e(seg.get("lab_class","p-idle"))}">'
                      f'{seg.get("label","")}</span><div class="val">{seg.get("value","")}</div></div>')
            # A ref may be a fixed anchor OR a distinctive PHRASE (`q`). Prefer the phrase:
            # note indices shift the moment anyone inserts rather than appends, and a link that
            # silently points at the wrong note is worse than no link at all.
            chips = ""
            for r in c.get("refs") or []:
                rid = r.get("anchor")
                if r.get("q"):
                    hit = next((f"note-{i}" for i, n in enumerate(ws.get("notes", []))
                                if r["q"].lower() in (n.get("text") or "").lower()), None)
                    if hit:
                        rid = hit
                    else:
                        print(f"  ! board {c.get('id')}: unresolved ref q={r['q'][:60]!r}",
                              file=sys.stderr)
                        if not rid:
                            continue
                if not rid:
                    continue
                chips += (f'<a class="ref" href="#{e(rid)}" data-ref="{e(rid)}">'
                          f'{e(r.get("label") or rid)}</a>')
            if chips:
                A(f'<div class="refs"><span class="reflab">evidence</span>{chips}</div>')
            A('</div></details>')
        A('</div></details></section>')
    return True

def phases(ws):
    """Derive phase state from what the workspace actually contains."""
    stride_n = sum(len(v) for v in ws.get("stride", {}).values())
    stride_cats = sum(1 for v in ws.get("stride", {}).values() if v)
    wstg = ws.get("wstg", [])
    walked = sum(1 for i in wstg if i["status"] != "todo")
    findings = sum(1 for i in wstg if i["status"] == "finding")
    notes = len(ws.get("notes", []))
    return [
        ("00", "Commit &amp; gate", "done" if notes else "wait", "policy + carve-outs" if notes else "—"),
        ("01", "Recon &amp; app model", "done" if notes >= 2 else "wait", f"{notes} notes"),
        ("02", "STRIDE", "done" if stride_cats == 6 else ("live" if stride_n else "wait"),
         f"{stride_n} threats" if stride_n else "—"),
        ("03", "WSTG walk",
         "done" if wstg and walked == len(wstg) else ("live" if walked else "wait"),
         f"{walked} / {len(wstg)}"),
        ("04", "Confirm &amp; escalate", "live" if findings else "wait",
         f"{findings} finding(s)" if findings else "—"),
        ("05", "Coverage &amp; close", "wait", "—"),
    ]


# A recorded outcome is written as prose with ALL-CAPS labels ("METHOD: ... FOUND: ... LIMITS: ...").
# Rather than dump one wall of text, split on those labels and render a scannable label/value table.
_LABEL = re.compile(r"([A-Z][A-Z0-9 ,&/'()+.–-]{2,70}?):\s")
_BOUNDARY = re.compile(r"[.;!?)\]]\s+$|\*{3}\s*$|^$")
# Inline enumerations "(a) ... (b) ..." / "(1) ... (2) ..." become real list items.
_ENUM = re.compile(r"(?:(?<=\s)|^)\(([a-z]|\d{1,2})\)\s+")
# Severity/verdict words worth colouring so the eye lands on the outcome, not the prose.
_TONE = (("p-stop", ("FINDING", "CONFIRMED", "BLOCKED", "ACTION")),
         ("p-ok", ("CLEARED", "NEGATIVE", "RESULT", "FOUND", "RECORD")),
         ("p-warn", ("LIMITS", "LIMIT", "WHAT THIS DOES NOT RULE OUT", "PENDING", "NOT")),
         ("p-live", ("METHOD", "NEXT", "TEST", "DESIGN", "SCOPE")))


def _tone(label):
    up = label.upper()
    for cls, words in _TONE:
        if any(w in up for w in words):
            return cls
    return "p-idle"


def _segments(note):
    """Split a recorded outcome into (label, value) pairs. Unlabelled text yields one ('', text)."""
    txt = re.sub(r"\*{3}", "", note or "").strip()
    txt = re.sub(r"^STEP CARD\s*[-–]\s*", "", txt).strip()
    cuts = []
    for m in _LABEL.finditer(txt):
        if m.start() == 0 or _BOUNDARY.search(txt[max(0, m.start() - 3):m.start()]):
            cuts.append((m.start(), m.end(), m.group(1)))
    if not cuts:
        return [("", txt)]
    segs = []
    if cuts[0][0] > 0:
        lead = txt[:cuts[0][0]].strip()
        if lead:
            segs.append(("", lead))
    for i, (_s, end, label) in enumerate(cuts):
        stop = cuts[i + 1][0] if i + 1 < len(cuts) else len(txt)
        val = txt[end:stop].strip().strip(".;, ")
        if val:
            segs.append((label.strip(), val))
    return segs


# Break a long value at sentence/clause ends so it reads as separate lines instead of a slab.
_SENT = re.compile(r"(?<=[.;])\s+(?=[A-Z(\"'])")


def _lines(val):
    """A long unenumerated value becomes one short line per clause — far easier to track."""
    if len(val) <= 190:
        return f"<span>{e(val)}</span>"
    parts = [p.strip() for p in _SENT.split(val) if p.strip()]
    if len(parts) < 2:
        return f"<span>{e(val)}</span>"
    # Re-join runt fragments so no line is a stub.
    merged = []
    for p in parts:
        if merged and len(merged[-1]) < 60:
            merged[-1] += " " + p
        else:
            merged.append(p)
    return "".join(f'<p class="ln">{e(p)}</p>' for p in merged)


def _value_html(val):
    parts = _ENUM.split(val)
    if len(parts) < 3:
        return _lines(val)
    lead, items = parts[0].strip(), []
    for i in range(1, len(parts) - 1, 2):
        items.append((parts[i], parts[i + 1].strip().strip(";, ")))
    out = _lines(lead) if lead else ""
    out += "<ul class=\"enum\">" + "".join(
        f'<li><b>{e(k)}</b>{e(v)}</li>' for k, v in items if v) + "</ul>"
    return out


def _body(note):
    rows = []
    for label, val in _segments(note):
        if label:
            # A long label cannot share a narrow column without wrapping into a ragged stack,
            # so it becomes a full-width sub-heading instead.
            wide = " wide" if len(label) > 26 else ""
            rows.append(f'<div class="seg{wide}"><span class="lab {_tone(label)}">{e(label)}</span>'
                        f'<div class="val">{_value_html(val)}</div></div>')
        else:
            rows.append(f'<div class="seg lede">{_value_html(val)}</div>')
    return "".join(rows)


def _short(text, cap=96):
    """A scannable one-line title from a long recorded sentence: cut at the first real break."""
    t = re.sub(r"\s+", " ", re.sub(r"\*{3}", "", text or "")).strip()
    for sep in (": ", " — ", " - ", ". "):
        i = t.find(sep)
        if 12 <= i <= cap:
            return t[:i].strip(" .:—-")
    if len(t) <= cap:
        return t
    cut = t[:cap].rsplit(" ", 1)[0]
    return cut.rstrip(" ,;:") + "…"


def _lead(note, cap=150):
    """First sentence of the outcome, shown on the collapsed row so the walk skims."""
    for label, val in _segments(note):
        if val:
            v = re.sub(r"\s+", " ", val).strip()
            return (label + " — " if label else "") + (v if len(v) <= cap
                                                       else v[:cap].rsplit(" ", 1)[0] + "…")
    return ""


def _rich(t):
    """Minimal inline markup for authored summary text: **bold** and `code`."""
    out = e(t)
    out = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", out)
    out = re.sub(r"`(.+?)`", r"<code>\1</code>", out)
    return out


# A "negative" is any test or threat whose outcome was "nothing here" — regardless of which status
# string recorded it. Statuses alone are not enough: a WSTG test that is walked and comes back clean is
# status `done`, indistinguishable from a `done` test that found something, so the recorded NOTE has to
# be consulted. Without this, "Hide negatives" only ever hid the handful of `na` rows.
_NEG_STATUS = ("closed-negative", "na", "closed", "by-design", "n/a")
_NEG_MARKERS = ("clean negative", "negative -", "negative,", "negative.", "non-finding",
                "not a finding", "no surface", "closed as", "nothing is leaking", "no finding",
                "clean.", "correctly", "holds", "not reportable", "no reportable")

def _is_neg(status, note=None):
    if (status or "").strip().lower() in _NEG_STATUS:
        return True
    head = (note or "")[:400].lower()
    return any(m in head for m in _NEG_MARKERS)


def _is_tested(status):
    """Walked at all — the inverse of the untested backlog."""
    return (status or "").strip().lower() not in ("todo", "", "open")

def step(sid, title, status, note=None, extra=None, dim=False, detail=None, anchor=None, neg=False,
         tested=False):
    """One collapsible sub-step. Without a note it is a plain non-expanding row.

    `detail` is prepended to the body as its own segment — used where the row title had to be
    shortened, so the full recorded wording is never lost.
    """
    pill = f'<span class="pill {PILL.get(status,"p-idle")}">{e(status)}</span>'
    aid = f' id="{e(anchor)}"' if anchor else ""
    head = (f'<span class="sid">{e(sid)}</span>'
            f'<span class="stitle">{e(title)}</span>{pill}')
    if not note and not detail:
        return (f'<div class="step flat{" todo" if dim else ""}{" neg" if neg else ""}'
                f'{" tested" if tested else ""}"{aid}>'
                f'<div class="step-h">{head}</div></div>')
    lead = _lead(note) if note else _short(detail or "", 150)
    if lead:
        head += f'<p class="slead">{e(lead)}</p>'
    body = ""
    if detail:
        body += (f'<div class="seg"><span class="lab p-live">THREAT</span>'
                 f'<div class="val">{e(detail)}</div></div>')
    if note:
        body += _body(note)
    body = f'<div class="snote">{body}</div>'
    if extra:
        body += f'<p class="shosts">{e(extra)}</p>'
    return (f'<details class="step{" neg" if neg else ""}{" tested" if tested else ""}"{aid}>'
            f'<summary class="step-h">{head}'
            f'<span class="chev" aria-hidden="true"></span></summary>{body}</details>')


# A long-running programme accumulates hundreds of notes. Rendered flat they are unreadable, so bucket
# them by what the note IS. Classification reads the opening of the note, where the writer states its kind.
_NOTE_BUCKETS = [
    ("correction", "Corrections &mdash; claims that measurement killed",
     ("CORRECTION", "IS WRONG", "ANOMALY", "SELF-CORRECTION", "DISMANTLE", "NEVER REPORT",
      "FALSE POSITIVE TO NEVER", "DEFLATES")),
    ("finding", "Findings &amp; confirmations",
     ("CONFIRMED", "FINDING", "IS THE ESCALATION", "COUNTER-HYPOTHESIS IS DEAD")),
    ("cleared", "Cleared &mdash; negatives, do not re-walk",
     ("NEGATIVE", "CLEARED", "CLOSED", "KILL", "DEAD", "SECURE", "NOT A FINDING", "TESTED AND BOUNDED",
      "EXHAUSTED", "GATE CLOSED")),
    ("lead", "Live leads &amp; next tests",
     ("LEAD", "HYPOTHES", "UNTESTED", "NEXT", "TEST PLAN", "WORKLIST", "PENDING", "TEST SURFACE",
      "OPERATOR ACTION", "DECISION POINT", "SEVERITY GATE")),
    ("method", "Method &amp; recovered API shapes",
     ("METHOD", "RECOVERED", "SHAPES", "SCHEMA", "DOC MAP", "SURFACE ENUMERATED", "MINED", "INVENTORY")),
    ("rules", "Programme rules, scope &amp; exclusions",
     ("HARD RULE", "HARD LINE", "EXCLUDED", "OUT OF SCOPE", "PHASE 0", "SCOPE", "POLICY", "FOCUS AREA",
      "SANCTIONED", "ELIGIBILITY", "NON-QUALIFYING")),
    ("ops", "Recon, coverage &amp; operations",
     ("COVERAGE-", "ANTI-BURN", "RECON", "BLOCKER", "INVARIANT", "OPERATIONAL", "ACCOUNTS", "BASELINE",
      "ESTATE", "EGRESS", "CLOUDFLARE")),
]
_BUCKET_PILL = {"correction": "p-warn", "finding": "p-stop", "cleared": "p-ok",
                "lead": "p-live", "method": "p-idle", "rules": "p-idle",
                "ops": "p-idle", "context": "p-idle"}


def _note_bucket(text):
    head = re.sub(r"\*+", "", (text or "")[:200]).upper()
    for key, _title, words in _NOTE_BUCKETS:
        if any(w in head for w in words):
            return key
    return "context"


def render(ws, accounts):
    wstg = ws.get("wstg", [])
    by_cat = {c: [i for i in wstg if i["category"] == c] for c in CAT_ORDER}
    walked = sum(1 for i in wstg if i["status"] != "todo")
    stride = ws.get("stride", {})
    stride_n = sum(len(v) for v in stride.values())
    gen = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    name = ws.get("name") or ws.get("key")

    P = []
    A = P.append
    A(f"<title>{e(name)} Walk</title>")
    A(CSS)
    A('<div class="wrap">')

    A('<header class="top">')
    A('<div class="eyebrow"><span>The Program Walk</span><span class="dot">·</span>'
      '<span class="dim">STRIDE &rarr; WSTG</span></div>')
    A(f"<h1>{e(name)}</h1>")
    A('<p class="sub">Every sub-step and what it found, one line at a time. Each row shows its outcome '
      'in a single sentence &mdash; open it only if you want the detail. The row you open keeps a copper '
      'spine so you can look away and find your place again.</p>')
    A('<div class="facts">')
    A(f'<span class="fact go"><b>{e(ws.get("platform","?")).upper()}</b></span>')
    A(f'<span class="fact">WSTG <b>{walked}/{len(wstg)}</b></span>')
    A(f'<span class="fact">STRIDE <b>{stride_n}</b></span>')
    A(f'<span class="fact">notes <b>{len(ws.get("notes",[]))}</b></span>')
    A(f'<span class="fact">accounts <b>{len(accounts)}</b></span>')
    # Filed count comes from the board's "F" bucket, so it can never disagree with the cards
    # actually listed. A hand-typed total here drifted the moment a report was submitted.
    _filed = sum(len(gr.get("cards") or []) for gr in ((ws.get("board") or {}).get("groups") or [])
                 if (gr.get("cat") or "").upper() == "F")
    if _filed:
        A(f'<span class="fact go">filed <b>{_filed}</b></span>')
    A("</div></header>")

    # ---- TABS ----
    A('<div class="tabs" role="tablist">'
      '<button role="tab" data-tab="sum" aria-selected="true">Executive summary</button>'
      '<button role="tab" data-tab="detail" aria-selected="false">Full walk &mdash; every test</button>'
      '</div>')

    # ---- PANEL 1: executive summary ----
    A('<div class="panel" data-panel="sum">')
    # Expand/collapse belongs on BOTH tabs: the summary's cards are collapsible too, and a reader
    # should not have to switch tabs to reach the control that operates the tab they are on.
    A('<div class="toolbar" role="group" aria-label="View controls">'
      '<button type="button" data-act="expand">Expand all</button>'
      '<button type="button" data-act="collapse">Collapse all</button>'
      '<span class="hint">every lead, one line each &mdash; open a row only for the evidence</span>'
      '</div>')
    drew_board = board_html(ws, A, e, _rich)
    summary = [] if drew_board else (ws.get("exec_summary") or [])
    if not drew_board and not summary:
        A('<section class="card"><p class="sub">No executive summary recorded for this workspace yet.</p>'
          '</section>')
    for sec in summary:
        tone = sec.get("tone", "context")
        # A <details> rather than a <section>: the toolbar's Expand/Collapse acts on `details`
        # inside the panel, and while the summary rendered plain sections those buttons were dead
        # controls - they claimed to operate this tab and had nothing to operate on.
        A(f'<details class="card sum" open><summary class="sum-h">'
          f'<h2><span class="pill {_BUCKET_PILL.get(tone,"p-idle")}">{e(tone)}'
          f'</span> {e(sec.get("title",""))}</h2>'
          f'<span class="chev" aria-hidden="true"></span></summary>')
        for p in sec.get("points", []):
            txt = p.get("t") if isinstance(p, dict) else str(p)
            refs = (p.get("refs") if isinstance(p, dict) else None) or []
            chips = ""
            for r in refs:
                # A note ref may be given as a distinctive PHRASE rather than an index: indices shift
                # every time a note is appended, and a silently-wrong link is worse than no link.
                rid = r.get("id")
                if not rid and r.get("q"):
                    rid = next((f"note-{i}" for i, n in enumerate(ws.get("notes", []))
                                if r["q"].lower() in (n.get("text") or "").lower()), None)
                    if not rid:
                        print(f"  ! unresolved note ref: {r['q'][:60]!r}", file=sys.stderr)
                        continue
                chips += (f'<a class="ref" href="#{e(rid)}" data-ref="{e(rid)}">'
                          f'{e(r.get("label") or rid)}</a>')
            A(f'<div class="pt"><p>{_rich(txt)}</p>'
              + (f'<div class="refs"><span class="reflab">evidence</span>{chips}</div>' if chips else "")
              + "</div>")
        A("</details>")

    # ---- FOLLOW-UPS ----
    # ws["followups"] was rendered NOWHERE until 2026-09-08. That is the same class of defect as the
    # wstg/stride loss recovered the same day: a field no document renders is a field nobody notices
    # has gone stale, gone missing, or been answered months ago. Open work items belong on the summary
    # tab beside the board, because "what is still open" is the question this document exists to answer.
    _FU_PILL = {"high": "p-stop", "medium": "p-warn", "med": "p-warn", "low": "p-idle"}
    fus = [f for f in (ws.get("followups") or [])
           if isinstance(f, dict) and (f.get("status") or "open") in ("open", "blocked")]
    if fus:
        _rank = {"high": 0, "medium": 1, "med": 1, "low": 2}
        fus.sort(key=lambda f: (_rank.get((f.get("priority") or "low").lower(), 3),
                                (f.get("status") or "open") != "open"))
        A('<section class="card"><details class="grp grp-live" open>'
          '<summary class="grp-h"><span class="cat">FU</span>'
          '<span class="catname">Follow-ups &mdash; open work items</span>'
          f'<span class="count">{len(fus)}</span>'
          '<span class="chev" aria-hidden="true"></span></summary><div class="grp-b">')
        for f in fus:
            pr = (f.get("priority") or "low").lower()
            fid = str(f.get("id", "x"))
            body = ""
            for lab, key in (("WHY", "why"), ("ACTION", "action"),
                             ("TARGET", "target"), ("ORIGIN", "origin")):
                val = str(f.get(key) or "").strip()
                if val and val.lower() != "none":
                    body += (f'<div class="seg"><span class="lab {_tone(lab)}">{lab}</span>'
                             f'<div class="val">{_value_html(val)}</div></div>')
            head = (f'<span class="sid">{e(fid)}</span>'
                    f'<span class="stitle">{e(f.get("label", ""))}</span>'
                    f'<span class="pill {_FU_PILL.get(pr, "p-idle")}">{e(pr)}</span>')
            if (f.get("status") or "open") == "blocked":
                head += '<span class="pill p-warn">blocked</span>'
            if body:
                lead = _short(str(f.get("why") or ""), 150)
                if lead:
                    head += f'<p class="slead">{e(lead)}</p>'
                A(f'<details class="step" id="fu-{e(fid)}"><summary class="step-h">{head}'
                  '<span class="chev" aria-hidden="true"></span></summary>'
                  f'<div class="snote">{body}</div></details>')
            else:
                A(f'<div class="step flat" id="fu-{e(fid)}"><div class="step-h">{head}</div></div>')
        A("</div></details></section>")
    A("</div>")

    # ---- PANEL 2: the full walk ----
    A('<div class="panel" data-panel="detail" hidden>')

    A('<section class="card"><h2>Phases</h2><div class="rail">')
    for n, t, state, s in phases(ws):
        A(f'<div class="ph {state}"><div class="n">{n}</div><div class="t">{t}</div>'
          f'<div class="s">{e(s)}</div></div>')
    A("</div></section>")

    A('<div class="toolbar" role="group" aria-label="View controls">'
      '<button type="button" data-act="expand">Expand all</button>'
      '<button type="button" data-act="collapse">Collapse all</button>'
      '<button type="button" data-act="todo" aria-pressed="false">Hide untested</button>'
      '<button type="button" data-act="neg" aria-pressed="false">Hide negatives</button>'
      '<button type="button" data-act="tested" aria-pressed="false">Hide tested</button>'
      f'<span class="hint">start with <b>Hide untested</b> &mdash; it drops {len(wstg) - walked} '
      f'not-yet-walked rows and leaves the {walked} with a recorded outcome</span></div>')

    # ---- STRIDE ----
    A('<section class="card"><h2>STRIDE model &mdash; every threat</h2>')
    for c in "STRIDE":
        rows = stride.get(c, [])
        head = (f'<span class="cat">{c}</span><span class="catname">{STRIDE_NAMES[c]}</span>'
                f'<span class="count">{len(rows) if rows else "—"}</span>'
                f'<span class="chev" aria-hidden="true"></span>')
        if not rows:
            A(f'<div class="grp empty"><div class="grp-h">{head}</div></div>')
            continue
        A(f'<details class="grp"><summary class="grp-h">{head}</summary><div class="grp-b">')
        for r in rows:
            threat = r.get("threat", "")
            A(step(r.get("id", ""), _short(threat), r.get("status", "open"),
                   r.get("note"), ", ".join(r.get("hosts") or []), detail=threat,
                   anchor=f'stride-{r.get("id","")}',
                   neg=_is_neg(r.get("status"), r.get("note")),
                   tested=_is_tested(r.get("status"))))
        A("</div></details>")
    A("</section>")

    # ---- WSTG ----
    A('<section class="card"><h2>WSTG walk &mdash; every test</h2>')
    for c in CAT_ORDER:
        items = by_cat.get(c) or []
        if not items:
            continue
        done = sum(1 for i in items if i["status"] != "todo")
        pct = int(100 * done / len(items))
        state = "grp-done" if done == len(items) else ("grp-live" if done else "")
        # open the category currently in progress; keep finished + untouched ones shut
        is_open = " open" if 0 < done < len(items) else ""
        head = (f'<span class="cat">{c}</span>'
                f'<span class="catname">{e(items[0].get("cat_name",""))}</span>'
                f'<span class="bar"><i style="width:{pct}%"></i></span>'
                f'<span class="count">{done}/{len(items)}</span>'
                f'<span class="chev" aria-hidden="true"></span>')
        A(f'<details class="grp {state}"{is_open}><summary class="grp-h">{head}</summary>'
          f'<div class="grp-b">')
        for i in items:
            todo = i["status"] == "todo"
            A(step(i["id"], i["name"], i["status"], None if todo else i.get("note"), dim=todo,
                   anchor=i["id"],
                   neg=(not todo) and i["status"] != "finding" and _is_neg(i["status"], i.get("note")),
                   tested=_is_tested(i["status"])))
        A("</div></details>")
    A("</section>")

    if accounts:
        A('<section class="card"><h2>Owned accounts</h2><div class="grp-b flush">')
        for a in accounts:
            # set_accounts() persists label/email/username/password/url/notes. The old renderer read
            # name/user_id/offer, which that writer never produces, so every account rendered as an
            # empty title and "id ?" - the record existed and the document showed nothing.
            who = a.get("email") or a.get("username") or ""
            where = a.get("url") or ""
            title = who + (f" · {where}" if where else "")
            A(step(str(a.get("label", "?")).upper(), title, "owned", a.get("notes")))
        A("</div></section>")

    if ws.get("notes"):
        notes = list(enumerate(ws["notes"]))
        notes.reverse()  # newest first: the last thing learned is the thing most likely wanted
        grouped = {}
        for idx, n in notes:
            grouped.setdefault(_note_bucket(n.get("text", "")), []).append((idx, n))
        A(f'<section class="card"><h2>Recorded knowledge &mdash; {len(ws["notes"])} notes</h2>')
        A('<input class="nsearch" type="search" placeholder="Filter notes &mdash; try 403, addUserToAccount, '
          'Cloudflare, oracle&hellip;" aria-label="Filter recorded knowledge">')
        A('<p class="nhint">Newest first, grouped by what the note is. Everything is collapsed &mdash; '
          'open only what you need.</p>')
        for key, title, _w in _NOTE_BUCKETS + [("context", "Other context", ())]:
            rows = grouped.get(key) or []
            head = (f'<span class="pill {_BUCKET_PILL[key]}">{key}</span>'
                    f'<span class="catname">{title}</span>'
                    f'<span class="count">{len(rows)}</span>'
                    f'<span class="chev" aria-hidden="true"></span>')
            if not rows:
                A(f'<div class="grp empty"><div class="grp-h">{head}</div></div>')
                continue
            A(f'<details class="grp"><summary class="grp-h">{head}</summary><div class="grp-b">')
            for idx, n in rows:
                txt = n.get("text", "")
                A(step(n.get("ts", "")[:10] or f"#{idx}", _short(txt) or "note", "note", txt,
                       anchor=f"note-{idx}", neg=key == "cleared",
                       tested=key in ("cleared", "finding", "correction")))
            A("</div></details>")
        A("</section>")

    A("</div>")  # close detail panel

    A(f'<footer>generated {gen} &middot; tools/walk_report.py &middot; '
      f'{walked}/{len(wstg)} tests recorded &middot; {stride_n} threats</footer>')
    A("</div>")
    A(JS)
    return "\n".join(P)


CSS = """<style>
/* BENCH LOOK — dark FR-4 substrate, copper chrome, silkscreen mono. Single look in every
   theme on purpose: this is an ops board read at night, next to a terminal. */
:root{color-scheme:dark;
--ground:#06090A;--panel:#0B1012;--panel-2:#111A1C;--line:#1E2B2E;--ink:#E9F0EF;--ink-2:#93A5A6;
--ink-3:#5C7073;--accent:#E39A4B;--accent-soft:#2A1B0A;--ok:#48C9A9;--ok-soft:#082622;--warn:#EBD07A;
--warn-soft:#2A2410;--stop:#E4705C;--stop-soft:#2C1310;--idle:#1B2528;
--copper:#8A5A28;--signal:#4FD1C5;
--sans:"Segoe UI Variable Text","Segoe UI",Inter,system-ui,-apple-system,sans-serif;
--mono:ui-monospace,"Cascadia Mono","SF Mono",Menlo,Consolas,monospace}
*{box-sizing:border-box}
body{margin:0;background:var(--ground);color:var(--ink);font-family:var(--sans);line-height:1.55;
-webkit-font-smoothing:antialiased}
.wrap{max-width:1000px;margin:0 auto;padding:40px 22px 72px;display:flex;flex-direction:column;gap:26px}
.top{display:flex;flex-direction:column;gap:12px}
.eyebrow{font-family:var(--mono);font-size:11px;letter-spacing:.14em;text-transform:uppercase;
color:var(--accent);display:flex;gap:9px;flex-wrap:wrap}
.eyebrow .dot,.eyebrow .dim{color:var(--ink-3)}
h1{margin:0;font-size:clamp(28px,4vw,42px);line-height:1.05;letter-spacing:-.025em;font-weight:680;
text-wrap:balance}
.sub{margin:0;color:var(--ink-2);max-width:66ch;font-size:15px}
.facts{display:flex;flex-wrap:wrap;gap:7px;margin-top:2px}
.fact{font-family:var(--mono);font-size:11.5px;padding:5px 10px;border-radius:5px;background:var(--panel-2);
border:1px solid var(--line);color:var(--ink-2)}
.fact b{color:var(--ink);font-weight:600}
.fact.go{background:var(--ok-soft);border-color:transparent;color:var(--ok)}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:22px 24px}
h2{margin:0 0 16px;font-size:12px;font-family:var(--mono);font-weight:600;letter-spacing:.13em;
text-transform:uppercase;color:var(--ink-3)}
.rail{display:grid;gap:2px;grid-template-columns:repeat(6,1fr)}
@media (max-width:760px){.rail{grid-template-columns:repeat(2,1fr);gap:9px}}
.ph{padding:13px 12px;background:var(--panel-2);border-top:3px solid var(--idle)}
.ph .n{font-family:var(--mono);font-size:10.5px;color:var(--ink-3);letter-spacing:.1em}
.ph .t{font-size:13px;font-weight:600;margin-top:3px;line-height:1.25}
.ph .s{font-family:var(--mono);font-size:10.5px;margin-top:6px;color:var(--ink-3)}
.ph.done{border-top-color:var(--ok)}.ph.done .s{color:var(--ok)}
.ph.live{border-top-color:var(--accent);background:var(--accent-soft)}.ph.live .s{color:var(--accent)}

.toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:-8px 0 -6px}
.toolbar button{font-family:var(--mono);font-size:11.5px;padding:6px 12px;border-radius:6px;cursor:pointer;
background:var(--panel);border:1px solid var(--line);color:var(--ink-2)}
.toolbar button:hover{border-color:var(--accent);color:var(--accent)}
.toolbar button[aria-pressed="true"]{background:var(--accent-soft);border-color:transparent;color:var(--accent)}
.toolbar button:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.toolbar .hint{font-size:12px;color:var(--ink-3)}

.tabs{display:flex;gap:6px;border-bottom:1px solid var(--line);padding-bottom:0;margin-bottom:-8px}
.tabs button{font-family:var(--mono);font-size:12px;letter-spacing:.03em;padding:10px 16px;cursor:pointer;
background:none;border:0;border-bottom:2px solid transparent;color:var(--ink-3)}
.tabs button:hover{color:var(--ink-2)}
.tabs button[aria-selected="true"]{color:var(--accent);border-bottom-color:var(--accent)}
.tabs button:focus-visible{outline:2px solid var(--accent);outline-offset:-2px}
.panel[hidden]{display:none}
.panel{display:flex;flex-direction:column;gap:26px}
.card.sum h2{display:flex;align-items:center;gap:9px;font-family:var(--sans);font-size:15px;
text-transform:none;letter-spacing:0;color:var(--ink);font-weight:640;margin-bottom:4px}
.pt{padding:13px 0;border-top:1px solid var(--line)}
.pt p{margin:0;font-size:13.5px;line-height:1.72;color:var(--ink-2);max-width:78ch}
.pt strong{color:var(--ink);font-weight:620}
.pt code{font-family:var(--mono);font-size:12px;background:var(--panel-2);padding:1px 5px;border-radius:4px;
color:var(--ink)}
.refs{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-top:9px}
.reflab{font-family:var(--mono);font-size:9.5px;letter-spacing:.12em;text-transform:uppercase;
color:var(--ink-3);margin-right:2px}
a.ref{font-family:var(--mono);font-size:11px;padding:3px 9px;border-radius:5px;text-decoration:none;
background:var(--accent-soft);color:var(--accent);border:1px solid transparent}
a.ref:hover{border-color:var(--accent)}
a.ref:focus-visible{outline:2px solid var(--accent);outline-offset:1px}
@keyframes flash{0%{background:var(--accent-soft);border-left-color:var(--accent)}
100%{background:var(--panel-2);border-left-color:var(--accent)}}
.step.jump{animation:flash 1.6s ease-out}
.nsearch{width:100%;padding:10px 13px;margin:0 0 10px;border-radius:8px;border:1px solid var(--line);
background:var(--panel-2);color:var(--ink);font-family:var(--mono);font-size:12.5px}
.nsearch::placeholder{color:var(--ink-3)}
.nsearch:focus{outline:2px solid var(--accent);outline-offset:1px;border-color:transparent}
.nhint{margin:0 0 14px;font-size:12px;color:var(--ink-3)}
.grp{border:1px solid var(--line);border-radius:10px;margin-bottom:10px}
.grp:last-child{margin-bottom:0}
.grp.empty{opacity:.55}
/* The category header stays pinned while you scroll its tests, so you never lose which
   category you are in after looking away. */
.grp-h{display:flex;align-items:center;gap:11px;padding:11px 14px;background:var(--panel-2);flex-wrap:wrap;
cursor:pointer;list-style:none;position:sticky;top:0;z-index:3;border-radius:9px}
details[open]>.grp-h{border-radius:9px 9px 0 0;border-bottom:1px solid var(--line)}
.grp-h::-webkit-details-marker{display:none}
.grp-h:focus-visible{outline:2px solid var(--accent);outline-offset:-2px}
.grp-done>.grp-h{background:var(--ok-soft)}
.grp-live>.grp-h{background:var(--accent-soft)}
.grp-b.flush{display:block}
.cat{font-family:var(--mono);font-size:12px;font-weight:700;letter-spacing:.06em}
.catname{color:var(--ink-2);font-size:13px;flex:1 1 auto}
.count{font-family:var(--mono);font-size:11.5px;font-variant-numeric:tabular-nums;color:var(--ink-2)}
.bar{width:78px;height:5px;border-radius:3px;background:var(--idle);overflow:hidden;flex:0 0 auto}
.bar i{display:block;height:100%;background:var(--ok);border-radius:3px}

.step{border-top:1px solid var(--line);border-left:3px solid transparent;scroll-margin-top:60px}
.step.flat{padding:10px 14px}
.step-h{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap;padding:11px 14px;cursor:pointer;
list-style:none}
.step.flat .step-h{padding:0;cursor:default}
.step-h::-webkit-details-marker{display:none}
.step-h:focus-visible{outline:2px solid var(--accent);outline-offset:-2px}
details.step>.step-h:hover{background:var(--panel-2)}
details.step>.step-h:hover .stitle{color:var(--accent)}
/* THE ROW YOU ARE READING is marked hard — accent spine, lifted background, accent title.
   Look away, look back, and your place is still obvious. */
details.step[open]{border-left-color:var(--accent);background:var(--panel-2)}
details.step[open]>.step-h .stitle{color:var(--accent);font-weight:640}
.step.todo{opacity:.4}
.sid{font-family:var(--mono);font-size:11px;color:var(--accent);font-weight:600;flex:0 0 auto;
min-width:96px}
.stitle{font-size:13.5px;font-weight:550;flex:1 1 240px;line-height:1.45}
.snote{margin:0;padding:4px 16px 16px;display:flex;flex-direction:column;gap:0}
/* One fact per row, label always in the same column: the eye re-finds the line it lost. */
.seg{display:grid;grid-template-columns:158px minmax(0,1fr);gap:16px;align-items:start;padding:10px 0;
border-top:1px solid var(--line)}
.seg:first-child{border-top:0}
.seg:hover{background:rgba(227,154,75,.055)}
.seg.wide{grid-template-columns:1fr;gap:6px}
@media (max-width:720px){.seg{grid-template-columns:1fr;gap:5px}}
.lab{font-family:var(--mono);font-size:10px;letter-spacing:.06em;padding:3px 7px;border-radius:4px;
justify-self:start;text-align:left;line-height:1.35;word-break:break-word}
.val{font-size:13.5px;color:var(--ink-2);line-height:1.72;max-width:74ch}
.seg.lede{display:block;font-size:14px;color:var(--ink);line-height:1.7;padding:2px 0 12px;max-width:74ch}
p.ln{margin:0 0 9px;padding-left:11px;border-left:2px solid var(--line)}
p.ln:last-child{margin-bottom:0}
.seg:hover p.ln{border-left-color:var(--accent)}
ul.enum{margin:6px 0 0;padding:0;list-style:none;display:flex;flex-direction:column;gap:5px}
ul.enum li{padding-left:24px;position:relative}
ul.enum li b{position:absolute;left:0;top:0;font-family:var(--mono);font-size:10.5px;color:var(--accent);
font-weight:600}
.slead{flex:1 1 100%;font-size:12px;color:var(--ink-3);line-height:1.5;margin:1px 0 0;
display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
details[open]>.step-h .slead{display:none}
.shosts{margin:0;padding:0 14px 12px;font-family:var(--mono);font-size:11px;color:var(--ink-3)}
.pill{display:inline-block;font-family:var(--mono);font-size:10.5px;padding:2px 7px;border-radius:4px;
letter-spacing:.04em;white-space:nowrap;flex:0 0 auto}
.p-ok{background:var(--ok-soft);color:var(--ok)}
.p-warn{background:var(--warn-soft);color:var(--warn)}
.p-stop{background:var(--stop-soft);color:var(--stop)}
.p-live{background:var(--accent-soft);color:var(--accent)}
.p-idle{background:var(--panel-2);color:var(--ink-3)}
.chev{width:8px;height:8px;border-right:1.6px solid var(--ink-3);border-bottom:1.6px solid var(--ink-3);
transform:rotate(45deg);flex:0 0 auto;margin-left:2px;transition:transform .15s ease}
details[open]>.grp-h .chev,details[open]>.step-h .chev,
details[open]>.sum-h .chev{transform:rotate(-135deg)}
.sum-h{display:flex;align-items:center;justify-content:space-between;gap:9px;cursor:pointer;
list-style:none}
.sum-h::-webkit-details-marker{display:none}
.sum-h:focus-visible{outline:2px solid var(--accent);outline-offset:-2px}
.sum-h>h2{margin:0}
details.card.sum:not([open])>.sum-h>h2{opacity:.82}
body.hide-todo .step.todo{display:none}
body.hide-neg .step.neg{display:none}
body.hide-tested .step.tested{display:none}
body.hide-tested .grp.grp-done{display:none}
footer{color:var(--ink-3);font-family:var(--mono);font-size:11px;letter-spacing:.03em;text-align:center}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}

/* ---- bench chrome -------------------------------------------------------
   Substrate: a faint silkscreen grid, well under text contrast so it reads as
   board rather than as decoration. */
body{background-image:
linear-gradient(rgba(138,90,40,.045) 1px,transparent 1px),
linear-gradient(90deg,rgba(138,90,40,.045) 1px,transparent 1px);
background-size:64px 64px;background-attachment:fixed}

/* Fiducial marks — the registration crosshairs a board carries at its corners.
   Drawn on the card box itself, so nothing in the markup has to change. */
.card{position:relative}
.card::before,.card::after{content:"";position:absolute;width:11px;height:11px;pointer-events:none;
border-color:var(--copper);opacity:.85}
.card::before{top:-1px;left:-1px;border-top:1px solid;border-left:1px solid;border-top-left-radius:12px}
.card::after{bottom:-1px;right:-1px;border-bottom:1px solid;border-right:1px solid;
border-bottom-right-radius:12px}

/* Header: a copper trace running out of a via. */
.eyebrow{align-items:center}
.eyebrow::before{content:"";width:7px;height:7px;border-radius:50%;background:var(--ground);
border:1.5px solid var(--accent);flex:0 0 auto}
.top::after{content:"";height:1px;background:
linear-gradient(90deg,var(--copper),rgba(138,90,40,.15) 62%,transparent);margin-top:4px}

/* Phase rail as a channel strip: each phase is a channel, its top edge the trace,
   and a live channel gets a via at the left where the signal enters. */
.ph{position:relative}
.ph.live::before,.ph.done::before{content:"";position:absolute;top:-6px;left:11px;width:7px;height:7px;
border-radius:50%;background:var(--ground);border:1.5px solid var(--idle)}
.ph.done::before{border-color:var(--ok)}
.ph.live::before{border-color:var(--accent)}

/* An open row's spine reads as a copper trace rather than a flat rule. */
details.step[open]{border-left-color:var(--accent);
box-shadow:inset 3px 0 0 -1px rgba(227,154,75,.35)}
.sid{color:var(--accent)}

/* Instrument readouts: counts line up digit-for-digit. */
.count,.fact{font-variant-numeric:tabular-nums}
</style>"""

JS = """<script>
(function(){
  // ---- tabs ----
  function showTab(name){
    document.querySelectorAll('.tabs button').forEach(function(b){
      b.setAttribute('aria-selected', b.dataset.tab === name ? 'true' : 'false');
    });
    document.querySelectorAll('.panel').forEach(function(p){
      p.hidden = p.dataset.panel !== name;
    });
  }
  var tabs = document.querySelector('.tabs');
  if(tabs) tabs.addEventListener('click', function(ev){
    var b = ev.target.closest('button'); if(b) showTab(b.dataset.tab);
  });

  // ---- summary -> detail deep links ----
  // Switch tab, open every collapsed ancestor, scroll to it, flash it. A reference is useless if it
  // lands the reader on a closed <details>.
  function reveal(id){
    var el = document.getElementById(id);
    if(!el) return false;
    showTab('detail');
    document.body.classList.remove('hide-todo');
    var t = document.querySelector('.toolbar button[data-act="todo"]');
    if(t){ t.setAttribute('aria-pressed','false'); t.textContent = 'Hide untested'; }
    var node = el;
    while(node){
      if(node.tagName === 'DETAILS') node.open = true;
      node = node.parentElement;
    }
    el.scrollIntoView({block:'center'});
    el.classList.remove('jump');
    void el.offsetWidth;
    el.classList.add('jump');
    return true;
  }
  document.addEventListener('click', function(ev){
    var a = ev.target.closest('a.ref'); if(!a) return;
    ev.preventDefault();
    if(reveal(a.dataset.ref)) history.replaceState(null, '', '#' + a.dataset.ref);
  });
  if(location.hash) setTimeout(function(){ reveal(location.hash.slice(1)); }, 60);

  // Each tab carries its own controls, and expand/collapse acts on THAT tab only - an
  // unscoped expand from the summary would throw open every note and every test at once.
  document.querySelectorAll('.toolbar').forEach(function(bar){
    bar.addEventListener('click', function(ev){
      var b = ev.target.closest('button'); if(!b) return;
      var act = b.dataset.act;
      if(act === 'expand' || act === 'collapse'){
        var open = act === 'expand';
        var scope = bar.closest('.panel') || document;
        scope.querySelectorAll('details').forEach(function(d){ d.open = open; });
      }
      if(act === 'todo'){
        var on = document.body.classList.toggle('hide-todo');
        b.setAttribute('aria-pressed', on ? 'true' : 'false');
        b.textContent = on ? 'Show untested' : 'Hide untested';
      }
      if(act === 'tested'){
        var onT = document.body.classList.toggle('hide-tested');
        b.setAttribute('aria-pressed', onT ? 'true' : 'false');
        b.textContent = onT ? 'Show tested' : 'Hide tested';
      }
      if(act === 'neg'){
        var onN = document.body.classList.toggle('hide-neg');
        b.setAttribute('aria-pressed', onN ? 'true' : 'false');
        b.textContent = onN ? 'Show negatives' : 'Hide negatives';
      }
    });
  });
  // Filter the notes list. Matching rows are revealed and their group opened, so a search never
  // leaves a hit hidden inside a collapsed section.
  var box = document.querySelector('.nsearch');
  if(box){
    var card = box.closest('.card');
    box.addEventListener('input', function(){
      var q = box.value.trim().toLowerCase();
      card.querySelectorAll('details.grp').forEach(function(g){
        var shown = 0;
        g.querySelectorAll('details.step').forEach(function(s){
          var hit = !q || s.textContent.toLowerCase().indexOf(q) !== -1;
          s.style.display = hit ? '' : 'none';
          if(hit) shown++;
          if(q && hit) s.open = true;
          if(!q) s.open = false;
        });
        var c = g.querySelector('.count');
        if(c){
          if(!c.dataset.total) c.dataset.total = c.textContent;
          c.textContent = q ? shown + '/' + c.dataset.total : c.dataset.total;
        }
        g.style.display = (q && !shown) ? 'none' : '';
        g.open = q ? shown > 0 : false;
      });
    });
  }
})();
</script>"""


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    key = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else f"/tmp/{key}-walk.html"
    ws = W.load(key)
    if not ws:
        print(f"no such workspace: {key}")
        sys.exit(1)
    try:
        accounts = W.get_accounts(key)
    except Exception:
        accounts = []
    with open(out, "w", encoding="utf-8") as f:
        f.write(render(ws, accounts))
    walked = sum(1 for i in ws.get("wstg", []) if i["status"] != "todo")
    print(f"wrote {out}  ({walked}/{len(ws.get('wstg', []))} tests, "
          f"{sum(len(v) for v in ws.get('stride', {}).values())} threats)")


if __name__ == "__main__":
    main()

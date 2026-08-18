#!/usr/bin/env python3
"""walk_report.py — render a PROGRAM WALK status board (STRIDE + WSTG) as a self-contained HTML page.

Reads a program workspace and emits EVERY sub-step with its recorded outcome, so the board is a
drill-down record ("what did each test find?"), not a scoreboard of counts. Every category and every
step collapses, so a 97-test walk stays navigable. Regenerate after any batch of steps and republish
to the SAME artifact URL.

    python3 tools/walk_report.py <workspace-key> [out.html]

Doctrine: docs/knowledge/process-stride-wstg.md ("Standing rules of this workflow").
"""
import sys, os, html, datetime
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


def step(sid, title, status, note=None, extra=None, dim=False):
    """One collapsible sub-step. Without a note it is a plain non-expanding row."""
    pill = f'<span class="pill {PILL.get(status,"p-idle")}">{e(status)}</span>'
    head = (f'<span class="sid">{e(sid)}</span>'
            f'<span class="stitle">{e(title)}</span>{pill}')
    if not note:
        return f'<div class="step flat{" todo" if dim else ""}"><div class="step-h">{head}</div></div>'
    body = f'<p class="snote">{e(note)}</p>'
    if extra:
        body += f'<p class="shosts">{e(extra)}</p>'
    return (f'<details class="step"><summary class="step-h">{head}'
            f'<span class="chev" aria-hidden="true"></span></summary>{body}</details>')


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
    A('<p class="sub">Every sub-step and what it found. Categories are walked in order; a test is only '
      'closed with its outcome recorded. Click any row to read the finding.</p>')
    A('<div class="facts">')
    A(f'<span class="fact go"><b>{e(ws.get("platform","?")).upper()}</b></span>')
    A(f'<span class="fact">WSTG <b>{walked}/{len(wstg)}</b></span>')
    A(f'<span class="fact">STRIDE <b>{stride_n}</b></span>')
    A(f'<span class="fact">notes <b>{len(ws.get("notes",[]))}</b></span>')
    A(f'<span class="fact">accounts <b>{len(accounts)}</b></span>')
    A("</div></header>")

    A('<section class="card"><h2>Phases</h2><div class="rail">')
    for n, t, state, s in phases(ws):
        A(f'<div class="ph {state}"><div class="n">{n}</div><div class="t">{t}</div>'
          f'<div class="s">{e(s)}</div></div>')
    A("</div></section>")

    A('<div class="toolbar" role="group" aria-label="View controls">'
      '<button type="button" data-act="expand">Expand all</button>'
      '<button type="button" data-act="collapse">Collapse all</button>'
      '<button type="button" data-act="todo" aria-pressed="false">Hide untested</button>'
      '<span class="hint">click a row to read its finding</span></div>')

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
            A(step(r.get("id", ""), r.get("threat", ""), r.get("status", "open"),
                   r.get("note"), ", ".join(r.get("hosts") or [])))
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
            A(step(i["id"], i["name"], i["status"], None if todo else i.get("note"), dim=todo))
        A("</div></details>")
    A("</section>")

    if accounts:
        A('<section class="card"><h2>Owned accounts</h2><div class="grp-b flush">')
        for a in accounts:
            A(step(str(a.get("label", "?")).upper(),
                   f'{a.get("name","")} · id {a.get("user_id","?")}',
                   a.get("offer", "") or "owned", a.get("notes")))
        A("</div></section>")

    if ws.get("notes"):
        A('<section class="card"><h2>Recorded knowledge</h2><div class="grp-b flush">')
        for n in ws["notes"]:
            txt = n.get("text", "")
            head = txt.split("—")[0].split(" - ")[0][:90].strip() or "note"
            A(step(n.get("ts", "")[:10], head, "note", txt))
        A("</div></section>")

    A(f'<footer>generated {gen} &middot; tools/walk_report.py &middot; '
      f'{walked}/{len(wstg)} tests recorded &middot; {stride_n} threats</footer>')
    A("</div>")
    A(JS)
    return "\n".join(P)


CSS = """<style>
:root{--ground:#F7F5FA;--panel:#FFF;--panel-2:#F1EDF6;--line:#DFD8EA;--ink:#191324;--ink-2:#544A66;
--ink-3:#867B9B;--accent:#7A2FD4;--accent-soft:#EFE4FC;--ok:#12876A;--ok-soft:#DDF2EA;--warn:#9A6407;
--warn-soft:#FAEED6;--stop:#B4322F;--stop-soft:#FBE3E2;--idle:#CFC6DE;
--sans:"Segoe UI Variable Text","Segoe UI",Inter,system-ui,-apple-system,sans-serif;
--mono:ui-monospace,"Cascadia Mono","SF Mono",Menlo,Consolas,monospace}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--ground:#0D0A13;--panel:#161020;
--panel-2:#1E1630;--line:#2C2340;--ink:#EFEAF7;--ink-2:#B0A4C6;--ink-3:#7D7196;--accent:#B478F5;
--accent-soft:#2A1B44;--ok:#49D3A4;--ok-soft:#10312A;--warn:#E8B45C;--warn-soft:#33260F;--stop:#F2706C;
--stop-soft:#3A1918;--idle:#3B3151}}
:root[data-theme="dark"]{--ground:#0D0A13;--panel:#161020;--panel-2:#1E1630;--line:#2C2340;--ink:#EFEAF7;
--ink-2:#B0A4C6;--ink-3:#7D7196;--accent:#B478F5;--accent-soft:#2A1B44;--ok:#49D3A4;--ok-soft:#10312A;
--warn:#E8B45C;--warn-soft:#33260F;--stop:#F2706C;--stop-soft:#3A1918;--idle:#3B3151}
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

.grp{border:1px solid var(--line);border-radius:10px;margin-bottom:10px;overflow:hidden}
.grp:last-child{margin-bottom:0}
.grp.empty{opacity:.55}
.grp-h{display:flex;align-items:center;gap:11px;padding:11px 14px;background:var(--panel-2);flex-wrap:wrap;
cursor:pointer;list-style:none}
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

.step{border-top:1px solid var(--line)}
.step.flat{padding:10px 14px}
.step-h{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap;padding:10px 14px;cursor:pointer;
list-style:none}
.step.flat .step-h{padding:0;cursor:default}
.step-h::-webkit-details-marker{display:none}
.step-h:focus-visible{outline:2px solid var(--accent);outline-offset:-2px}
details.step>.step-h:hover .stitle{color:var(--accent)}
.step.todo{opacity:.45}
.sid{font-family:var(--mono);font-size:11px;color:var(--accent);font-weight:600;flex:0 0 auto}
.stitle{font-size:13.5px;font-weight:550;flex:1 1 240px}
.snote{margin:0;padding:0 14px 14px 14px;font-size:13px;color:var(--ink-2);line-height:1.62;max-width:92ch}
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
details[open]>.grp-h .chev,details[open]>.step-h .chev{transform:rotate(-135deg)}
body.hide-todo .step.todo{display:none}
footer{color:var(--ink-3);font-family:var(--mono);font-size:11px;letter-spacing:.03em;text-align:center}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
</style>"""

JS = """<script>
(function(){
  var bar = document.querySelector('.toolbar');
  if(!bar) return;
  bar.addEventListener('click', function(ev){
    var b = ev.target.closest('button'); if(!b) return;
    var act = b.dataset.act;
    if(act === 'expand' || act === 'collapse'){
      var open = act === 'expand';
      document.querySelectorAll('details').forEach(function(d){ d.open = open; });
    }
    if(act === 'todo'){
      var on = document.body.classList.toggle('hide-todo');
      b.setAttribute('aria-pressed', on ? 'true' : 'false');
      b.textContent = on ? 'Show untested' : 'Hide untested';
    }
  });
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

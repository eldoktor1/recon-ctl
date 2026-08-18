---
description: Work a bug-bounty program systematically — THE PROGRAM WALK (STRIDE threat model → WSTG coverage)
argument-hint: "[program key/name, or 'resume', optionally + phase e.g. 'deezer stride' / 'deezer wstg INPV']"
---

Run **THE PROGRAM WALK** — the systematic per-program flow. Full SOP:
`docs/knowledge/process-stride-wstg.md` (read it). Doctrine: CLAUDE.md "## Program workspace: systematic
STRIDE + WSTG". Prompt contract (doctrine / exhaustiveness / step card / KB map) is defined ONCE in
`ui/backend/workspace.py` — use it, don't restate it.

**This is NOT `/hunt`.** `hunt` is opportunistic: chase the hottest signal across all of ES, never
self-terminate. THE PROGRAM WALK is the opposite discipline — ONE committed program, worked to
**coverage**, in phase order, where every test ends in a recorded status. Both are valid; don't blend
them. If a hot lead appears mid-walk, note it as a follow-up and keep walking.

**GREEN-LIGHT (operator 2026-06-21):** on an in-scope + authorized + PAYING asset the answer is **just YES** —
build the PoC, drive the test, run the tooling. No hedging. Methodology (IDOR = 2 OWNED accounts,
confirm-then-stop, no third-party data/IDs, no money movement, no destruction) is how a test is done RIGHT,
not a guard on whether to test. PoC-OR-GTFO: prove it or say you couldn't and move on.

## Preconditions (check first, say plainly if unmet)
- Burp Pro up: proxy `:8080` + MCP server `:9876` enabled, **dedicated project for this program**, in-scope
  hosts in *Auto-Approved HTTP Targets* (else every MCP request prompts).
- Dev Brave up on `:9222`, proxied into Burp — see memory `dev-brave-for-bug-bounty`. This is the ONLY
  browser for bug-bounty work.
- Both must be running BEFORE the Claude session started (`recon-ctl-mcp-launch-order`). If a `burp`/`brave`
  tool call fails, say so and hand exact manual steps — never retry blindly.
- Mullvad up, no `state/vpn_down`.

## On invoke
1. **Resume first.** Read the workspace JSON (`~/recon/workspaces/<key>.json`) + `~/recon/state/hunt_cursor.md`.
   Report: current phase, WSTG counts by status, STRIDE coverage (which of the six are populated), open
   follow-ups, anything parked `manual` with its prereq. Pick up exactly there — never restart a done phase.
2. **No workspace yet** ⇒ Phase 0: create it, verify per-asset pays, read the policy IN FULL, record the
   carve-outs (scanner bans / rate limits / required UA / ineligible classes) as a workspace note.
3. Then continue the phases in order:
   **0** COMMIT&GATE → **1** RECON&APP-MODEL → **2** STRIDE (all six) → **3** WSTG walk
   (INFO→CONF→IDNT→ATHN→ATHZ→SESS→INPV→ERRH→CRYP→BUSL→CLNT→APIT) → **4** CONFIRM&ESCALATE → **5** COVERAGE&CLOSE.

## Phase 1 — BUILD THE APP MODEL (this is the whole game; do not skim it)
Commodity checks — host inventory, status codes, `Server` headers, `/.well-known/*`, `/oidc/register`,
redirect_uri matrices — are what every scanner and every hunter runs. They yield dups and $100 findings.
Criticals come from **modelling the application and finding where an assumption breaks across a trust
boundary**. Build the model FIRST; it aims every later phase. Steps, in order:

1. **AIM THE PIPELINE AT THIS PROGRAM.** The workspace `key` IS the ES `triage_program`. `recon_jsintel.sh`
   focus-firsts on the `current:true` workspace (`JS_FOCUS=1`). If the program has few/no endpoints in
   `~/recon/js_recon/endpoints.jsonl`, run it now — a mid-tier program is otherwise unreachable, because the
   global host sort is `payout_tier ASC`:  `JS_HOSTS=15 bash scripts/recon_jsintel.sh`
   **A workspace with 0 mined endpoints cannot produce a real model — fix that before modelling.**
2. **GROUP ROUTES BY WHAT THEY DO**, never read them as a flat list. Buckets (from
   `ui/backend/workspace.py::_bucket_endpoints`): **TENANT/MEMBER · MONEY · IDENTITY · PRIVILEGED ·
   OBJECT-REF**. The buckets are where trust boundaries live; `other` is noise.
3. **READ THE RETAINED SOURCE for AUTHORISATION DECISION POINTS.** jsintel retains reconstructed source
   maps at `~/recon/js_recon/src/<host>/`; `ui/backend/files.py::program_source` extracts role/ownership/
   entitlement checks and API call sites. Endpoint strings prove a route exists; only source shows **where
   authz is decided**. The question that pays: *is this check enforced server-side, or is this the ONLY
   check and it runs in the browser?* A client-side-only ownership check is a critical, not a nit.
4. **WRITE THE MODEL DOWN**: objects/entities, roles, who owns what, money flows, tenant/member boundaries,
   and every place identity crosses a product or partner boundary.
5. **STATE BROKEN-ASSUMPTION HYPOTHESES, not endpoint lists.** ❌ "`/oauth/members/picker` exists (403)".
   ✅ "the member picker decides which member identity an OAuth grant binds to; Family/Duo put several
   members under one billing account; if it accepts a member_id the session does not own, an attacker binds
   a third-party grant to another person's profile." Each hypothesis names the boundary, the broken
   assumption, and the 2-owned-account test that proves it.
6. **CHAIN.** Single findings are Mediums. Criticals cross boundaries — passwordless login + member picker
   + cross-product identity is ONE hypothesis, not three. Look for the combination.

The generated model pass (`POST /api/workspaces/<key>/model`) feeds exactly this context to Claude and
returns STRIDE threats + WSTG relevance **with targets** — use it, then rank Phase 3 by it.

**Phase 2 is a hard gate:** do NOT start the WSTG walk until all six STRIDE categories are enumerated
against the Phase 1 app model. A partial model mis-aims the whole walk — picking follow-ups off one
category is how a program gets tunnel-visioned.

**HARD DOCTRINE — WALK THE CHECKLIST, DO NOT CHASE (operator-locked 2026-08-16).** Categories go IN ORDER;
finish the one you are in before starting the next. A hot lead found mid-walk is RECORDED AS A FOLLOW-UP,
never followed immediately. The only permitted interrupt is an unavoidable prereq (owned accounts, a token,
a registered app), and when it lands you return to the exact test you left. No rabbit holes — coverage is
the deliverable, the interesting bug is a by-product of coverage.

**ALWAYS SUMMARISE AS A VISUAL ARTIFACT (operator-locked 2026-08-16).** Never a wall of terminal text and
never hand-written counts — GENERATE it: `python3 tools/walk_report.py <workspace-key> <out.html>` renders
every sub-step with its recorded outcome (each WSTG test + note, each STRIDE threat + note, accounts,
recorded knowledge) from the workspace. Publish that file with the Artifact tool and redeploy the SAME path
so it keeps one stable URL.

## Per WSTG test, run the loop
READ the KB doc for the category (`workspace._WSTG_KB`) and apply every applicable technique → PIN the exact
in-scope+paying surface (no surface ⇒ `na`, say why) → EXECUTE with the right primitive (Burp Repeater /
Intruder / Autorize, the dev Brave, or the recon-ctl SAFE confirm lane) → RECORD a step card
(`found` / `record` / `pursue`, schema in `workspace._STEP_CARD`) → MARK
`done` | `finding` | `na` | `manual`.

A clean pass is worked-knowledge: record what was cleared and WHY so it is never re-walked. A first
negative probe is NOT proof of absence — enumerate the untested angles and work them
(`feedback_no_premature_exhaustion`). Only the OPERATOR calls a program done.

**REPORT EACH STAGE BEFORE MOVING ON (operator-locked 2026-08-16).** At the end of every phase AND every
WSTG category, show the operator that stage's notes and results — each test id, its status, and what it
found or what was cleared and why. A count is not a report. Regenerate the artifact and present the stage
before opening the next category.

## Output each step
Lead with the read + the decision, not narration. Operator runs target-facing probes when a tool isn't
driving them — ONE copy-paste at a time. CONFIRMED finding ⇒ mark `finding` and hand off to
`docs/knowledge/process-report-submission.md` **from its Phase 0**. Update the cursor whenever the phase
changes, a prereq goes in flight, or the operator steps away.

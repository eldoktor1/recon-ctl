# process: STRIDE + WSTG program SOP (how a committed program is WORKED)

The repeatable pipeline for working a whole PROGRAM systematically, never ad-hoc. Do the phases IN ORDER.
STRIDE builds the model; the model AIMS the WSTG walk; the WSTG checklist IS the plan and the
worked-vs-left record. Nothing is tested off-book.

Scope of this doc: **program → coverage**. It hands off to [[process-report-submission]] the moment a
finding is CONFIRMED, and it is the systematic counterpart to the opportunistic `hunt` flow (CLAUDE.md
THE HUNT FLOW) — use `hunt` to chase a hot signal, use THIS to take a program to completion.

Canonical state lives in the workspace JSON (`~/recon/workspaces/<key>.json`), driven by the recon-ui
Program Workspace. The prompt contract (doctrine, exhaustiveness, step card, KB map) is defined ONCE in
`ui/backend/workspace.py` — read it there, do not restate it elsewhere.

---

## Phase 0 — COMMIT & GATE  (once per program, before ANY testing)
- [ ] Workspace exists and is `current`: `status=active`, seeded WSTG + STRIDE (`workspace.create`).
- [ ] **Per-asset** scope+pays confirmed from `scope/raw/<plat>.json` — `targets.in_scope[].eligible_for_bounty`,
      NOT the program-level `pays` ([[feedback_scope_check_per_asset_pays_bug]]).
- [ ] Program policy read **IN FULL** (Overview + RoE + Scope + Out-of-scope/Ineligible). This is the same
      gate as [[process-report-submission]] Phase 0, run ONCE at program level so it can't be skipped later.
- [ ] **Record the carve-outs into a workspace note** — they change what the rest of this SOP may do:
      automated-scanner bans (kills the nuclei/dalfox/sqlmap/kr lanes for this program), rate limits,
      "do not reproduce again", third-party/customer-asset exclusions, required UA/header tags, VPN/IP
      requirements, ineligible classes.
- [ ] **Dedicated Burp project** for the program (one per program) so proxy history / Repeater / Intruder /
      Autorize state persists across the engagement. Add in-scope hosts to Auto-Approved HTTP Targets.
- [ ] Any host with existing `host_notes` — read them. Do not re-walk a killed angle.

Gate fails on any line ⇒ `recon-note` + DROP the program (or the specific asset). A passing gate is a FULL
green light — over-caution on clean in-scope work is the other failure mode
([[feedback_dont_obstruct_authorized_testing]], [[feedback_poc_or_gtfo]]).

## Phase 1 — RECON & APP MODEL  (you cannot threat-model what you have not mapped)
Build the picture STRIDE will reason over. Passive/cheap first, then target traffic.
- **Surface**: ES join on `triage_program`, then widen — `recon-uncover`, `recon-permute`, CT/`fresh`,
  `recon-kr` on bare API hosts. Exclude benched (`ignore_expires_at > now`) and non-paying assets.
- **Endpoints**: `recon-jsintel` (jsluice + source-map reconstruction), `recon-params crawl-host`, kiterunner routes.
- **Stack + VERSIONS**: headers, JS bundles, error pages, favicon hash, `/actuator`, framework fingerprints.
  Version-reason every CVE/KEV match — tech-class alone is a LEAD, never P0.
- **Walk the app in the proxied browser** with the Burp project recording, so the site map is real, not inferred.
- **Write the app model** into the workspace: assets, **roles** (anon / user / premium / admin / partner),
  **object types + ID shapes** (numeric=enumerable, uuid=harvestable), **data flows**, **trust boundaries**,
  auth mechanism (session cookie / JWT / OAuth), and every entry point.

Output: an app model concrete enough that a threat can name the asset, role, and flow it attacks.

## Phase 2 — STRIDE THREAT MODEL  (ALL SIX categories, before any WSTG test)
Per category, enumerate threats against the Phase 1 model using the prompts in `workspace.STRIDE_GUIDE`:

| | Category | Aim at |
|---|---|---|
| **S** | Spoofing | auth schema, token/JWT forgery, session fixation, SSO/OAuth flows, host/email spoofing |
| **T** | Tampering | client-trusted data, hidden/priced fields, mass assignment, param pollution, injection |
| **R** | Repudiation | state-changing actions with no tamper-evident audit trail, forgeable logs |
| **I** | Info disclosure | IDOR/BOLA, verbose errors, JS secrets, source maps, buckets, backups |
| **D** | Denial of service | unbounded/expensive ops, missing rate limits — **reason about it, never actually DoS** |
| **E** | Elevation of privilege | vertical/horizontal authz bypass, forced browsing to admin, IDOR→privesc chains |

RULES:
- **Do not start Phase 3 until all six are enumerated.** A partial model mis-aims the whole WSTG walk —
  picking follow-ups off one category is how a program gets worked with tunnel vision.
- Each threat must be **target-specific and concrete** ("`connect.deezer.com` OAuth accepts an unregistered
  `redirect_uri` → code theft"), never generic ("XSS possible").
- Rank by **payout × likelihood × dup-resistance**. Product-class/shipped-API threats are near-certain dups —
  deprioritise (THE MOTTO).
- Promote the top threats to workspace **follow-ups** with `why` + `priority`. Follow-ups are the money
  worklist; the WSTG walk is the coverage guarantee. Both run — they are not alternatives.

## Phase 3 — WSTG WALK  (category by category: INFO→CONF→IDNT→ATHN→ATHZ→SESS→INPV→ERRH→CRYP→BUSL→CLNT→APIT)

> **HARD DOCTRINE — WALK THE CHECKLIST, DO NOT CHASE.** Work the categories IN ORDER and finish the category
> you are in before starting the next. A hot lead found mid-walk is **recorded as a follow-up, never followed
> immediately**. The ONLY permitted interrupt is an unavoidable prereq (owned accounts, a token, a registered
> app) — and the moment it lands you return to the exact test you left. Skipping ahead to the interesting
> class *feels* productive while leaving whole categories permanently unwalked; that is the failure mode this
> SOP exists to prevent. Coverage is the deliverable — the interesting bug is a by-product of coverage.

Walk in order. Per test, run this loop:

1. **READ the KB methodology** for the category (mapping in `workspace._WSTG_KB`) and apply EVERY applicable
   technique/payload/bypass, not the happy path. No KB doc for a class you're about to work ⇒ research it
   first, then APPEND what you learn (RESEARCH MANDATE).
2. **PIN the surface** — name the real in-scope+paying hosts/endpoints/params this test applies to. A test
   with no matching surface is `na`, and say why.
3. **EXECUTE with the right primitive** — Burp Repeater/Intruder/Autorize, the proxied browser, or the
   recon-ctl lane that is the SAFE confirm primitive for the class. Read-only by default.
4. **RECORD a step card** (schema in `workspace._STEP_CARD`): `found` (evidence, not narration) /
   `record` (worked-knowledge note, persisted verbatim) / `pursue` (ranked real next moves).
5. **MARK status**: `done` | `finding` | `na` | `manual` (needs owned accounts / operator-run tool / authed
   confirm). `manual` is a real outcome — it parks the test with its prereq, it does not skip it.

Category → KB doc → the lane that usually confirms it:

| Cat | KB methodology | Typical confirm lane |
|---|---|---|
| INFO | class-unauth-hunting | crawl-host, uncover, permute, kr, tech |
| CONF | class-bucket-exposure, class-takeover, class-cache-deception, class-403-bypass | buckets, wcd, baddns |
| IDNT | class-idor | owned-account provisioning |
| ATHN | class-jwt-attacks | Burp Repeater (token forgery) |
| ATHZ | class-idor | 2-owned-account swap, Autorize |
| SESS | class-jwt-attacks | Burp (fixation/rotation diff) |
| INPV | class-xss, class-sqli, class-ssrf, class-domxss | confirm-xss (dalfox), confirm-sqli, interactsh |
| ERRH | class-unauth-hunting | Burp Repeater |
| CRYP | class-jwt-attacks | Burp / manual |
| BUSL | class-race-conditions, class-idor | Burp (Turbo/race), 2 owned accounts |
| CLNT | class-domxss, class-xss, class-clientside-secrets, class-firebase | domxss, blindxss |
| APIT | class-graphql, class-idor, class-ssrf | graphql, kr |

**A clean pass is worked-knowledge too** — record what was cleared and WHY so it is never re-walked. A note
saying "clean" is a provisional checkpoint on THAT angle, never a tombstone
([[feedback_no_premature_exhaustion]]).

## Phase 4 — CONFIRM & ESCALATE
- **CONFIRMED** = an exploitable primitive directly observed. **LEAD** = pattern only. Only CONFIRMED mints P0;
  LEADs clamp to P1-max. Reflection is not XSS; introspection-enabled is not a finding; public-read is not a
  bucket finding.
- **PoC-OR-GTFO**: prove it or say you couldn't and move on. No theoretical-severity hedging.
- Authed / 2-account work: TWO accounts the researcher OWNS, swap only owned IDs, confirm-then-stop.
  Never guessed or enumerated third-party IDs. Authenticated testing stays operator-overseen.
- Anti-burn: respect 429/403, back off, never get the Mullvad exit banned.
- CONFIRMED ⇒ mark the WSTG item `finding` and hand off to **[[process-report-submission]] from Phase 0**.

## Phase 5 — COVERAGE & CLOSE
The program is **covered** when every WSTG item is `done` / `na` / `finding`, every STRIDE threat is resolved
(tested, converted to a follow-up, or explicitly dropped with a reason), and every `manual` has its prereq
recorded. Coverage ≠ "no bugs here" — only the OPERATOR calls a program done.

On pause: update `~/recon/state/hunt_cursor.md` with the current phase, the open follow-ups, and any prereq
in flight, so a comeback never loses the thread.

---

## Standing rules of this workflow (operator-locked 2026-08-16)
These bind every program walk, not just the one in front of you.
1. **Walk the checklist, do not chase.** Categories in order; finish the one you are in. Hot lead ⇒ follow-up,
   not a detour. Only an unavoidable prereq may interrupt, and you return to the exact test you left.
2. **Every probe names its WSTG id.** If a request doesn't belong to a test on the checklist, you are chasing.
3. **Summarise as a visual Artifact**, never a wall of terminal text, and never hand-written counts.
   Generate it: `python3 tools/walk_report.py <workspace-key> <out.html>` renders EVERY sub-step with its
   recorded outcome (each WSTG test + note, each STRIDE threat + note, accounts, recorded knowledge) straight
   from the workspace. Publish that file, and republish the SAME path so the artifact keeps one stable URL.
   The board is a drill-down record — "what did each test find?" — not a scoreboard.
4. **Dev Brave only** (`brave-recon-debug`, CDP :9222, proxied into Burp) — never the daily browser, and never
   a browser that is split-tunnelled out of Mullvad (`chrome.exe` is). See [[dev-brave-for-bug-bounty]].
5. **Burp + dev Brave must be running BEFORE Claude starts** — MCP binds at session start and cannot reconnect.
   Dedicated Burp project per program; in-scope hosts in Auto-Approved HTTP Targets.
6. **Hunter tag first, and PROVE it lands.** Set the program's mandated UA (Burp Match&Replace for browser
   traffic; written into the raw request for Repeater/MCP calls), then verify with a unique marker request
   before any real testing. See [[ywh-hunter-tag]].
7. **Read host_notes before ranking anything.** Prior worked-knowledge kills angles and prevents duplicate work.
8. **Where bot management is present (Akamai etc.), drive forms BY HAND.** CDP-driven form filling trips the
   sensor (`_abck` flips to `~-1~`) and produces misleading generic errors; the operator clicks, Claude reads Burp.
9. **Burp proxy-history reads are oldest-first** (`offset 0`) — use a unique marker + regex to find recent
   traffic, or you will analyse stale requests and draw the wrong conclusion.
10. **Prefer offline oracles over live enumeration** — the app's own JS bundles and public reverse-engineering
    clients map an internal API far more cheaply and quietly than probing, and stay inside scanner bans.
11. **Keep step notes SHORT — verdict first.** A step note is 1-3 sentences: the verdict, the one piece of
    evidence that proves it, and anything carried forward. Target under ~250 characters. Long-form context
    belongs in a workspace note, not under every checklist row — at 97 tests the board becomes unreadable
    and stops being used. Write it tight the first time.
12. **Report each stage before moving on.** At the end of every phase AND every WSTG category, SHOW the
    operator that stage's recorded notes and results — each test id, its status, and what it actually found
    (or what was cleared and why). A count is not a report. Do not open the next category until the finished
    one has been presented and the artifact regenerated.

## Hard lines (never overridden by any phase above)
Only in-scope + paying assets. IDOR/BAC uses two OWNED accounts. Never harvest third-party data, move money,
run destructive/DoS/RCE-for-harm, or bypass a login to get in. Autonomous probing stays unauthenticated,
non-destructive, rate-limited, Mullvad-gated. Note EVERY FP / skip / disqualification / noise at the moment
you hit it — a judgment not written down is incomplete work.

---

## NO SURFACE CHECKS ON A COMMITTED PROGRAM (operator-locked 2026-08-18)

**"No more surface check for programs."** A surface check is not a lighter version of the work; on a
committed program it is a WRONG ANSWER, because it produces the same output a stranger's scanner
produces an hour later — a duplicate — while consuming the evening that could have produced a real
finding. It also poisons the record: a shallow pass written up as a clean pass becomes worked-knowledge
that stops anyone looking there again.

**Binding rules:**
1. A lane is not "checked" until it is EXHAUSTED or a hard blocker is named. "I ran one probe and it
   was 403" closes nothing — state precisely what that probe did and did not answer.
2. No sampling where enumeration is possible. All bundles, all operations, all endpoints, all hosts —
   or an explicit written reason why not.
3. Every negative must carry its own limits (what it does NOT rule out). See the SEEK bucket note:
   403 on ListBucket does not clear object-level ACLs.
4. Never report a phase complete on partial coverage. Report the actual numbers.

## DEPTH DOCTRINE — "as deep as we can get, for programs, ALWAYS" (operator-locked 2026-08-18)

**Surface-level work on a committed program is a failure, even when it produces tidy notes.**
The operator called this out mid-walk on SEEK: 26 workspace notes had been recorded off ~5
incidentally-captured HTTP messages, while the actual depth was thin. Recording is not digging.

**The standard for every program, every phase:**
- **Exhaust the client.** Not one JS bundle — ALL of them. Enumerate the module graph
  deterministically (entry HTML -> modulepreload -> follow every `import` edge), never from
  `performance.getEntriesByType('resource')`, whose buffer is capped and is CLEARED on SPA
  navigation (this silently returned 0 results mid-SEEK and looked like a real negative).
- **Enumerate the API surface, don't sample it.** Every GraphQL query AND mutation, every REST
  path, every role/permission string. One confirmed operation is not a map.
- **Use what we already own before touching the target.** `endpoints.jsonl`, ES, Burp history,
  reconstructed source maps. Leaving 2,000 already-mined endpoints unread while calling a program
  "modelled" is the exact failure this doctrine forbids.
- **Never generalise a probe.** One production host answering does NOT answer a question about
  staging hosts. State what was actually tested and what was not.
- **A silent zero is a bug until proven otherwise.** If an extraction returns nothing, instrument
  and re-run before recording it as a negative. Empty results are the easiest false negative to
  believe.
- **Depth beats breadth on a committed program.** We are not racing a scanner; we are looking in
  the corners nobody looks at. "The nooks and crannies" is the whole thesis (see the MOTTO).

Ties to [[feedback_no_premature_exhaustion]]: "haven't found it yet" is not "not there", and a
surface pass is not evidence of absence. Only the OPERATOR calls a program done.


## TRUST IS AN INSTRUMENT, NOT A CLAIM (operator-locked 2026-08-18)

The operator asked mid-walk: "how can I trust that you are being as thorough as possible?"
The correct answer is never reassurance. An agent narrating its own work will always sound
more complete than it is, because it reports what it DID and is silent about what it never
touched. Prose hides the silence; a ledger exposes it.

**`tools/coverage_audit.py <workspace-key>` is the answer.** It is generated from ES, the
workspace JSON and endpoints.jsonl - not from any agent's self-report - and it prints what is
MISSING: assets never contacted, hosts known vs contacted, already-mined endpoints left
unread, WSTG resolved vs todo, STRIDE enumerated vs tested. Run it whenever a claim of
progress is made. The numbers are hand-checkable.

**Binding rules:**
1. **Numbers before prose.** Every stage report leads with coverage figures. "26 notes" is
   not coverage; 1/97 WSTG is.
2. **Declare what you touched.** Any asset an agent sent traffic to gets a workspace note
   prefixed `COVERAGE-TOUCHED:` with a depth label (DEEP / PARTIAL / OBSERVED ONLY). Any
   known-but-untouched asset gets an explicit `COVERAGE-UNTOUCHED:` note, so silence can
   never be mistaken for "cleared".
3. **Rich artefacts are not coverage.** A detailed app model, a long note list and a good
   threat model can coexist with ~0% of the estate contacted. That combination is the exact
   failure this rule exists to catch - it happened on SEEK: 42 notes, 34 threats, and 3 of
   686 hosts contacted.
4. **Every negative states its limits** (what it does NOT rule out), or it is not a negative.
5. **The operator audits, the agent does not grade itself.** Only the OPERATOR calls a
   program done.


## TL;DR ALWAYS — REPORT ONLY WHAT THE OPERATOR NEEDS (operator-locked 2026-08-19)

The operator works evenings. Long stage reports are a tax on the only scarce resource in this
whole system: their attention. Detail belongs in the WORKSPACE and the ARTIFACT, which are
durable, searchable and machine-generated. Chat is for decisions.

**Every reply during a program walk MUST open with a TL;DR and MUST fit on one screen.**

Required shape:
1. **One line of status** — coverage numbers (WSTG x/97, threats tested x/34), nothing else.
2. **What changed** — max 3 bullets. New confirmed facts or killed theories only.
3. **What I need from you** — the decision or action, stated as a question. If nothing is
   needed, say "nothing needed" and continue.

Hard rules:
- **No narration of method** unless it changed the result. The operator does not need the tool
  calls, the debugging, or the reasoning chain - those are in the workspace notes.
- **Corrections are one line.** "I was wrong about X; it is actually Y." Not a retrospective.
- **Never re-explain what was already reported.** Assume the operator read the last TL;DR.
- **Tables over prose** for anything with more than two dimensions.
- **Findings and blockers are the only things worth expanding on**, and even then: what it is,
  why it pays, what unblocks it.
- If the operator wants depth they will ask. Depth on request, never by default.

Anti-pattern that triggered this rule: multi-turn stage reports on SEEK that restated the app
model, the method and the caveats every time, when the only actionable content was "hirer signup
or partner application - which?".

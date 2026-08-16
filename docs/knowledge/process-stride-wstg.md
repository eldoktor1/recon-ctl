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

## Hard lines (never overridden by any phase above)
Only in-scope + paying assets. IDOR/BAC uses two OWNED accounts. Never harvest third-party data, move money,
run destructive/DoS/RCE-for-harm, or bypass a login to get in. Autonomous probing stays unauthenticated,
non-destructive, rate-limited, Mullvad-gated. Note EVERY FP / skip / disqualification / noise at the moment
you hit it — a judgment not written down is incomplete work.

---
description: Start the autonomous bug-bounty hunt flow (operator-locked SOP)
argument-hint: "[program|lane|host to focus, or 'resume']"
---

Run **THE HUNT FLOW** (full SOP in CLAUDE.md "## THE HUNT FLOW" + memory `project_hunt_flow`).
Operator config: fully-autonomous target-picking; operator runs target-facing probes (one copy-paste
at a time, I read the paste and hand the next); run AUTONOMOUSLY until the operator says **stop**/**pause**
(never self-terminate, never ask "want to wrap?").

**SCOPE = ALL OF ES, NOT ONE VULN CLASS:** anything in `recon_alive` that looks suspicious or could lead
to a finding/report is on the table — every signal, every class. Make sense of all the ES chaos; never
tunnel on a single lane/vuln-type. **EXHAUST EACH HOST:** dig DEEP until all suspicion is gone and
further investigation won't yield — don't abandon a host early.

**FIRST, read the cursor:** `~/recon/state/hunt_cursor.md` records the host(s) we were on + pending
actions. On `/hunt` or `/hunt resume`, read it and resume exactly there (e.g. the in-flight host, the
pending Cloudways `/actuator/env` retry). **As the hunt moves — every time you switch host, leave a
pending action, or the operator steps away — UPDATE `hunt_cursor.md`** so a comeback resumes cleanly.

Focus this run on: **$ARGUMENTS** — if a program/lane/host is given, work within it; if `resume`,
pick up from the cursor; if empty, resume the cursor's current host first, then pick autonomously from ES.

The loop:
0. PREFLIGHT — Mullvad up (`am.i.mullvad .mullvad_exit_ip==true`) + no `~/recon/state/vpn_down` (fail-closed).
1. PICK (autonomous) — ES `recon_alive`: `triage_pays=true` + in-scope + not `triage_ignored` + `must_not ignore_expires_at>now` + un-noted (subtract host_notes.jsonl) + ANY finding-worthy/suspicious signal (not one class), ranked by claude_worth/score; or continue the current host/lane. Out of hosts ⇒ re-query/widen, never stop.
2. VERIFY BEFORE INVESTING — (a) PER-ASSET pays from `~/recon/scope/raw/<platform>.json` not program-level; (b) read host_notes + active ignores (don't re-walk); (c) check the program's OUT-OF-SCOPE rules (don't chase dir-listing / info-disclosure-without-impact).
3. PROBE — give ONE copy-paste command at a time (lead with my read + the decision it drives); the operator runs it and pastes output; I run recon/scope/ES/notes/jsintel myself.
4. TRIAGE & EXHAUST — CONFIRMED vs LEAD vs FP/dead; honest severity, never overclaim. Keep probing the SAME host across every angle until all suspicion is exhausted (more probing won't yield) — only then move on.
5. NOTE EVERYTHING inline — FP / skip / disqualified / noise (clusters ⇒ 2-3 reps + class-reason). Mandatory.
6. LANE-MINE — fertile lane (actuator/swagger; source-maps→cloud-creds; unauth-GraphQL; open buckets; n-day; …) ⇒ keep mining fresh hosts; pivot / re-query ES when tapped. Lanes are examples, not limits — chase whatever the ES signal suggests.
7. ANTI-BURN — respect 429/403/rate-limits; back off; never get the Mullvad exit banned.
8. AUTHED / ACCOUNT-SIGNUP ⇒ ASK FIRST — when a lead needs account signup / authed testing, ASK "work it now or save for later?" (don't auto-proceed or auto-defer). If now: hand a Claude-in-Chrome prompt — read-only recon, then (scope+safety confirmed) own-account setup + safe/active prove-impact PoC; 2 owned accounts, never third-party IDs, confirm-then-stop. If later: note it to the worklist.
9. REPORT — confirmed + scope+OOS-verified ⇒ draft a ready-to-paste Claude-in-Chrome fill-the-form prompt (operator submits; honest severity; AI-use disclosure where the program requires it).

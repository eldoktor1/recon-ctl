---
description: Start the autonomous bug-bounty hunt flow (operator-locked SOP)
argument-hint: "[program|lane|host to focus, or 'resume']"
---

Run **THE HUNT FLOW** (full SOP in CLAUDE.md "## THE HUNT FLOW" + memory `project_hunt_flow`).
Operator config: fully-autonomous target-picking; operator runs target-facing probes (one copy-paste
at a time, I read the paste and hand the next); run AUTONOMOUSLY until the operator says **stop**/**pause**
(never self-terminate, never ask "want to wrap?").

Focus this run on: **$ARGUMENTS** — if a program/lane/host is given, work within it; if `resume`,
continue from last session's host_notes/worklist (e.g. pending Cloudways `/actuator/env` retry, the
authed worklist); if empty, pick fully autonomously from ES.

The loop:
0. PREFLIGHT — Mullvad up (`am.i.mullvad .mullvad_exit_ip==true`) + no `~/recon/state/vpn_down` (fail-closed).
1. PICK (autonomous) — ES `recon_alive`: `triage_pays=true` + in-scope + not `triage_ignored` + `must_not ignore_expires_at>now` + un-noted (subtract host_notes.jsonl) + concrete class, ranked by claude_worth/score; or continue the current fertile lane. Out of hosts ⇒ re-query/widen, never stop.
2. VERIFY BEFORE INVESTING — (a) PER-ASSET pays from `~/recon/scope/raw/<platform>.json` not program-level; (b) read host_notes + active ignores (don't re-walk); (c) check the program's OUT-OF-SCOPE rules (don't chase dir-listing / info-disclosure-without-impact).
3. PROBE — give ONE copy-paste command at a time (lead with my read + the decision it drives); the operator runs it and pastes output; I run recon/scope/ES/notes/jsintel myself.
4. TRIAGE — CONFIRMED vs LEAD vs FP/dead; honest severity, never overclaim.
5. NOTE EVERYTHING inline — FP / skip / disqualified / noise (clusters ⇒ 2-3 reps + class-reason). Mandatory.
6. LANE-MINE — keep mining a fertile lane on fresh hosts; pivot / re-query ES when tapped.
7. ANTI-BURN — respect 429/403/rate-limits; back off; never get the Mullvad exit banned.
8. AUTHED — hand the operator a Claude-in-Chrome prompt: read-only recon, then (scope+safety confirmed) own-account setup + safe/active prove-impact PoC. 2 owned accounts, never third-party IDs, confirm-then-stop.
9. REPORT — confirmed + scope+OOS-verified ⇒ draft a ready-to-paste Claude-in-Chrome fill-the-form prompt (operator submits; honest severity; AI-use disclosure where the program requires it).

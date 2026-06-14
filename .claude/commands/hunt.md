---
description: Start the autonomous bug-bounty hunt flow (operator-locked SOP)
argument-hint: "[program|lane|host to focus, or 'resume']"
---

Run **THE HUNT FLOW** (full SOP in CLAUDE.md "## THE HUNT FLOW" + memory `project_hunt_flow`).
Operator config: fully-autonomous target-picking; operator runs target-facing probes (one copy-paste
at a time, I read the paste and hand the next); run AUTONOMOUSLY until the operator says **stop**/**pause**
(never self-terminate, never ask "want to wrap?").

**SCOPE = ALL OF ES — every IN-SCOPE + PAYING host — NOT ONE VULN CLASS:** within the in-scope + paying
surface (always gated on `triage_in_scope` + per-asset pays; never the raw index), anything in
`recon_alive` that looks suspicious or could lead to a finding/report is on the table — every signal,
every class. Make sense of all the ES chaos; never tunnel on a single lane/vuln-type. **EXHAUST EACH HOST:** dig DEEP until all suspicion is gone and
further investigation won't yield — don't abandon a host early.

**FIRST, read the cursor:** `~/recon/state/hunt_cursor.md` records the host(s) we were on + pending
actions. On `/hunt` or `/hunt resume`, read it and resume exactly there (e.g. the in-flight host, the
pending Cloudways `/actuator/env` retry). **As the hunt moves — every time you switch host, leave a
pending action, or the operator steps away — UPDATE `hunt_cursor.md`** so a comeback resumes cleanly.

Focus this run on: **$ARGUMENTS** — if a program/lane/host is given, work within it; if `resume`,
pick up from the cursor; if empty, resume the cursor's current host first, then pick autonomously from ES.
**MOOD HUNTING — a mood is a LENS, not a limit:** if the focus is a vuln-class / tech / lane / signal
keyword (xss, sqli, ssrf, lfi, redirect, api, wordpress, php, drupal, jira, graphql, jenkins, **cve/kev/
nday**, takeover, **interesting** (broad/unclassified high-signal), … or **ANY keyword** —
coldfusion/elasticsearch/citrix all work via broad match), run
`recon-mood <kw>` — it returns a ranked, scope+pays+not-benched worklist for that mood
(→ `~/recon/briefings/mood_<kw>_<date>.md`); `recon-mood --list` shows the curated set. The mood only
focuses WHERE you start — it does NOT cap the rigor. Within the mood run the **FULL /hunt flow at full
depth**: ENUMERATE (subfinder/permutation/CT/jsintel), SCAN, CRAWL (katana/gau/params), pull as much from
ES as needed, use **ANY tool available**, and EXHAUST each host across every angle + adjacent class —
same uniqueness/freshness/confirm/impact-gate discipline as a normal hunt.

The loop:
0. PREFLIGHT — Mullvad up (`am.i.mullvad .mullvad_exit_ip==true`) + no `~/recon/state/vpn_down` (fail-closed).
1. PICK (autonomous) — TWO sources, used TOGETHER:
   (a) **Pre-ranked BRIEFINGS in `~/recon/briefings/`** (already scope/pays/dedup-filtered — start here, highest signal-per-minute): `2IC_tonight_<date>.md` (2IC curated worklist), `idor_candidates_<date>.md` (BAC/IDOR money lane), `xss_candidates_<date>.md` + `sqli_candidates_<date>.md` (the rs0n lane — TOP UNIQUE LANES section first, skip PRODUCT-CLASS), `tonight_<date>.md`. If today's files are stale/missing, regenerate cheaply (ES-only): `recon-params candidates --class both` and read the 2IC list. These are PRIMARY picks, not an afterthought.
   (b) **Raw ES `recon_alive`**: `triage_pays=true` + in-scope + not `triage_ignored` + `must_not ignore_expires_at>now` + un-noted (subtract host_notes.jsonl) + ANY finding-worthy/suspicious signal (not one class), ranked by claude_worth/score.
   Or continue the current host/lane. Out of picks ⇒ re-query/widen/regenerate, never stop.
2. VERIFY BEFORE INVESTING — (a) PER-ASSET pays from `~/recon/scope/raw/<platform>.json` not program-level; (b) read host_notes + active ignores (don't re-walk); (c) check the program's OUT-OF-SCOPE rules (don't chase dir-listing / info-disclosure-without-impact).
3. PROBE — give ONE copy-paste command at a time (lead with my read + the decision it drives); the operator runs it and pastes output; I run recon/scope/ES/notes/jsintel/candidates myself. For an XSS/SQLi lead hand the CONFIRM command: `recon-params confirm xss <host>` (dalfox — break-out must EXECUTE) or `recon-params confirm sqli <host>` (SAFE `'` vs `''` differential). I read the result.
4. TRIAGE & EXHAUST — CONFIRMED vs LEAD vs FP/dead; honest severity, never overclaim. Keep probing the SAME host across every angle until all suspicion is exhausted (more probing won't yield) — only then move on.
5. NOTE EVERYTHING inline — FP / skip / disqualified / noise (clusters ⇒ 2-3 reps + class-reason). Mandatory.
6. LANE-MINE — fertile lane (actuator/swagger; source-maps→cloud-creds; unauth-GraphQL; open buckets; n-day; **XSS/SQLi reflected-param**; …) ⇒ keep mining fresh hosts; pivot / re-query ES when tapped. Lanes are examples, not limits — chase whatever the signal suggests.
   **XSS/SQLi — SMART, not blind (the whole point of the rs0n lane):** work the ranked `xss/sqli_candidates` worklist, **TOP UNIQUE LANES first** (rare per-app params on deep routes), SKIP the PRODUCT-CLASS section (`?q=`/`_next/image?url=` = dup-magnets everyone fuzzed). Prefer ⚡ true_fresh (be first). CONFIRM is the gate, not reflection: dalfox must show the payload EXECUTE (reflection ≠ XSS — encoded/framework-safe → note `reflected-not-exploitable` LEAD and move on); SQLi needs the `'`vs`''` differential to fire (never sqlmap/--dump/harvest). IMPACT-GATE before reporting: a DEMONSTRATED executing XSS / injectable SQLi only — theoretical/no-impact (CORS reflect, missing headers, self-XSS, error-only-no-data) get N/A, so don't spend the evening on them (see `feedback_theoretical_classes_get_declined`). Exhaust the host's other param surfaces + classes before pivoting.
7. ANTI-BURN — respect 429/403/rate-limits; back off; never get the Mullvad exit banned.
8. AUTHED / ACCOUNT-SIGNUP ⇒ ASK FIRST — when a lead needs account signup / authed testing, ASK "work it now or save for later?" (don't auto-proceed or auto-defer). If now: hand a Claude-in-Chrome prompt — read-only recon, then (scope+safety confirmed) own-account setup + safe/active prove-impact PoC; 2 owned accounts, never third-party IDs, confirm-then-stop. If later: note it to the worklist.
9. REPORT — confirmed + scope+OOS-verified ⇒ draft a ready-to-paste Claude-in-Chrome fill-the-form prompt (operator submits; honest severity; AI-use disclosure where the program requires it).

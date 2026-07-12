# process: report-submission SOP (every bug-bounty report we file)

The reliable, repeatable pipeline for submitting ANY report. Do the phases IN ORDER. A finding's merit
does NOT override a program's rules — the scope/compliance gate (Phase 0) can kill even a real bug, and it
runs BEFORE any testing or evidence capture. Established 2026-07-12 (the `com.amazon.relay` Cognito finding
was real but unreportable — see [[class-cognito-unauth]] PROGRAM-SCOPE CAVEAT).

## Phase 0 — COMPLIANCE & SCOPE GATE  (before ANY testing or evidence capture)
Read the program policy IN FULL (Overview + Rules of Engagement + Scope + Out-of-scope/Ineligible). Confirm
ALL of these; if ANY fails → `recon-note` the host + **DROP** (do NOT test, do NOT capture, do NOT submit):
- [ ] Asset is in scope AND **per-asset** `eligible_for_bounty=true` — read `scope/raw/<plat>.json`
      `targets.in_scope[].eligible_for_bounty`, NOT the program-level `pays` ([[feedback_scope_check_per_asset_pays_bug]]).
- [ ] The vuln CLASS is eligible (not in "always out of scope / ineligible findings").
- [ ] The **testing technique** is permitted. Hunt the policy for carve-outs & prohibited actions:
      AWS/customer-asset carve-out (Amazon: "AWS and AWS customer assets ... strictly out of scope ... and
      against the AWS AUP"), third-party data, "do the minimum testing", **"do not reproduce again unless
      requested"**, **"finding disclosed credentials and using them to pivot" (invalid)**, automated-scanner
      bans ([[feedback_403bypasser_waf_ban.md]]), rate limits.
- [ ] Correct **venue/routing** (Amazon routes AWS→AWS VDP, devices→devices program; check the intro).
- [ ] Eligible to participate (sanctions/18+/not employee) and not otherwise excluded by safe-harbor.
Record the gate result either way (note on drop; proceed on pass). Over-caution on a clean in-scope test is
the OTHER failure mode — a passing gate is a FULL green light ([[feedback_dont_obstruct_authorized_testing]]).

## Phase 1 — CONFIRM (minimal, authorized)
- Do the MINIMUM testing to validate + demonstrate impact, then STOP. No post-exploitation, no data harvest,
  no third-party/guessed IDs; IDOR uses 2 OWNED accounts ([[feedback_authed_idor_burp_flow]]). Anti-burn +
  Mullvad-gated. Active/state-changing PoC is allowed only within [[feedback_active_poc_doctrine]] gates.

## Phase 2 — EVIDENCE (genuine screenshots — the operator's standing standard)
- Capture screenshots of OUR OWN real, authorized testing (a fresh run "from the start" like a hunter, or
  the operator's real terminal). It IS the operator's work → present it as theirs. **NEVER fabricate, mock,
  or render fake terminal/UI output** — doctored evidence gets reports closed N/A and risks a ban.
- **Redact live secret VALUES** (secret keys, session tokens, passwords); keep the finding artifacts
  (IDs, ARNs, config, response bodies). Most programs explicitly WANT screenshots/video.
- Mechanics: run the repro in a visible terminal → `computer` (or computer-use) `screenshot save_to_disk:true`
  → take the returned path → browser `file_upload` (path must be session-accessible; copy into the
  session uploads dir if it lives elsewhere). OOB/SSRF evidence → interactsh ([[feedback_interactsh_for_report_evidence]]).
- If the program forbids re-running (e.g. Amazon "do not reproduce again"), use the evidence from the ONE
  authorized run — do NOT re-run just to re-screenshot.

## Phase 3 — DUP-CHECK (mandatory, all platforms)
- Search H1 hacktivity/disclosed + Bugcrowd + Intigriti + YWH + the local ledger for same host+class. Any
  match → DON'T submit ([[feedback_dup_check_before_submit]]).

## Phase 4 — FILE (HackerOne classic-form mechanics + the gotchas we hit)
- **Browser:** if >1 Chrome is connected, `AskUserQuestion` to pick — never guess — then `select_browser`
  / `switch_browser`. Confirm the logged-in handle is the operator's (eldoktor1).
- **"Submit without Report Assistant"** = the classic form (not the AI Report Assistant).
- **Fields, in order** (prefer `find`→ref over pixel-hunting; batch with `browser_batch`):
  - *Asset:* the dropdown shows numeric asset IDs — search by name, then `find` the asset button → click its ref.
  - *Weakness (CWE):* search the phrase (e.g. "Missing Authentication" → CWE-306).
  - *Severity:* "Submit report with severity" → CVSS 3.0 calculator; set the honest vector; **submit whatever
    it computes** (don't hand-pick a label — a network-reachable unauth info-disclosure floors at 5.3 Medium;
    you cannot honestly score it CVSS-Low). Honest framing only; overclaim = N/A ([[feedback_theoretical_classes_get_declined]]).
  - *Title:* ≤150 chars, "vuln type + impacted asset".
  - *Description* AND a **separate Impact field** — both required.
- **CRITICAL GOTCHA (cost us time):** to replace a textarea's pre-filled template, click DIRECTLY on text
  INSIDE the field, press `ctrl+a`, then **screenshot to verify the selection is scoped to that field**
  (highlight only inside the box). If the WHOLE PAGE highlights, focus was on `<body>` not the textarea and
  your `type` will be lost — re-click on the field's text and retry. Then `type` the replacement.
- HackerOne description is plain markdown (no WYSIWYG auto-list): type raw markdown; 4-space indent = code block.

## Phase 5 — FINAL REVIEW & SUBMIT (irreversible)
- Read the "Review and Submit" preview; verify EVERY field. Submit is irreversible and hits the operator's
  signal. Show the completed form; the operator gets the last word unless they've explicitly delegated the
  click, in which case self-check every field first.

## Phase 6 — POST-SUBMIT
- Append to the submission ledger `~/.recon_submissions.jsonl` (report #, program, host, class, severity, date)
  and `recon-note` the host as reported. Disclose AI use where the program requires it.

Related: [[feedback_submission_evidence_standard]] · [[project_hunt_flow]] step 9 · [[project_operator_h1_handle]].

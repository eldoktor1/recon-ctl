# recon-pipeline v3 — detection → validation → report

The v3 layer turns detection into **confirmed, reported, non-duplicate** findings
and adds the safety scaffolding to run unattended for months. It does **not**
replace the scanners — they stay as tools. It adds the layers around them.

**Storage split (complementary, not a migration):**
- **ES** (`recon_alive`) = *what assets exist* — search/analytics. Unchanged.
- **SQLite** (`~/recon/v3/findings.db`, WAL) = *where each finding is in its lifecycle*.

## Components

| File | Phase | Role |
|---|---|---|
| `scripts/triage.sh` (clamp), `scripts/recon_evidence_gate.sh` | A | Evidence gate. Detection-only P0 → **P0-CANDIDATE (held at P1)** → non-intrusive class probe (nuclei/dalfox/bypass) → promote to P0 **only on a real fire**. N=5 / 3h / 5d → lead-exhausted. |
| `db/schema.sql`, `state.py` | B | Finding state machine. Guarded atomic transitions, WAL crash-safety (`resume_stale_verifying`), `false_positive_signatures` (quieter over time), `failure_patterns`, `run_counters`, `audit_log`. |
| `formatters.py`, `reporter.py` | C | Internal Finding → H1/Bugcrowd/Intigriti reports. Dup pre-check (own history + platform hook), evidence-freshness re-probe (since-patched bugs bounce back). **Never auto-submits.** |
| `orchestrator.py` | D | Drives the state machine. Scope-gated autonomy + hard-coded guardrails. |
| `observability.py` | E | Auditable morning-after daily digest from SQLite. |

## Autonomy boundary (Phase D, hard-coded)
**Scope is the only gate — if a host is in scope, it's in play.** Autonomous, read-only,
non-intrusive active testing on every in-scope asset → confirmation net → Claude verify →
reporter. No financial/program tiering. The hard line is the *type* of action, not the
program: never sends authenticated or state-changing requests unsupervised, and the
fund-moving/state-changing endpoint denylist is hard-coded and host-agnostic.

## Guardrails (Phase D, hard-coded, always)
Max 4 concurrent agents · per-program daily request ceiling (750) · ban/CAPTCHA/3×403 → **immediate halt + alert, no auto-resume** · recon-scope gate before any request · fund-moving/state-changing endpoint denylist (never tested) · 6-category exponential backoff (30s→1h) · daily LLM spend ceiling ($20) → halt · `vpn_down` pauses all · submission always human-gated.

## Running (inside the kali VM — never over WSL interop)
```
python3 v3/state.py init                 # create the DB (idempotent; auto-migrates older DBs)
python3 v3/orchestrator.py once          # one orchestration pass
python3 v3/orchestrator.py loop          # continuous (halts persist until human clears ~/recon/state/v3_halt)
python3 v3/reporter.py                   # build review-queue reports from confirmed findings
python3 v3/observability.py              # write today's audit digest
```
The evidence gate (Phase A) runs as a daemon loop (`recon_daemon.sh` registers `evidence-gate`).

## Status
All phases are unit/self-test validated (compile + logic). Scope is the only gate (no
program tiering). Before re-enabling after a cold stop: (1) dry-run the evidence gate
against a small candidate batch, (2) `state.py init` + one `orchestrator.py once`.

## Cohesive flow (v3.2, 2026-06-07)
Two Claude layers bracket a precise, per-class confirmation net. The retired blanket-scan
lanes (`nuclei-v21/bounty-scan/deep-scan/dast/exposure/digest`) stay on-demand only —
the evidence gate + confirmers own confirmation now.

```
1. DETECTION (cast the net): discovery · validate · scope · true-fresh · cve-kev/nvd ·
   vuln-feed · js-scanner · active-checks · params(4-wide) · portscan · bypass ·
   takeover · cloudrecon
        -> triage (deterministic score; detection-only P0 clamped to P0-CANDIDATE/P1)

2. CLAUDE ANALYSIS  (ai-analyze, Haiku — bulk/cheap): reads in-scope+paying assets,
   decides worth / interest / vuln-class with RAG-lite KB context, flags gate
   candidates. Conscious surface selection — aims the net, never blanket-scans.

3. CONFIRM  (SAFE primitives: unauthenticated, non-destructive)
     - evidence-gate (nuclei): version · unauth-surface · content-leak · graphql ·
       swagger/openapi ;  SSRF/XXE via interactsh OOB callback
     - xss-confirm:   headless-Chromium marker EXECUTION
     - param-confirm: SSTI ({{a*b}}->product) · open-redirect (->canary) · SQLi (error-diff)
   pattern-match = LEAD ; a primitive firing = CONFIRMED -> SQLite.
   IDOR / LFI / RCE = operator-LEAD only (hard line).

4. CLAUDE VERIFY  (ai-review, Sonnet; opus-escalate on ambiguity): adversarial FP filter
   on every confirmed finding -> ai_verdict (mirrored to ES + knowledge_base).
     real -> reporter + #review  ·  needs-human -> #review  ·  fp -> dismiss + FP-signature

5. REPORTER  (ai_verdict=real only; dup + freshness gates; NEVER auto-submits) -> review queue
   v3-digest -> daily auditable .md + compact #digest
```
**Discord v3 (verdict-driven, smart-not-noisy):** `#review` (Claude real/needs-human —
APPROVE/DISMISS/INVESTIGATE) · `#takeovers` (first-blood) · `#ops` (halts/vpn/bans) ·
`#digest` (daily). Per-finding spam channels retired — that data lives in ES + `recon-ai`.

## Claude as the "second man" (operator model)
Claude shows up in two distinct, non-overlapping roles — both on the **Max plan, no
API key, no API spend** (headless `claude -p` is billed to the Max subscription):

1. **In-loop VALIDATION agent** (`scripts/recon_ai_review.sh`, daemon `ai-review` loop):
   the article's accuracy layer. Detection and the evidence gate are fully
   deterministic; Claude is invoked *only* on gate-CONFIRMED findings (a handful/day,
   trivial quota) to adversarially disprove each one. Its verdict (`real`/`fp`/
   `needs-human`) is written to SQLite and gates the reporter. The retired Ollama
   pre-scorer is gone — the deterministic gate is the cheap pre-filter now.
2. **Terminal OPERATOR** (you, at the keyboard / Claude in the terminal): the second
   set of hands that triages, decides, and prepares submissions against the tight
   signal the daemon produces while you're at work. The one-stop brief:
```
python3 v3/observability.py        # what ran, what's confirmed, what needs you (review queue, halts)
python3 v3/reporter.py             # (re)build review-queue reports from confirmed findings
sqlite3 ~/recon/v3/findings.db "SELECT host,program,confidence,review_tier FROM findings WHERE state='reported' ORDER BY confidence DESC;"
```
Submission stays human-gated; Claude prepares, you approve + send.

## Applying the consolidation
Loop changes take effect on a **daemon restart** (`recon-start` / `recon_ctl restart`).
Until then the old loops keep running. VPN (Mullvad) must be up.

## Out of scope (decided)
Auto-submission (never) · novel-vuln fuzzing (known patterns only) · expanding the target corpus (fix the gate first).

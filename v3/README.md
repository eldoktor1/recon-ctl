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
| `tier_list.tsv`, `tier.py` | Gate 0 | Financial-tier classification (load-bearing). Default-unknown → **FINANCIAL**. A program is GENERAL only via explicit human review. |
| `scripts/triage.sh` (clamp), `scripts/recon_evidence_gate.sh` | A | Evidence gate. Detection-only P0 → **P0-CANDIDATE (held at P1)** → non-intrusive class probe (nuclei/dalfox/bypass) → promote to P0 **only on a real fire**. N=5 / 3h / 5d → lead-exhausted. |
| `db/schema.sql`, `state.py` | B | Finding state machine. Guarded atomic transitions, WAL crash-safety (`resume_stale_verifying`), `false_positive_signatures` (quieter over time), `failure_patterns`, `run_counters`, `audit_log`. |
| `formatters.py`, `reporter.py` | C | Internal Finding → H1/Bugcrowd/Intigriti reports. Dup pre-check (own history + platform hook), evidence-freshness re-probe (since-patched bugs bounce back). **Never auto-submits.** |
| `orchestrator.py` | D | Drives the state machine. Autonomy boundary by tier + hard-coded guardrails. |
| `observability.py` | E | Auditable morning-after daily digest from SQLite. |

## Autonomy boundary (Phase D, hard-coded)
- **GENERAL** (human-reviewed in `tier_list.tsv`): autonomous read-only active testing → reporter.
- **FINANCIAL/REGULATED** (default): detection + **PoC-staging only** → `staged_pocs.jsonl`, **human trigger required**. Never sends authed/state-changing requests unsupervised.

## Guardrails (Phase D, hard-coded, all tiers)
Max 4 concurrent agents · per-program daily request ceiling (750) · ban/CAPTCHA/3×403 → **immediate halt + alert, no auto-resume** · recon-scope gate before any request · fund-moving/state-changing endpoint denylist (never tested *or* staged) · 6-category exponential backoff (30s→1h) · daily LLM spend ceiling ($20) → halt · `vpn_down` pauses all · submission always human-gated.

## Running (inside the kali VM — never over WSL interop)
```
python3 v3/state.py init                 # create the DB
python3 v3/tier.py audit                 # review tier classifications (do this before Phase D goes live)
python3 v3/orchestrator.py once          # one orchestration pass
python3 v3/orchestrator.py loop          # continuous (halts persist until human clears ~/recon/state/v3_halt)
python3 v3/reporter.py                   # build review-queue reports from confirmed findings
python3 v3/observability.py              # write today's audit digest
```
The evidence gate (Phase A) runs as a daemon loop (`recon_daemon.sh` registers `evidence-gate`).

## Status
All phases are unit/self-test validated (compile + logic). **Live integration testing is pending** — the daemon was stopped during the build and target-facing probes were not run. Before re-enabling: (1) human-review `tier_list.tsv` and set GENERAL where appropriate (until then nothing is autonomous-active-eligible — fail-safe), (2) dry-run the evidence gate against a small candidate batch, (3) `state.py init` + one `orchestrator.py once`.

## Consolidated cohesive flow (post-v3, 2026-06-07)
The daemon was cut from 28 → 22 loops. The redundant active-confirmation lanes that
only dumped to Discord side-channels were retired (the evidence gate owns
confirmation now): `nuclei-v21`, `bounty-scan`, `deep-scan`, `dast`, `exposure`,
`digest`. Their scripts remain for on-demand `recon_ctl` use.

```
DETECTION (feeders)                 CONFIRM            REVIEW
discovery/validate/scope/true-fresh ─┐
cve-kev/cve-nvd/vuln-feed            ─┤
js-scanner/active-checks/params     ─┼─► triage (P0-CANDIDATE, held P1)
portscan/bypass/takeover/cloudrecon ─┘        │
                                              ▼
                                   evidence-gate (confidence-scored, non-intrusive)
                                     <0.70 LEAD · 0.70-0.84 batch/P1 · >=0.85 P0
                                              │ confirmed -> ES + SQLite + #confirmed
                                              ▼
                                   reporter (SQLite -> review queue, dup+freshness, NEVER submits)
                                              ▼
                                   v3-digest (daily auditable brief)
```
**Discord, redesigned:** `#confirmed` (gate P0 only) · `#ops` (halts/vpn) · `#digest`
(daily). Per-lane raw dumps retired. Review happens off Discord, in the queue/digest.

## Claude as the "second man" (operator model)
The pipeline is fully deterministic (Ollama for enrichment only — no Claude/LLM in
the loop, no API spend). Claude runs in the **terminal** (Max plan) as the operator's
second set of hands: while you're at work the daemon produces a tight signal, and
Claude is invoked to triage/decide/submit against it. The one-stop brief:
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

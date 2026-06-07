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

## Out of scope (decided)
Auto-submission (never) · novel-vuln fuzzing (known patterns only) · expanding the target corpus (fix the gate first).

# Pipeline Claude rewire — REPURPOSE plan (2026-06-08)

Decision (from the 3-subsystem audit): **repurpose, don't scrap.** The disappointment isn't "Claude
rejects everything" — it's (a) Claude is wired tools-less as a per-item classifier in 3 of 4 loops,
and (b) the verifier only ever sees the 3 most FP-heavy lanes. The durable bookkeeping is correct and
the verify *reasoning* is good; both just need re-aiming. Apply these in priority order. You apply them
(the safety layer blocks me from editing the running daemon); each is independent.

## KEEP AS-IS (durable, correct — no change)
- `engine/state.py` (state machine, KB memory, FP-signature learning, crash-safety, WAL handling)
- `engine/reporter.py` (hard-gate on `ai_verdict='real'`, never-auto-submit), `formatters.py`,
  `observability.py`, `orchestrator.py`
- The 4 deterministic confirmers: `tools/safe_probe_worker.py`, `xss_confirm_worker.py`,
  `param_confirm_worker.py`, `screenshot_worker.py` — these become the agent's "hands."

## ROOT CAUSE (why findings.db is 27 rows, all fp, 0 real)
`recon_ai_review.sh` (VERIFY) only ever received takeover(23)/verified-secret(3)/portscan(1) — all
structurally-FP lanes that mint `confirmed` via their OWN direct paths (takeover_hunter, secret verify,
portscan), NOT the evidence gate. The evidence gate's *money* lanes (`unauth-surface, content-leak,
graphql, swagger, ssrf, xxe, xss, auth-bypass` — see `recon_evidence_gate.sh:196 probe_for_class`) rely
on nuclei-template / OOB fires that rarely trigger, so almost nothing real reaches verify. Net: the
verifier is a well-built FP-killer pointed only at FPs.

---

## PRIORITY 1 — stop the FP lanes from being the ONLY thing verified
The takeover/secret/portscan lanes have their own 99%-FP gates and don't need the expensive AI consensus
panel re-deciding them. Options (pick one):
- **A (recommended):** route only money-lane confirmations (graphql/unauth-surface/exposure/swagger/
  xss/ssti/sqli/idor) into `ai-pending`; let takeover/secret/portscan report through their existing
  deterministic gates without the AI panel. In `engine/state.py record_confirmed` (or wherever
  `ai-pending` is populated) add a class filter.
- **B:** keep routing them but DOWN-RANK so the panel budget is spent on money lanes first.
This alone won't create `real`s — Priority 2 does — but it stops wasting ~5 opus calls/finding on
pre-decided FPs.

## PRIORITY 2 — let the NEW 2IC agent be the money-lane brain (the real fix)
The scheduled `2ic-nightly-recon` agent already does tool-using investigation on the money lanes
(graphql introspection, exposure fetch+diff, BAC/IDOR reasoning) — exactly what the gate's nuclei
probes can't. Wire its confirmed findings INTO the same state machine so dedup/reporter/observability
are reused:
- Have the agent call `python3 engine/state.py record-confirmed <host> <url> <prog> <class> "" <score>
  <conf> <evidence-json>` for anything it confirms real, then `state.py ai-verdict ... real ...`.
- This makes the agent the producer of `real` rows the reporter has never seen — closing the loop.
- Net effect: retire/thin the tools-less `recon_ai_idor.sh` (the agent subsumes it) and keep
  `recon_ai_review.sh` only as the deterministic-confirmer (xss/param) verifier.

## PRIORITY 3 — cheap high-value fixes (exact diffs)

### 3a. Scope consistency — xss/param confirmers use STALE ES triage (the jedi.ripe.net bug)
`recon_safe_probe.sh` was patched to use the authoritative `recon_scope_check.sh`; the two autonomous
confirmers still gate on stale ES fields. Make them match.

`scripts/recon_xss_confirm.sh:39-42` and `scripts/recon_param_confirm.sh:37-40`, replace the
`in_scope_now()` body:
```bash
# BEFORE (stale ES triage):
in_scope_now() {
  [[ "$(es "$ES_URL/$INDEX_NAME/_source/$1" | jq -r \
     '((.triage_in_scope//false)==true) and ((.triage_pays//false)==true) and ((.triage_out_of_scope//false)!=true)')" == "true" ]]
}
# AFTER (authoritative scope DB):
in_scope_now() {
  local sc; sc="$(bash "$(dirname "${BASH_SOURCE[0]}")/recon_scope_check.sh" "$1" 2>/dev/null)"
  [[ "$(printf '%s' "$sc" | jq -r '((.in_scope//false)==true) and ((.pays//false)==true) and ((.out_of_scope//false)!=true)')" == "true" ]]
}
```

### 3b. IDOR loop — opus + `--tools ""` + no memory = max cost, min leverage
`scripts/recon_ai_idor.sh:32`. If you keep this loop at all (Priority 2 may retire it): either drop the
model, or justify opus by giving it tools + memory.
```bash
# cheap: CLAUDE_MODEL="${CLAUDE_IDOR_MODEL:-sonnet}"
# better: keep opus but at line 98 add Read access to the host's JS bundle and inject kb-lookup context
#         (mirror how recon_ai_review.sh passes --tools Read --add-dir + KB), so it stops blind-guessing
#         the same product-class endpoints.
```

### 3c. ANALYZE — make it multimodal (it already has the screenshot in ES)
`scripts/recon_ai_analyze.sh` runs `--tools ""` over ES *strings*. ES already stores `screenshot_path`/
thumb. Pass the screenshot (like review.sh does) so "is this an exposed panel vs a marketing page" is
judged by vision — kills a class of FPs before they reach the gate. Keep haiku for bulk; only attach the
image for assets with `triage_score>=` the sonnet threshold.

### 3d. Consensus panel — 3 opus lens calls → 1
`scripts/recon_ai_review.sh:279-314` fires `judge`(sonnet) + 3 sequential `lens_vote`(opus) +
`author_report`(opus) per real-candidate. The 3 lenses re-read the same finding+screenshot. Replace with
ONE opus call whose schema returns `votes:[{lens,verdict,reason}x3]`. Same diversity (prompt-framed),
~3× fewer opus calls.

### 3e. Verdict topology — a real shouldn't round down
`recon_ai_review.sh:307` requires unanimous 3/3 for `real` but majority to refute, and every fall-through
(`:207-208` unparseable/probe-exhausted) drains to needs-human/fp. Allow `real` when ≥2/3 lenses confirm
AND none hard-refute; keep the takeover post-clamp (`:391`) only for the takeover class. This lets a
genuinely-exploitable partial survive one flaky lens.

### 3f. MONITOR — deterministic, or give it memory
`scripts/recon_ai_monitor.sh` sends a telemetry blob to sonnet hourly to restate threshold checks it's
already given. Either replace the verdict with deterministic thresholds (burn-risk = f(blocks,cooldowns,
pause)), or feed it the prior `ai_monitor_latest.json` so it can do the one LLM-worthy thing: trend
detection across runs. Cheapest: deterministic verdict + a daily (not hourly) Claude trend digest.

### 3g. safe_probe hardening (defense vs prompt-injection)
`tools/safe_probe_worker.py`: DNS-pin the resolved IP between the SSRF check and the fetch (close the
TOCTOU rebinding gap); note that TLS verification is disabled (`CERT_NONE`) so target content feeding the
multimodal LLM is MITM-spoofable — acceptable for recon, but document it.

### 3h. Shared liveness check
Every AI loop burns a `claude -p "Reply with exactly: OK"` ping per cycle. Cache it behind a TTL'd marker
(`~/recon/state/claude_alive` with mtime check) shared across loops.

---

## Net target architecture
- **Agent (2ic-nightly-recon)** = money-lane brain: investigates with tools, confirms, writes `real`
  rows into the state machine, posts the digest.
- **Evidence gate + deterministic confirmers** = cheap autonomous "hands" producing candidates/confirms.
- **recon_ai_review.sh** = verifier for the deterministic-confirmer output only (xss/param/exposure),
  consolidated + topology-fixed.
- **state.py / reporter.py** = unchanged durable bookkeeping, now actually fed `real`s.
- **Retire/thin:** tools-less `recon_ai_idor` (agent subsumes), `recon_ai_monitor` LLM verdict
  (deterministic), the per-cycle liveness pings.

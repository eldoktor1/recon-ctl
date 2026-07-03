# class-ai-hunter-design — research-backed design for the Claude hunter layer

How Claude should be wired into this pipeline to ACTUALLY find unique, paid bugs — grounded in the
leading published work (Google Project Zero Big Sleep/Naptime, XBOW, 2025–26 agentic-pentest papers).
Recorded 2026-06-22 per the RESEARCH MANDATE.

## The problem we're fixing
The pipeline was a DETECTION engine (scanners emit signals → Claude *scores/filters* them → report).
Filtering commodity scanner output yields commodity findings → duplicates → $0. Claude was used to be
*not wrong*, not to *find the non-obvious*. The bugs that pay (IDOR/BAC chains, business-logic, auth/
tenancy gaps, API misuse) have NO scanner signal — they exist only if something *understands the app*
and *reasons* about breaking it. So Claude must be the HUNTER, not the filter.

## What the research converges on (design principles)
1. **Seeded / variant-analysis ≫ open-ended.** Big Sleep: giving a concrete starting point (a known
   bug, a diff, a pattern) "removes a lot of ambiguity." Open-ended "find bugs here" is too hard for
   current models. ⇒ Never point Claude at a host blind; seed each hunt with a specific bug-class +
   pattern (from the candidate rankers, the KB, or a disclosed bug in the same tech).
2. **Human-researcher workflow WITH tools + a multi-round feedback loop.** Big Sleep (code browser/
   debugger/sandbox) and XBOW (curl-crawl first, then multi-round tool execution with "environmental
   feedback correction") give the agent HANDS and let it hypothesize→act→read→refine. Models reason
   far better *after seeing a real response*. ⇒ the hunter needs the safe-probe loop as a tool, not a
   one-shot read-only judgement.
3. **LLM explores; deterministic code confirms → zero FP.** XBOW's core: "exploit execution validation
   over theoretical detection… LLMs do creative attack exploration, deterministic code does strict
   verification" (zero FP). Big Sleep grounds on actual crashes. General LLMs run 10–50% FP without
   this. ⇒ the VERDICT is a probe firing / a primitive observed — not Claude's opinion.
4. **Model alloying — route by task.** XBOW routes between frontier models per task. ⇒ cheap model
   filters to the few; frontier (Opus) does the creative hunt; deterministic code verifies.
5. **Multi-trajectory sampling.** Big Sleep explores multiple hypotheses across INDEPENDENT
   trajectories, not one pass. ⇒ run N independent hunter attempts per high-value target.
6. **The two FP failure modes are CONTEXT and FOCUS** (Vulnhalla "guided questioning" → 96% FP cut):
   give the model exactly what it needs (context) and a precise place to look (focus). ⇒ MODEL builds
   context; HYPOTHESIZE makes it focused.

## Our hunter loop (the implementation)
SEED → MODEL → HYPOTHESIZE → TEST → VERIFY → MINT → LEARN, per high-value in-scope+pays target:
- **SEED** — pick a target + bug-class from the candidate rankers (idor/xss/sqli/graphql) or KB pattern
  (variant analysis). Never open-ended.
- **MODEL** (Opus, big context, ZERO target traffic) — assemble jsintel endpoints + JS + sourcemaps +
  headers + scope into a structured app-model: API surface, auth/tenancy model, object types & ID
  schemes, roles, business flows.
- **HYPOTHESIZE** (Opus) — reason model + KB → specific, ranked, *focused*, testable hypotheses, each
  with a concrete test + expected-positive signature + dup-check. Not "host looks interesting."
- **TEST** (harness-mediated) — unauth-safe hypotheses run through `recon_safe_probe.sh` in a bounded
  loop (Claude requests, the TRUSTED HARNESS runs, Claude interprets → refines/chains). Authed/IDOR →
  emit a precise 2-owned-account operator plan; NEVER autonomous authed actions.
- **VERIFY** — execution-grounded (the probe result is ground truth) + the existing consensus panel as
  a second gate. Hard-gate `ai_verdict='real'`.
- **MINT** — `state.py record-confirmed` → reporter → #review; else LEAD → briefing.
- **LEARN** — append discovered exploitation/FP patterns to the KB (per-tech, per-program) so the next
  hunt starts smarter.

## Keep vs change (vs the pre-2026-06-22 design)
- KEEP: haiku bulk filter (picks the few targets), the consensus VERIFY panel, CONFIRMED-vs-LEAD,
  `recon_safe_probe.sh`, and every scope/pays/owned-account hard line.
- CHANGE: seed instead of open-ended; give the hunter the probe loop as hands (not verify-only);
  multi-trajectory; Opus deep on the curated few (invert the spend); verdict = execution, panel second.

## Throughput / multi-exit note
The hunt is reasoning-heavy and sends FEW, surgical requests — so one hunt rarely nears an IP rate
limit. The multiple Mullvad exits pay off for (a) running MANY parallel hunters/trajectories (one
program per IP, polite, no shared rate budget) and (b) the request-heavy CONFIRM phase (dalfox/sqlmap/
fuzz). Not a multiplier for a single hunt. (See scripts/recon_multitunnel.sh; MT_LANES scopes IPs to
confirm/unique lanes, never bulk.)

## Hard lines (unchanged — these make it LEGIT *and* VALID, not Anthropic-appeasement)
Authorized + in-scope + pays-confirmed only; 2 OWNED accounts for IDOR/BAC (guessing a stranger's id
proves nothing and isn't the bug); never pull third-party data; confirm-don't-exploit-past-PoC; authed
testing stays human-in-the-loop; Mullvad-only egress + anti-burn; carry the authorization context
(in-scope/pays/testing-to-report) on every action so legitimate work never *looks* like anything else.
A SCOPED autonomous hunter is more defensible than ad-hoc poking — every action gated + logged.

## Sources
- https://projectzero.google/2024/10/from-naptime-to-big-sleep.html (Big Sleep design principles)
- https://cisoseries.com/automating-offensive-security-with-xbow/ + https://www.zeitgeist.bot/company/xbow (XBOW: LLM-explores/code-confirms, model alloying, zero-FP via execution validation)
- https://arxiv.org/html/2508.20816v1 (Multi-Agent Pentesting AI for the Web: main-agent + sub-agent)
- https://www.bankinfosecurity.com/bug-hunting-llms-expert-tool-seeks-more-true-flaws-a-30696 (guided questioning → 96% FP reduction; context+focus)


---
<!-- applied-proposal: 2026-07-01_tooling_class-ai-hunter-design -->
### Applied research — tooling (2026-07-01)

## Nuclei AI/LLM panel sweep (2026-07-01)

New in nuclei-templates v10.4.3 (May 2026): 20+ AI/ML infrastructure panel detection templates.
These are high dup-resistance targets — companies deploy AI infra without security review and the crowd isn't scanning for them.

**Target panels now detectable:**
AgentGPT, AnythingLLM, AstrBot, ClearML, ChromaDB (+ unauthenticated API), Flowise, H2O Wave, KoboldAI, Langflow, llama.cpp, Marqo, OpenHands, SillyTavern, Stable Diffusion WebUI, Weights & Biases, Xinference, Chainlit, ComfyUI, Marimo

**Add to the pipeline:**
```bash
nuclei -update-templates  # ensure v10.4.3+
nuclei -tags panel -l <in-scope-hosts.txt> -o ai_panels_$(date +%Y%m%d).json

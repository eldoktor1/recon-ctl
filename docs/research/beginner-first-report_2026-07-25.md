# Research digest — systems, hunters & the beginner's first paid report — 2026-07-25

Deep-research synthesis (multi-source, adversarially verified). Goal: make this pipeline the
best at reliably delivering a **beginner their first valid PAID report, repeatably**. Sources cited
inline. Items marked ⚠️ are directional (single-source or estimate).

## The one thesis
**The binding constraint is surviving TRIAGE (duplicate / informative / N-A), not finding bugs.**
Even XBOW — #1 on HackerOne's US reputation-gain board, Apr–Jun 2025 — turned ~43–45% of its ~1,060
submissions into **no-reward** outcomes (208 duplicate, 209 informative, 36 N-A) vs only 132
confirmed/resolved. So the funnel must be optimised for *reports-that-pay*, not reports-submitted.
Our dedup-first / FP-kill / unique-surface / human-in-loop doctrine is directly validated.
- Sources: xbow.com/blog/top-1-how-xbow-did-it · uprootsecurity.com/blog/xbow-hackerone-ai-penetration-testing · blog.raw.pm/en/about-the-hype-around-xbow/

## What actually produced paid results (vs noise)
- **Clone/staging dedup is a real, copyable mechanism.** XBOW collapsed cloned/staging hosts with
  **content SimHash + headless-screenshot imagehash** before spending effort. This is exactly the
  "smart targeting + clone/staging dedup" our CLAUDE.md already names as *the next layer*. → **ROADMAP:
  add asset-level clone dedup (SimHash of crawled body + perceptual hash of the screenshot the VERIFY
  agent already captures) to the ES asset store; group near-duplicates, hunt one representative.**
- **Per-class execution validators, not pattern-matches.** XBOW confirms XSS by a headless browser
  proving the payload *executed*. Matches our confirm-primitive doctrine (dalfox must EXECUTE;
  reflection ≠ XSS; SSTI math-only; OOB canary for SSRF/XXE). Keep every class gated on a firing primitive.
- **Autonomy is bounded + human review is mandatory** (HackerOne policy). AI surfaces + pre-validates;
  a human confirms + submits. Our gates (operator runs target probes, authed/IDOR human-confirmed,
  reporter hard-gates on Claude `real` + operator submit) are correct and policy-compliant — a feature.
- **Commodity "run every tool" pipelines manufacture duplicates.** reconFTW already bundles
  jsluice/sourcemapper/S3Scanner/arjun — so the *tools* aren't the edge; **Claude's reasoning + dedup on
  top is.** Every lane must still answer "how is this not what everyone runs?"

## The beginner's highest-EV path (lane priorities)
1. **Access-control / IDOR / BOLA is #1.** ~36% of real IDOR reports rate High/Critical, ~81% Medium+,
   and it's a class **AI can surface but not auto-confirm** → perfect for our "rank + hand to human" model.
   - **State-changing BOLA (Action-Level, ~41.7%) is co-dominant with read IDOR (~36.9%)** → the IDOR
     ranker must score **object-MUTATING endpoints** (POST/PUT/DELETE, `update*/delete*/transfer*`), not
     only read-only ID substitution. → **APPLY in `recon_idor_candidates.py`.**
   - **Sequential integer IDs are the single most common (~22.6%)** = highest-EV signal (our ranker already
     scores numeric > uuid ✓); but **UUID/opaque still ~39.2%** of cases — don't discard opaque IDs. ⚠️(arxiv)
2. **Beginner-standard set:** reflected/stored XSS, CSRF-with-impact, SSRF, subdomain takeover, exposed
   panels / info-disclosure **with demonstrated impact**. Skip theoretical (CORS-reflect, missing headers,
   self-XSS, version-only) — they get N-A (matches [[feedback_theoretical_classes_get_declined]]).
3. **Hunt on unique surface the crowd misses:** Haddix-style reverse-DNS/DMARC/CSP pivots, JS &
   source-map mining, GraphQL **Global-ID decode→increment→re-encode**, fresh CT surface — not the
   saturated `?q=` / `_next/image` dup-magnets.

## Why first reports get closed dup/N-A — and how we avoid it
- **Duplicate** (biggest killer): run on fresh/under-hunted surface; enforce cross-platform dup-check
  before submit ([[feedback_dup_check_before_submit]]); suppress product-class / fan-out endpoints.
- **Informative / N-A:** demand a firing PoC and real impact (PoC-OR-GTFO); never overclaim severity.
- **Out-of-scope:** per-asset scope+pays gate (now the UI default-hides OOS/non-paying).

## Marketability (what "best-in-class" means, from the platforms themselves)
Bugcrowd & YesWeHack both ship **AI-assisted enrichment + duplicate detection + scope/severity
scoring with humans keeping PoC reproduction + final decisions.** That hybrid, dedup-first,
human-in-loop model is exactly what a marketable tool should mirror — which is our architecture.

## Actions taken / queued from this digest
- ✅ Measure success by **accepted PAID** outcomes (`record_outcome` / ai-accuracy), not raw confirms —
  already the [[feedback_stay_fresh_adaptable]] adaptation loop.
- ✅ Beginner worklist default-hides OOS/non-paying; leads streamlined with inline confirm.
- ⏳ **APPLY:** rank state-changing/mutating BOLA in `recon_idor_candidates.py` (next code pass).
- ⏳ **ROADMAP:** clone/staging dedup (SimHash body + perceptual-hash screenshot) in the ES asset layer.

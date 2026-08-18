# Bounty-class priorities — where the money + low-dup edge is (2025 data)

Research-grounded focus guide. Pulled 2026-06-15 from HackerOne 9th HPSR / Top-10, Bugcrowd
2025 CISO report, and practitioner writeups. Validates + refines the CLAUDE.md IDOR/BAC money pillar.

## The headline numbers (2025)
- HackerOne paid **$81M** in bounties (+13% YoY). Top-100 all-time earners = $31.8M.
- **AI vulns exploded**: valid AI findings **+210% YoY**, **prompt injection +540%**, programs with AI in
  scope **+270%** (1,121 programs). Fastest-growing lane, lowest competition relative to growth.
- Bugcrowd: **broken access control critical +36%**, **API vulns +10%**, hardware +88%, network 2x.
- Real case: one researcher earned **$500k in <90 days** for broken access control across ~1,500 APIs.

## Rising vs declining (the dup map)
- **RISING (focus here):** Broken Access Control, IDOR/BOLA variations, misconfigurations, business
  logic, AI/prompt-injection. The theme: *"vulnerabilities that require understanding how systems work,
  not how payloads break them"* — automation-blind, low-dup, human-reasoning-driven.
- **DECLINING / SATURATED (dup traps):** XSS (most-REPORTED but -10% since 2023, commodity), SQLi-by-scanner.
  Surface-level enumeration loses to deeper understanding. Matches our MOTTO.

## HackerOne Top-10 by impact/reward (order)
1 XSS · 2 Improper Authentication · 3 Information Disclosure · 4 Privilege Escalation · 5 SQLi ·
6 Code Injection · 7 SSRF · 8 IDOR · 9 Improper Access Control · 10 CSRF.
KEY: **SSRF, IDOR, Privilege Escalation = "harder to come by but the MOST VALUABLE by bounties awarded."**
XSS tops VOLUME, not value. <half the list overlaps OWASP Top-10.

## What ACTUALLY paid in 2025 (practitioner, ProwlSec)
- **GraphQL SQLi** $2.5k–$10k+ (unsanitized filter args, boolean-blind confirm) — direct DB access = critical.
- **IDOR** $1k–$5k (REST/GraphQL seq/numeric IDs, e.g. `/api/v1/projects/{id}/documents`; test READ *and* WRITE).
- **SSRF** $3k+ (URL-param fetch / profile-pic-by-URL → OOB canary → AWS IMDS/IAM creds, internal svc).
- **Business logic** ~$4.2k (client-side price trusted by server, `total_amount` tamper) — "impossible for scanners."
- Edge = manual testing, data-flow understanding, **chaining**, not scanning.

## Operator focus ranking (part-time, low-dup, our pipeline)
1. **IDOR / BOLA / Broken Access Control over REST + GraphQL APIs** — #1 EV. Rising, most-valuable,
   automation-can't-confirm, needs 2-account reasoning. Fed by our jsintel→endpoints→`recon_idor_candidates`
   pillar. (Tonight's BDES + Vistar both landed here = gated APIs whose value is authed IDOR.)
2. **Business logic / workflow abuse** — high value, scanner-blind, low-dup. Pairs with #1; reason over the
   app's intended flow (pricing, quotas, multi-tenant boundaries, state machines).
3. **GraphQL-specific** — introspection → schema → SQLi/IDOR/auth-bypass. High payout, our GraphQL lane.
4. **SSRF** — still top-value tier, cloud-migration-driven, OOB-canary confirmable (our `recon_safe_probe`).
5. **AI / prompt-injection** — fastest-growing lane (+540%), 1,121 programs now in scope = the new
   "fresh blood." Lowest competition relative to growth. WORTH ADDING as a research + mood lane.

## Avoid (declining + saturated = dups / N/A)
Commodity reflected-XSS on saturated programs, scanner-SQLi, missing headers, theoretical CORS, version
disclosure, self-XSS, info-disclosure-without-impact. (Already flagged by our doctrine + brief_filter.)

## Sources
- HackerOne Top-10 Most Impactful & Rewarded: hackerone.com/blog/hackerone-top-10-most-impactful-and-rewarded-vulnerability-types
- HackerOne 2025 HPSR researcher signals: hackerone.com/blog/2025-hpsr-researcher-signals
- HackerOne $23.5M/10-vulns press: hackerone.com/press-release/organizations-paid-hackers-235-million-these-10-vulnerabilities-one-year-4
- BleepingComputer $81M 2025: bleepingcomputer.com/news/security/hackerone-paid-81-million-in-bug-bounties-over-the-past-year/
- Bugcrowd 2025 CISO report (AC +36%, API +10%): bugcrowd.com/press-release/bugcrowd-reports-an-88-increase-in-hardware-vulnerabilities-...
- ProwlSec "Top Bugs That Actually Paid Bounties in 2025": medium.com/@ProwlSec/top-bugs-that-actually-paid-bounties-in-2025-871eb0874400

---

# PROGRAM-SELECTION GATE: scanner policy + per-asset tiering (measured 2026-08-16)

**The lesson that produced this section:** a program was picked on ES `triage_payout_tier` + reachability,
then Phase 0 revealed (a) an outright automated-scanner BAN and (b) that the whole recommended estate was
the program's LOWEST bounty tier. Both facts live ONLY in the policy prose, not in ES.

**Check these TWO things during selection, not at Phase 0:**
1. **Scanner policy** — ban / volume-limited / allowed-with-conditions. Decides whether the pipeline can
   even be pointed at the program.
2. **Per-asset tiering** — `targets[].impact` (Intigriti) or the reward chart. `triage_payout_tier` is a
   DERIVED field and was WRONG (said "high" for an Intigriti **Tier 3** estate paying €400/High).

## Measured results

| program | platform | automated scanners | top payout | notes |
|---|---|---|---|---|
| **SBB** (sbbglobal) | Intigriti | **BANNED** — "do not use automatic scanners"; 5 req/s; scanner-found subs rejected | €6,666 T1 mobile · **T3 `*.sbb.ch` High = €400** | test accounts ALLOWED via @intigriti.me |
| **Acronis** | HackerOne | **ALLOWED** — must put @wearehackerone email in User-Agent; **5 req/s per host** all tools combined | — | asks to avoid prod where possible |
| **Playtika** | HackerOne | volume-limited — "no tools/scanners that automatically generate significant volumes of traffic" | T1 Crit $5,000 · T3 High $500 · avg High $1,500 | `eligible_for_bounty` is MIXED per asset |
| **GitHub** | HackerOne | **ALLOWED** — "so long as they do not produce excessive traffic" (one nmap = fine) | **Crit avg $100,000 · High $12,050 · Med $5,545** | heavily saturated; only ~47 reachable hosts in ES |
| **Opera** | Bugcrowd | no prohibition found | **P1 $10,000** · P2 $3,000–5,000 · P3 $500–3,000 | PRIMARY targets = auth/accounts/flow/autoupdate.opera.com |

## Trap recorded
Opera was nearly rejected on the wrong evidence: the `*.opera.software` Keycloak is edge-403 by origin ACL
and the `*.beta.opera-mini.net` Pike hosts are Opera Mini PROXYING THIRD-PARTY SITES. Neither is the
program's paying surface — the **Primary Targets** are four `*.opera.com` hosts. Always read the
program's own Primary/Target list before judging a program by whatever ES happens to have crawled.

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

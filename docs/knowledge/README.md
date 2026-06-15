# Knowledge Base — recorded research & threat intel

**Why:** documenting everything we learn is what turns this from a script-kiddie toolchain into a
sharper, compounding security-research system (operator doctrine, 2026-06-15). Every research session,
technique, tech-stack attack surface, host-class insight, bypass, and dead-end-turned-fresh-path gets
recorded HERE so future hunts START informed instead of re-deriving from scratch.

**Doctrine link:** see `feedback_research_before_acting` (memory) + CLAUDE.md "RESEARCH MANDATE".
Research the FULL set of sources — general internet (writeups/disclosed reports/CVE analysis/PoCs/forums/
talks/hunter blogs), the **target web app's own docs**, the **technology/framework docs**, and **any**
useful resource. Then RECORD what's reusable here.

## How to use
- **Before/while hunting a tech or class:** read the matching `tech-<name>.md` / `class-<name>.md` for the
  playbook (endpoints to hit, CVEs, sinks, bypasses, what each result means).
- **After researching anything reusable:** add/append a file here (or a section). Cite sources. Keep it
  actionable (concrete paths/payloads/checks, not theory). Date entries.
- **Host-specific findings** stay in `host_notes` (per-host worked-knowledge); this KB is for GENERAL,
  reusable knowledge (tech/class/technique), not one-off host state.

## Index
- `tech-nextjs.md` — Next.js / React app attack surface (DOM XSS, /_next/image SSRF+SVG-XSS, __NEXT_DATA__
  leak, CVE-2025-29927 middleware bypass, Server-Actions SSRF, route/build enumeration).
- _add more as we learn: tech-liferay.md, tech-aem.md, class-domxss.md, …_

## Naming
- `tech-<stack>.md` (nextjs, liferay, aem, wordpress, coldfusion, …)
- `class-<vuln>.md` (domxss, idor, ssti, …)
- `technique-<name>.md` (cross-cutting methods)

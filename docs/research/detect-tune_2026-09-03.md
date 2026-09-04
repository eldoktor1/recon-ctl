# Research digest — detect-tune — 2026-09-03

# Research digest — detect-tune — 2026-09-03

## 1. Next.js middleware-authorization-bypass CVE cluster (May + July 2026) — new n-day confirm primitive, HIGH PRIORITY

Two coordinated Vercel security releases this year patched a run of middleware/proxy bypass CVEs in Next.js App Router / Pages Router. This is exactly our n-day pattern (CHAIN-TO-IMPACT: version-gate THEN a safe single-request primitive that proves actual bypass, not just version match) and Next.js sits under our existing `tech-nextjs.md` — not yet covered in any prior digest.

**May 2026 batch** (patched 15.5.16 / 16.2.5, disclosed ~May 6 2026):
- **CVE-2026-44574** — dynamic route parameter smuggling: `nxtP*` query params get injected past middleware's view of `pathname`. PoC: `GET /public-path?nxtPslug=admin-secret&__nextDefaultLocale=&__nextLocale=` with `x-matched-path`/`x-now-route-matches` headers set — middleware evaluates the public path, the smuggled param resolves the protected dynamic segment at render time. Affected: Next 15.4.0–15.5.15, 16.0.0–16.2.4.
- **CVE-2026-44575** — `.rsc`/segment-prefetch requests resolve to a protected page via a route the middleware matcher never covers (incomplete matcher generation). Same affected range; **note a GitHub advisory follow-up (GHSA-26hh-7cqf-hhc6 / CVE-2026-45109) says the first fix was INCOMPLETE** — re-verify against current patch level, don't trust "patched" from version alone.
- **CVE-2026-44573** — Pages Router + i18n: middleware never runs for the **locale-less** `/_next/data/<buildId>/<page>.json` route, so protected SSR JSON is retrievable unauthenticated by hitting the data route without a locale prefix.

**July 2026 batch** (patched 15.5.21 / 16.2.11, disclosed ~July 20-21 2026):
- **CVE-2026-64642** — Turbopack builds + exactly one `config.i18n.locales` entry: prefixing any protected path with that single locale skips the middleware matcher entirely. Affects 16.0.0–16.2.10.
- **CVE-2026-64645** — SSRF/open-redirect in `rewrites()`/`redirects()` when the destination hostname is built from request-controlled input: a trailing-dot DNS trick (`GET /attacker.com` against a `/:tenant → https://:tenant.api.example.com` rule expands to `attacker.com..api.example.com`, DNS root-qualifies to `attacker.com.`) makes the origin proxy to an attacker host. **This is a genuine unauth SSRF primitive — feeds our interactsh OOB-canary confirm lane directly** (point the smuggled hostname at our own canary domain, callback = definitive, same pattern as our existing SSRF confirm).
- **CVE-2026-64643** — Server Action/`use cache` internal endpoint IDs globally disclosed unauthenticated — recon-grade (attack-surface mapping for jsintel-style endpoint mining), not itself an impact.

**Actionable for us:**
- Add a Next.js version-fingerprint step to `recon_nday.sh` (build ID / `x-powered-by: Next.js` / `/_next/static/chunks/` asset headers already give version) gated to these ranges.
- Safe unauth confirm primitive (matches CHAIN-TO-IMPACT: don't mint on version alone): for a host flagged in-range, send ONE crafted request per PoC pattern above at a **known-protected path we can identify from crawled surface** (e.g. an `/admin`/`/dashboard`/`/account` route seen 30x-redirecting-to-login on direct GET) with the smuggled param/header/locale-prefix variant, and check whether protected content is returned instead of the login redirect — single GET/no auth, non-destructive, exactly our safe-probe primitive.
- For CVE-2026-64645 specifically: only applicable if the target actually uses templated `rewrites()`/`redirects()` with a request-derived destination (visible via reflected redirect Location headers containing part of the request path/query) — narrow candidate set before probing, then confirm via interactsh callback like our existing SSRF lane.
- A full PoC collection exists for the May batch: [github.com/dwisiswant0/next-16.2.4-pocs](https://github.com/dwisiswant0/next-16.2.4-pocs) — useful reference payloads.

Sources: [nextjs.org/blog/july-2026-security-release](https://nextjs.org/blog/july-2026-security-release), [securityboulevard.com CVE-2026-44575](https://securityboulevard.com/2026/05/cve-2026-44575-middleware-authorization-bypass-in-next-js-app-router/), [zeropath.com CVE-2026-44574](https://zeropath.com/blog/cve-2026-44574-nextjs-middleware-authorization-bypass), [zeropath.com CVE-2026-44573](https://zeropath.com/blog/cve-2026-44573-nextjs-middleware-bypass), [advisories.gitlab.com CVE-2026-44573](https://advisories.gitlab.com/npm/next/CVE-2026-44573/), [securelayer7.net CVE-2026-64642](https://securelayer7.net/lab/cve-2026-64642-nextjs-turbopack-i18n-middleware-bypass), [github.com/vercel/next.js/security/advisories/GHSA-26hh-7cqf-hhc6](https://github.com/vercel/next.js/security/advisories/GHSA-26hh-7cqf-hhc6) (incomplete-fix follow-up), [herodevs.com CVE-2026-64645](https://www.herodevs.com/blog-posts/cve-2026-64645-next-js-ssrf-vulnerability-in-rewrites-and-redirects-explained-and-how-to-fix-it), [github.com/dwisiswant0/next-16.2.4-pocs](https://github.com/dwisiswant0/next-16.2.4-pocs)

---

Nothing else new this run cleared the bar for actionable + not-already-covered (cache-deception and Cloudflare-bot-management searches returned only pre-existing/general material, no new technique beyond what's already in `class-cache-deception.md`).

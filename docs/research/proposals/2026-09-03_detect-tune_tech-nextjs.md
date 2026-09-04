# PROPOSAL (proposal) for docs/knowledge/tech-nextjs.md — detect-tune 2026-09-03
_Review and apply manually; not auto-merged into the KB._

## Middleware-authorization-bypass CVE cluster (2026, two batches) — n-day confirm primitive

Two Vercel security releases patched a run of middleware/proxy authorization-bypass CVEs. Version-gate first, THEN run the safe single-request confirm primitive below — never mint on version match alone (CHAIN-TO-IMPACT law).

**May 2026 batch** — patched 15.5.16 / 16.2.5 (vulnerable: 15.4.0–15.5.15, 16.0.0–16.2.4):
- `CVE-2026-44574` (param smuggling): `GET /public-path?nxtPslug=<protected-slug>&__nextDefaultLocale=&__nextLocale=` with `x-matched-path`/`x-now-route-matches` headers — middleware sees the public pathname, the smuggled `nxtP*` param resolves a protected dynamic segment at render.
- `CVE-2026-44575` (.rsc/segment-prefetch): request the page as a `.rsc`/prefetch segment URL — matcher doesn't cover it, protected content renders unauth. **First fix was incomplete** (follow-up `GHSA-26hh-7cqf-hhc6`/CVE-2026-45109) — verify against current patch, not just "≥16.2.5".
- `CVE-2026-44573` (Pages Router + i18n): `GET /_next/data/<buildId>/<protected-page>.json` with NO locale prefix — middleware doesn't run for the locale-less data route, protected SSR JSON returns unauth. Get `<buildId>` from any public page's `__NEXT_DATA__` blob or `_next/static/<buildId>/`.

**July 2026 batch** — patched 15.5.21 / 16.2.11:
- `CVE-2026-64642` (Turbopack + single-locale i18n, 16.0.0–16.2.10): prefix any protected path with the app's sole configured locale (e.g. `/en/admin` when only `en` is configured) — matcher generation skips it, middleware never runs.
- `CVE-2026-64645` (SSRF/open-redirect via `rewrites()`/`redirects()`): only applicable if the app has a templated external rewrite/redirect built from request-controlled input (Location header or fetched content reflects part of the request path/query into a hostname). Trailing-dot DNS trick: request a path whose captured segment is `attacker-canary.com` — root-qualified DNS resolution sends the proxy to our canary. Confirm via interactsh OOB callback (same primitive as our existing SSRF lane) — never point at anything but our own canary.
- `CVE-2026-64643` (info): Server Action/`use cache` endpoint IDs disclosed unauth — recon-grade only, feeds endpoint surface mapping, not an independent finding.

**Safe unauth confirm (single GET, non-destructive):** identify a candidate protected path from crawled surface (a route that 30x-redirects-to-login on a direct unauth GET), then re-request it with the relevant PoC variant (smuggled `nxtP*` param / `.rsc` suffix / locale-less `_next/data` path / single-locale prefix). Protected content returned instead of the login redirect = CONFIRMED bypass. Version-in-range with no observed bypass on the probed paths = LEAD only, note and move on (don't re-probe every path exhaustively — respect anti-burn).

Sources: nextjs.org/blog/july-2026-security-release, securityboulevard.com/2026/05/cve-2026-44575, zeropath.com/blog/cve-2026-44574-nextjs-middleware-authorization-bypass, zeropath.com/blog/cve-2026-44573-nextjs-middleware-bypass, securelayer7.net/lab/cve-2026-64642-nextjs-turbopack-i18n-middleware-bypass, herodevs.com/blog-posts/cve-2026-64645-next-js-ssrf-vulnerability-in-rewrites-and-redirects-explained-and-how-to-fix-it, github.com/dwisiswant0/next-16.2.4-pocs

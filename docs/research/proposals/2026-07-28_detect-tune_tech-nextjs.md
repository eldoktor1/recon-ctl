# PROPOSAL (proposal) for docs/knowledge/tech-nextjs.md — detect-tune 2026-07-28
_Review and apply manually; not auto-merged into the KB._

## 4a. CVE-2026-44575 / CVE-2026-45109 — middleware bypass via `.rsc` / segment-prefetch (2026, distinct from CVE-2025-29927)
Newer variant of the middleware-bypass class (§4's `x-middleware-subrequest` is the 2025 CVE-2025-29927;
this is separate and NOT fixed by upgrading past that patch). Self-hosted App Router only — Pages Router
and Vercel-managed deployments are unaffected.
- **CVE-2026-44575** — affects 15.2.0–15.5.15 and 16.0.0–16.2.4 (fixed 15.5.16 / 16.2.5). Middleware
  authorization checks the normal route path but not the `.rsc` transport variant or segment-prefetch path.
- **CVE-2026-45109** — Turbopack-compiled `middleware.ts` specifically; fixed 15.5.18 / 16.2.6 (trails the
  general fix — a host on 15.5.16/17 with Turbopack can still be exposed).
- **TEST (safe, unauth, GET-only):** find a route that normally 401s/403s/redirects unauthenticated
  (e.g. `/dashboard`). Request `GET /dashboard.rsc` and `GET /dashboard.segments/$c$children/__PAGE__.segment.rsc`.
  200 + RSC payload body (not the login redirect) = bypass CONFIRMED. No creds, no state change.
- Add both fixed-version ranges to the Next.js version-gate check alongside CVE-2025-29927.
Source: https://securityboulevard.com/2026/05/cve-2026-44575-middleware-authorization-bypass-in-next-js-app-router/

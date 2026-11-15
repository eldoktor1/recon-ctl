# PROPOSAL (proposal) for docs/knowledge/tech-nextjs.md — kb-enrich 2026-09-06
_Review and apply manually; not auto-merged into the KB._

## Middleware authorization bypass — CVE-2025-29927 (CVSS 9.1)

Still worth checking on every in-scope Next.js host — a 2-request unauth primitive.

**Affected:** Next.js < 12.3.5 / < 13.5.9 / < 14.2.25 / < 15.2.3.

**Mechanism:** Next.js trusts the client-supplied `x-middleware-subrequest` header (meant only to
stop internal middleware recursion) as proof a request already passed through middleware. Spoofing
it skips middleware entirely — including any auth/authz check implemented in `middleware.ts`
(the common pattern for gating `/admin`, `/dashboard`, protected API routes).

**Detection (unauth, no data harvest, safe-probe compatible):**
1. Fingerprint Next.js (`_next/static` in body / standard asset paths).
2. `GET` a protected route with no special header. Note status + look for
   `x-middleware-rewrite`/`x-middleware-next`/`x-middleware-redirect` in the response headers
   (confirms middleware is gating this route).
3. Re-send with the version-appropriate bypass header:
   - pre-12.2: `X-Middleware-Subrequest: pages/_middleware` (or `pages/<route>/_middleware`)
   - 12.2–13.1.x: `X-Middleware-Subrequest: middleware` (or `src/middleware`)
   - 13.2.0+: `X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware`
     (5x chain; `src/middleware:...:src/middleware` variant also works)
4. Status flips 401/403/redirect → 200 with the header, stays gated without it = CONFIRMED bypass.

This is a genuine finding-grade primitive (not just "version is old") because the behavior is
directly observed — pair the version fingerprint with the live before/after status diff before
minting; a version match alone stays a LEAD per our KEV-tech-class-without-verification rule.

Sources: [ProjectDiscovery](https://projectdiscovery.io/blog/nextjs-middleware-authorization-bypass),
[Datadog Security Labs](https://securitylabs.datadoghq.com/articles/nextjs-middleware-auth-bypass/),
[Offsec](https://www.offsec.com/blog/cve-2025-29927/)

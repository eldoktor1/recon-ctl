# PROPOSAL (proposal) for docs/knowledge/tech-nextjs.md — kb-enrich 2026-09-17
_Review and apply manually; not auto-merged into the KB._

## CVE-2025-29927 — middleware authorization bypass via `x-middleware-subrequest` (2025-03-21, unauth, safe single-header test)

Next.js used an internal header (`x-middleware-subrequest`) to stop middleware from recursing into itself.
The check only looked at whether the header's colon-split value contained the middleware's internal name —
an attacker can just send that value directly and Next.js skips ALL middleware (auth checks, redirects,
rewrites) for the request.

**Exact payload by version (unauth-safe, single GET, no state change):**
| Version range | Header value |
|---|---|
| pre-12.2 | `x-middleware-subrequest: pages/_middleware` (or nested, e.g. `pages/dashboard/_middleware`) |
| 12.2.x | `x-middleware-subrequest: middleware` (or `src/middleware`) |
| 13.2.0+ / 14.x / 15.x pre-fix | `x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware` (5x repeat; `src/middleware:...` if under `/src`) |

**Detection (matches our safe-probe primitive — GET-only, no auth):**
1. Confirm target is Next.js (`_next/static` in page source, or `x-powered-by: Next.js`/`x-nextjs-cache` headers).
2. Hit a known middleware-gated path WITHOUT the header → expect redirect/401/403 (or a `x-middleware-rewrite`/`x-middleware-redirect` response header, proving middleware ran).
3. Re-request the SAME path WITH the header above → **200 (or the protected content) = confirmed bypass.**
4. This is a clean CHAIN-TO-IMPACT primitive per our law: don't stop at "header accepted," fetch the now-unprotected resource and show what it contains.

Affected: all Next.js <12.3.5 (12.x), <13.5.9 (13.x), <14.2.25 (14.x), <15.2.3 (15.x). Mitigation for
unpatched hosts is proxy-level header stripping, so a fixed-looking response doesn't rule out a
misconfigured edge that still forwards the header — worth a retest even on "patched" version banners if reachable directly.
Sources: [ProjectDiscovery technical analysis](https://projectdiscovery.io/blog/nextjs-middleware-authorization-bypass), [GitHub PoC](https://github.com/aydinnyunus/CVE-2025-29927), [Fastly writeup](https://www.fastly.com/blog/cve-2025-29927-authorization-bypass-in-next-js)

## CVE-2026-75604 — unauthenticated RCE via Image Optimization (AVIF/libheif heap overflow + Windows path traversal), fixed 2026-Q3

Two issues shipped in the same advisory:
- **AVIF/libheif heap overflow** (upstream libheif ≤1.23.1, "duplicate Alpha planes from nested items"):
  attacker-controlled AVIF processed through Next.js's built-in Image Optimization API leads to unauth RCE.
  Affects Next.js **≥10.0.0** wherever the optimizer will fetch/process a remote or uploaded AVIF.
- **Windows path traversal** (Windows-hosted servers only, Pages Router + App Router both present, Cache
  Components NOT enabled): unauthenticated RCE via filesystem path handling, from Next.js **13.4** onward.

Fixed: **15.5.24** / **16.3.3**.

**Recon-safe fingerprinting only (do NOT feed a crafted AVIF — that crosses into exploitation, human-in-loop
per our RCE-primitive hard line):**
- Confirm the image optimizer is reachable + accepts remote URLs: `GET /_next/image?url=<in-scope-asset>&w=256&q=75` — a 200 with resized image = optimizer live.
- Version banner: check response headers (`x-powered-by`, `server`) and `/_next/static/<buildId>/_buildManifest.js` (buildId sometimes correlates to a release); a definitive version needs the `npx next --version`-equivalent, which is not remotely obtainable — treat as **KEV-tech-class-match** (version-unconfirmed) and clamp to LEAD per our documented-FP-pattern, never P0, until the running version is confirmed some other way (changelog-correlated build ID, disclosed stack, etc).
- Platform matters for the path-traversal variant — Windows-hosted Next.js is uncommon in our AWS/GCP/Cloudflare-heavy in-scope tech list but worth a `Server`/`X-Powered-By`/TTL-fingerprint check before ruling it out.

Bonus, same 2026 advisory wave: **CVE-2026-27980** (DoS via unbounded image-cache disk growth, versions 10.0.0–16.1.7) — low severity, note only if a program explicitly pays DoS.
Sources: [HOL: CVE-2026-75604 unauth RCE writeup](https://hol.org/blog/cve-2026-75604-nextjs-unauth-rce-image-optimization-windows), [Vercel May 2026 security release](https://vercel.com/changelog/next-js-may-2026-security-release), [SentinelOne CVE-2026-27980](https://www.sentinelone.com/vulnerability-database/cve-2026-27980/)

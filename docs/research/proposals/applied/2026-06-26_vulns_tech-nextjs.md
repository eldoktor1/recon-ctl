# PROPOSAL (proposal) for docs/knowledge/tech-nextjs.md — vulns 2026-06-26
_Review and apply manually; not auto-merged into the KB._

## 8. Re:CACHE — RSC reflection → zero-click stored XSS via cache poisoning (June 2026)

Targets Next.js App Router. When `Rsc: 1` header is sent, Next.js returns a React Server Component
payload. On routes where a URL parameter is reflected into the RSC output after the `__PAGE__` boundary
marker, a CDN caching the RSC response enables shared-cache poisoning → zero-click stored XSS.

**Safe pipeline detection:**
1. Fingerprint App Router: `x-nextjs-cache` response header OR `__PAGE__` in RSC body OR `__NEXT_DATA__` script tag
2. Send `Rsc: 1` + benign canary param on parameterized routes; check if canary appears verbatim past `__PAGE__` marker
3. Unique `?cb=<nonce>` cache-buster on every probe — never test under shared cache key
4. Second request without buster → `CF-Cache-Status: HIT` = RSC variant cached = poisoning prerequisite confirmed

**Related CVE:** CVE-2025-57822 (Next.js < 14.2.32 / < 15.4.7) — version-confirmed for the reflection variant.
Fingerprint version via `/_next/static/<buildId>/_buildManifest.js` or error-page version leak.

**Edge:** `Rsc: 1` + `__PAGE__` boundary is not in community nuclei templates. Crowd doesn't probe RSC internals.

Source: https://zhero-web-sec.github.io/research-and-things/re-cache-excessive-reflection-type-confusion-and-0-click-sxss-on-nextjs

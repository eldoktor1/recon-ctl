# Next.js / React app — attack surface playbook

Recorded 2026-06-15 (researched while hunting webviews.monzo.com, a Next.js app). Sources at bottom.
**Fingerprint:** `main-<hash>.js` bundles, `__NEXT_DATA__` script tag, `/_next/static/`, `_buildManifest.js`,
`x-powered-by: Next.js`, router internals (`asPath`, `addLocale`, `addBasePath`, "Invariant" errors).

## Why React/Next is XSS-RESISTANT (don't waste time on the framework bundle)
React auto-escapes `<`, `>`, `&` in JSX. Generic `innerHTML=`/`location.href=` hits in the framework
bundle are almost always framework-internal (router navigation, URLSearchParams builders) = FALSE POSITIVES.
DOM XSS in React/Next needs an UNSAFE pattern in APP code, not the framework. Hunt the page chunks, not main.

## 1. DOM XSS — the real signals (mine PAGE chunks, not framework)
- **`dangerouslySetInnerHTML` / `__html`** rendering user/URL-controlled content WITHOUT DOMPurify = the
  #1 React XSS. Hotspots: rich-text/CMS/blog/comments, and any page that renders SHARED/passed-in content
  (e.g. a `/share/[type]` webview rendering the shared item). Payload `<img src=x onerror=alert(1)>`.
- **`location.hash`** as source: the fragment is NEVER sent to the server → backend sanitizes nothing →
  prime for client-side sinks, esp. SPAs using `#` for routing/state. Also `location.search`, `window.name`,
  `document.referrer`, `postMessage`/`event.data` (webviews ← native bridge).
- **Where to look:** page chunks under `/_next/static/chunks/pages/...` (per-route code), NOT main-*.js.
  Get routes from `_buildManifest.js` or jsintel. Grep chunks for `dangerouslySetInnerHTML`, `__html`,
  `innerHTML`, `insertAdjacentHTML`, client template engines (Handlebars/Vue-runtime) w/o sanitization.
- Tooling: `recon-domxss <url>` flags sink+source; FILTER framework FPs (URLSearchParams.append,
  router `location.href=route`). Mine specific routes: `recon-domxss https://host/share/x`.

## 2. /_next/image — SSRF + SVG-XSS (HIGH value, often present)
`/_next/image?url=<URL>&w=256&q=75` is the image optimizer.
- **SSRF:** if `remotePatterns`/`domains` is wildcard/misconfigured, it fetches arbitrary `url` server-side.
  TEST: `url=https://example.com/` → returns a 200 image = it proxied external = SSRF (then a HUMAN
  carefully checks internal/metadata — DON'T auto-harvest metadata; benign external canary proves it).
  Allowed-domain configs return 400 "url not allowed".
- **SVG-XSS:** if `dangerouslyAllowSVG: true`, point `url` at an allowed-host SVG with script → served as
  image/svg+xml = stored/reflected XSS. Check the image response `content-type` + CSP.
- Bonus: chain open-redirect on an allowed subdomain to bypass remotePatterns.

## 3. __NEXT_DATA__ — secrets / internal-URL leak (easy info-disc)
`<script id="__NEXT_DATA__">{...}</script>` holds the SSR props from `getServerSideProps`/`getStaticProps`.
TEST: fetch a page, parse that JSON for API keys, tokens, internal URLs, build config. Common easy win.

## 4. CVE-2025-29927 — middleware AUTH BYPASS (critical when present)
Next.js middleware (used for auth/redirects) can be SKIPPED by sending header
`x-middleware-subrequest: middleware` (or `:middleware:middleware:...` / `src/middleware` depending on
version/structure). If a route is protected only by middleware, this bypasses it. TEST a protected route
with and without the header; 200 with the header = bypass. Patched in 14.2.25 / 15.2.3. LEAD until the
running version/behavior confirms — don't assume.

## 5. CVE-2024-34351 — Server Actions SSRF (patched 14.1.1)
Server Actions (POST with `Next-Action` header, functions marked `"use server"`). Manipulate the `Host`
header → server may fetch internal pages and render them back. Enumerate action hashes via
`NextjsServerActionAnalyzer` if `productionBrowserSourceMaps` on.

## 6. Cache poisoning / deception
SSR/SSG pages: check `Vary` + `Cache-Control`. Param pollution may cache another user's personalized
response. Test unkeyed params reflected into cached output.

## 7. Route / build enumeration (do FIRST to aim the above)
| Path | Reveals |
|---|---|
| `/_next/static/<buildId>/_buildManifest.js` | route→chunk map (all pages) |
| `/_next/static/chunks/pages/` | per-route app code (mine for DOM XSS) |
| `/_next/data/<buildId>/<route>.json` | SSR data per route (cache/SSRF angle) |
| `/_next/image?url=` | image optimizer (SSRF/SVG-XSS) |
| `/package.json`, lockfiles, `.npmrc` | dependency-confusion (if exposed) |
| `__NEXT_DATA__` (in page HTML) | SSR props / secrets |

## 8. STATIC EXPORT (next export / output:'export') — narrows the surface
If `__NEXT_DATA__.assetPrefix` points to a CDN/S3 bucket (e.g. `…s3…web-export…`) the app is a STATIC
export served as files. Implications: **NO `/_next/image` optimizer** (it 404s → no image SSRF/SVG-XSS),
**no Server Actions / getServerSideProps** (no SSR-side SSRF/cache-poison via Node). The surface shrinks to
DOM XSS + CSP + the hosting bucket. (Observed: webviews.monzo.com, static export on S3, 2026-06-15.)

## 9. CSP as the XSS gate — and the whitelist as the bypass gadget
A tight CSP (`script-src 'self' 'nonce-…'`, no `unsafe-inline`, `object-src 'none'`) BLOCKS most DOM XSS
execution — even `<img onerror>` won't fire. So when CSP is strong, the XSS path is a **CSP-BYPASS GADGET**:
look at what `script-src` whitelists. If it lists **an S3 bucket / CDN** (attacker-writable or world-writable
PUT) or **a host with a JSONP/script-reflection endpoint**, you can host/inject JS from an ALLOWED origin →
bypass. So: enumerate every `script-src`/`default-src` origin → test each for write (anon S3 PUT, read-only
listability first) or script-reflection. (Observed: webviews.monzo.com CSP whitelists `monzo-prod-…web-export`
+ `monzo-s101-…nonprod-web-export` S3 buckets + `internal-api.monzo.com` in script-src — the bypass candidates.)
- **SCOPE GATE on the bucket angle:** `AccessDenied` on bucket LIST ≠ no anon WRITE (list-denied + PUT-allowed
  is a classic misconfig). BUT before ANY write-test, verify the bucket is IN SCOPE — programs scoped to
  `*.domain.com` often do NOT include `*.amazonaws.com` S3 assets; writing to an OOS bucket is unauthorized
  (hard line). Monzo: S3 export buckets are `*.amazonaws.com`, scope is `*.monzo.com` only → bucket write-test
  OOS, angle closes. So: strong nonce-CSP + only-OOS/locked bypass-origins = DOM XSS effectively non-exploitable.

## Quick checklist
- [ ] Fingerprint Next.js + get buildId + routes (_buildManifest / jsintel)
- [ ] `/_next/image?url=https://example.com/` → SSRF? + content-type for SVG-XSS
- [ ] Parse `__NEXT_DATA__` for secrets/internal URLs
- [ ] CVE-2025-29927 `x-middleware-subrequest` on protected routes
- [ ] Mine page chunks for `dangerouslySetInnerHTML`+`location.hash`/`search` (DOM XSS)
- [ ] CSP header present/weak? (gates XSS impact)
- [ ] CSRF (Next.js has no default immunity) on state-changing POSTs

## Sources
- DeepStrike — Next.js Security Testing Guide: https://deepstrike.io/blog/nextjs-security-testing-bug-bounty-guide
- DOM XSS in SPAs guide: https://medium.com/@asifebrahim580/dom-based-xss-in-single-page-applications-spas-a-complete-guide-for-beginners-bug-bounty-56d4e496a0a0
- XSS in Next.js (dangerouslySetInnerHTML/App Router): https://vibeappscanner.com/vulnerability-in/xss-nextjs
- Grab deeplink→webview (HackerOne #401793): https://hackerone.com/reports/401793
- CVE-2025-29927 (Next.js middleware bypass), CVE-2024-34351 (Server Actions SSRF) — verify version before claiming.


---
<!-- applied-proposal: 2026-06-26_vulns_tech-nextjs -->
### Applied research — vulns (2026-06-26)

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

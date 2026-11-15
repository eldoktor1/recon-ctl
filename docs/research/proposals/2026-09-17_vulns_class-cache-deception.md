# PROPOSAL (proposal) for docs/knowledge/class-cache-deception.md — vulns 2026-09-17
_Review and apply manually; not auto-merged into the KB._

## CDN normalization matrix (2026-09, source: dev.to/roxdavirox — blog.mago.team)
- **Do NOT normalize paths before cache-rule evaluation (higher WCD risk):** Cloudflare, Fastly, Google Cloud (CDN). Both Cloudflare and GCP CDN are on our own top-in-scope-tech list — prioritize these fronting CDNs for the WCD lane.
- **DO normalize (lower risk, still test):** Azure, CloudFront.
- **Delimiter set to probe** (beyond a bare `/path.css` suffix): `;.css` (matrix-param confusion — e.g. Spring MVC ignores `;param`, CDN still caches by extension), `%23.css` (encoded-fragment confusion), and double-encoded traversal prefixes (`/share/%2F..%2Fapi/...`) where the CDN wildcard-caches the pre-decode path but the origin decodes post-cache.
- **Safe two-request test (no real-cache poisoning — use own cache-buster per our doctrine):**
  1. Authenticated GET to the sensitive endpoint + delimiter suffix; note `Cache-Control`/`Set-Cookie`.
  2. Unauthenticated GET to the *same exact URL* (own request, own cookie jar/cache-buster key) — `X-Cache: HIT` or `Age > 0` on a response that should be user-specific confirms deception.
- **Related bug class to watch for:** cache key that omits the Host header (CVE-2025-61598, Pingora <0.8.0, CVSS 8.4) — cross-origin response bleed through a shared cache. If any in-scope host fronts through Pingora, check version.
- Source: https://dev.to/roxdavirox/web-cache-deception-against-apis-cdns-cache-what-backends-serve-privately-339c

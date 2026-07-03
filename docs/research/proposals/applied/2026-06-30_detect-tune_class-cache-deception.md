# PROPOSAL (proposal) for docs/knowledge/class-cache-deception.md — detect-tune 2026-06-30
_Review and apply manually; not auto-merged into the KB._

## CDN Identification Oracle (add before §Probing)

Identify CDN before running WCD probes. Skip if CDN never caches dynamic routes for that response pattern.

| CDN | Identifying Header | Cache-Hit Value | Skip Signal |
|-----|-------------------|-----------------|-------------|
| Cloudflare | `CF-Cache-Status` | `HIT` | `DYNAMIC` on suffix path = skip |
| Akamai | `Server-Timing: cdn-cache; desc=HIT` | `desc=HIT` | `desc=MISS` consistently = likely not caching |
| Fastly | `X-Fastly-Cache` | `HIT` | absent = not Fastly |
| CloudFront | `X-Amz-Cf-Id` | `X-Cache: Hit from cloudfront` | `X-Cache: Miss` = not cached |
| Varnish | `X-Varnish` (two integers) | two integers | single integer = miss |

**FP suppression:** `CF-Cache-Status: DYNAMIC` or `Cache-Control: no-store` on the suffix-appended path = correctly NOT cached = secure FP, skip. Only the cacheability flip (dynamic base → cacheable suffix variant) is a real candidate.

**Cache-buster rule (safety primitive):** append `?cb=<uuid>` to every WCD probe so tests run under YOUR cache key, never poisoning the shared cache. Two requests with the same buster: if second returns cache HIT = confirmed cached under your key = WCD candidate.

## Varnish-specific (see also tech-varnish.md)

Varnish-fronted hosts expose a secondary bug class: unauthenticated PURGE. Add as `recon-wcd confirm` step for Varnish-identified hosts:
```bash
curl -X PURGE https://<host>/<path> -sv | grep "< HTTP"

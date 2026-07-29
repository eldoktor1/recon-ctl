# PROPOSAL (proposal) for docs/knowledge/class-cache-deception.md — kb-enrich 2026-07-28
_Review and apply manually; not auto-merged into the KB._

## Normalization-discrepancy WCD payload patterns (added 2026-07-28, PortSwigger 2026 labs)

Two precise discrepancy templates to add to `recon_wcd.sh`'s probe variants (always under our own
cache-buster param, never against the real cache key a victim would hit):

### A. Origin normalizes, cache doesn't (dot-segment traversal into a cacheable prefix)
Origin server decodes/resolves `..%2f`; cache server matches by raw path prefix without decoding.
Payload: `/<cacheable-static-prefix>/..%2f<sensitive-endpoint>?<cachebuster>`
Example: `/resources/..%2fmy-account?wcd123` → origin serves `/my-account` (sensitive), cache stores
it keyed under `/resources` (the static-asset rule) → subsequent unauth fetch of the exact URL returns
the cached sensitive page.

### B. Cache normalizes, origin doesn't (fragment-delimiter confusion)
Cache server decodes `%23%2f%2e%2e%2f` → `#/../` and resolves into a cacheable directory; origin
server treats `%23` (`#`) / `%3f` (`?`) as a hard stop and never sees the trailing path.
Payload: `/<sensitive-endpoint>%23%2f%2e%2e%2f<cacheable-prefix>?<cachebuster>`
Example: `/my-account%23%2f%2e%2e%2fresources?wcd123` → origin serves only `/my-account`; cache keys
it under `/resources`. The `%23` is load-bearing: browsers strip URL fragments client-side, so this
never reaches the origin as a real fragment — it's pure cache-key manipulation.

### Detection notes
- Test with a UNIQUE cachebuster per probe (existing doctrine — never touch the real shared cache key).
- Confirm via `X-Cache`/`Age`/`CF-Cache-Status` flip from MISS→HIT on the crafted path, AND that the
  body actually contains the sensitive endpoint's content (not a 404/redirect — a cached error page is
  not a WCD finding, that's CPDoS, different class).
- CPDoS (cache-poisoned-DoS, poisoning the cache with an ERROR page via a malformed header) is a
  separate, generally lower-value/availability-only class — not in our lane's scope (destructive/DoS-adjacent).

Sources: PortSwigger Web Security Academy, "Exploiting origin server normalization for web cache
deception" and "Exploiting cache server normalization for web cache deception" (2026 lab additions).

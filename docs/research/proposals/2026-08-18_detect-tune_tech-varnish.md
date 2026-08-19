# PROPOSAL (proposal) for docs/knowledge/tech-varnish.md — detect-tune 2026-08-18
_Review and apply manually; not auto-merged into the KB._

## CVE-2026-50052 — Varnish HTTP/2 request-smuggling/desync (added 2026-08-18)
Varnish Cache < 9.0.3/8.0.2/6.0.18, Vinyl Cache < 9.0.1. Deficiency in HTTP/2 frame→HTTP/1.1
translation lets a crafted HTTP/2 request be interpreted as ONE request by Varnish but TWO by
the backend — the smuggled second request attaches to the next user's connection (cache
poisoning / auth-bypass / response hijack across users).
**Detect:** only relevant if the host actually speaks HTTP/2 (`+http2` feature flag — off by
default in stock Varnish, so most fronted hosts are NOT exposed even if the Varnish version
matches). Confirm via ALPN `h2` before treating the version match as in-range; version-only =
LEAD per the KEV/n-day discipline. Fixed 2026-05-18.
Source: https://docs.varnish-software.com/security/VSV00019/, https://www.sentinelone.com/vulnerability-database/cve-2026-50052/

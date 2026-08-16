# PROPOSAL (proposal) for docs/knowledge/class-request-smuggling.md — vulns 2026-08-15
_Review and apply manually; not auto-merged into the KB._

## CVE-2026-50052 — Varnish Cache HTTP/2 request smuggling (added 2026-08-15)
Backend desync via HTTP/2 request parsing flaw → cache poisoning/auth bypass. Affected Varnish <9.0.3,
Vinyl Cache <9.0.1. Only reachable when `+http2` feature is explicitly enabled (default OFF) — narrows
exposure significantly vs the 2026-07-28 CVE-2026-34475 Varnish auth-bypass. Detect: `X-Varnish`/`Via:
varnish` header (tech-match only, no remote version disclosure) + confirm HTTP/2 ALPN support before
treating as in-range. LEAD only, no PoC/ITW as of 2026-08-15.
Source: https://www.sentinelone.com/vulnerability-database/cve-2026-50052/

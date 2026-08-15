# PROPOSAL (proposal) for docs/knowledge/class-request-smuggling.md — detect-tune 2026-08-15
_Review and apply manually; not auto-merged into the KB._

## CVE-2026-50052 — Varnish/Vinyl Cache HTTP/2 request smuggling (added 2026-08-15)
Vinyl Cache <9.0.1, Varnish Cache <9.0.3 / 8.0.2 / 6.0.18. Deficient HTTP/2 pseudo-header/framing
handling during the H2→HTTP/1.1 backend conversion creates a desync: attacker-crafted H2 request reads
as ONE request to the cache but TWO to the backend → cache poisoning / auth bypass / info disclosure.
**Hard gate**: only reachable when the deployment explicitly sets `feature` to include `+http2`
(disabled by default) — version-match alone is not sufficient, confirm H2 is actually enabled
(ALPN/alt-svc h2 on the Varnish-fronted edge) before treating as more than a LEAD.
Detection tool: Detectify's PoC scanner — https://github.com/detectify/Varnish-H2-Request-Smuggling
Distinct from CVE-2026-34475 (Varnish URL-handling auth bypass, already in this doc) — different root
cause (H2 parsing vs URL path handling), track both.
Sources: https://www.sentinelone.com/vulnerability-database/cve-2026-50052/, https://vinyl-cache.org/security/VSV00019.html

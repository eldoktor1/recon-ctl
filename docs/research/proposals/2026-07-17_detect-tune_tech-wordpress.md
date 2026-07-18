# PROPOSAL (proposal) for docs/knowledge/tech-wordpress.md — detect-tune 2026-07-17
_Review and apply manually; not auto-merged into the KB._

## wp-json user enumeration — FP/impact-gate note, 2026-07-17
`/wp-json/wp/v2/users` and `?author=N` username enumeration is WordPress core's intentional default
(headless/mobile API support), restricted to REST-exposed post-type authors since 4.7.1 — not a
misconfiguration by itself. Per our impact-gate doctrine, treat a bare enumeration hit as theoretical/N/A
unless chained with an amplifier already present on the same host: missing login rate-limiting/lockout
(credential-stuffing path) or `xmlrpc.php` `system.multicall` still enabled (brute-force multiplier). Don't
mint or spend probe budget on enumeration alone.

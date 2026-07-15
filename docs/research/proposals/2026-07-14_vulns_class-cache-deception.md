# PROPOSAL (proposal) for docs/knowledge/class-cache-deception.md — vulns 2026-07-14
_Review and apply manually; not auto-merged into the KB._

## Parser-discrepancy cache poisoning/deception (PortSwigger "Gotta Cache 'Em All", 2025, added 2026-07-14)
- New technique class beyond path-confusion: exploits DELIMITER discrepancies between origin app frameworks and the front-end cache — chars the cache treats as part of the path but the origin treats as a terminator (or vice versa): `;` (Spring/Java), `.` (Rails formatter ext), `%00` (OpenLiteSpeed), `%0a` (Nginx rewrite), `#`.
- Confirmed-affected in our stack: Cloudflare, CloudFront, Google Cloud (cache layer) + Nginx, Apache (origin).
- Detect (safe, our own cache-buster key, matches our existing WCD safety primitive):
  1. Baseline: non-cacheable request to a dynamic endpoint.
  2. Append a random suffix path segment (`/homeabcd`) — confirm still dynamic/uncached.
  3. Retry with a suspected delimiter before the suffix (`/home;abcd`, `/home%0aabcd`, etc.) — if the response now matches a STATIC/cacheable baseline (or `Cache-Status`/`CF-Cache-Status: HIT` appears on a second identical request), the delimiter causes a parser split → path-confusion WCD candidate.
- Second technique: cache-key normalization abuse — poison via unresolved `../` traversal sequences hidden after a delimiter the cache doesn't decode but the origin does.
- Source: https://portswigger.net/research/gotta-cache-em-all

# PROPOSAL (proposal) for docs/knowledge/class-ssrf.md — kb-enrich 2026-07-28
_Review and apply manually; not auto-merged into the KB._

## Redirect-chain confirm-primitive bypass (added 2026-07-28)

When a sink validates the literal input URL against an allowlist/blocklist but the underlying HTTP
client follows redirects, a direct interactsh canary URL will get rejected while a **redirect chain**
still lands. Point the sink at an allowed-looking URL (or a URL on a domain the validator accepts) that
302-redirects to the interactsh canary, instead of the canary directly. The confirm primitive is
unchanged (OOB callback = proof) — this just routes around hostname-level input validation that doesn't
also constrain where the client is allowed to *end up*. Try this as the second pass on any sink that
outright rejects/400s the direct canary URL before marking it not-vulnerable.

## Protocol-smuggling impact note — severity reasoning only, never autonomous (added 2026-07-28)

`gopher://`/`dict://` schemes deliver raw bytes (including CRLF) to the target port. Because
Redis/Memcached/SMTP/FastCGI are text/line-based protocols, a confirmed SSRF that can reach one of these
internal services on its native port is a materially higher-severity finding than one that only reaches
an HTTP metadata endpoint or a generic internal web app — the same primitive that gives an OOB ping can,
in the hands of an authorized full exploit, write Redis keys or hit FastCGI. This is a **write-up
severity signal only**: never issue the gopher/dict payload autonomously or chase actual internal writes
— the interactsh OOB callback remains the sole confirm primitive; this just informs how to *describe*
impact once a human is doing the authorized manual escalation.

### Sources (added 2026-07-28)
- portswigger.net/research (Orange Tsai "A New Era of SSRF" cited via secondary sources) — parser-discrepancy bypass class
- intruderlabs.com.br/en/blog/ssrf-bypass-techniques (gopher/dict payload mechanics)

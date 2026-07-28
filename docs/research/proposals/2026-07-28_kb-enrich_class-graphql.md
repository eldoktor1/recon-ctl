# PROPOSAL (proposal) for docs/knowledge/class-graphql.md — kb-enrich 2026-07-28
_Review and apply manually; not auto-merged into the KB._

## Automatic Persisted Queries (APQ) are not a safelist (added 2026-07-28)

`hideSchemaDetailsFromClientErrors`/introspection-off is not the only false sense of security
worth checking — **APQ is a second one, and it's easy to mistake for hardening.**

**The misconception:** a target where captured client traffic only ever shows
`{"extensions":{"persistedQuery":{"sha256Hash":"..."}}}` with no `query` field LOOKS like an
allowlisted API (nothing to fuzz — you'd need to know a valid hash). It usually isn't.

**Why it fails as a safelist:** Apollo-style APQ is a bandwidth/caching optimization, not
authorization. Protocol:
1. Client sends only the hash.
2. If the server doesn't recognize it → `{"errors":[{"message":"PersistedQueryNotFound", ...}]}`.
3. Client is expected to retry the SAME request with the full `query` string attached
   (still carrying the hash in extensions). Most Apollo-server deployments EXECUTE this
   full query normally, and then cache it under the hash for future short-form requests.

**Practical effect:** any hash you invent gets you a `PersistedQueryNotFound` for free — a
zero-risk confirmation the server is Apollo-APQ. From there, standard GraphQL testing (this
doc's full introspection-bypass ladder, batching/aliasing, IDOR-via-argument, WebSocket
subscriptions) is NOT restricted by APQ at all — attach the full query on the same request
and it runs like any other GraphQL endpoint. Scanners/hunters who only replay captured
HAR/proxy traffic (hash-only requests) will see nothing to test and wrongly deprioritize
the target; this is exactly the dup-avoidance edge worth exploiting.

**Detect (safe, read-only, one request):**

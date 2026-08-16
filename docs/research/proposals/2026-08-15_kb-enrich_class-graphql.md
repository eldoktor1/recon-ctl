# PROPOSAL (proposal) for docs/knowledge/class-graphql.md — kb-enrich 2026-08-15
_Review and apply manually; not auto-merged into the KB._

## Automatic Persisted Queries (APQ) is not a safelist — hash-injection bypass (added 2026-08-15)

Distinct from every existing bypass in this doc (fragment obfuscation, whitespace/inline-fragment
introspection bypass, field-suggestion recovery, federation `_service{sdl}`) — this targets a common
DEV MISCONCEPTION rather than a schema-disclosure gap: engineering teams often believe "we run APQ" ==
"only pre-approved queries execute," when APQ (Apollo Server/Router, graphql-yoga, gqlgen, most JS/Go
stacks) is a **bandwidth optimization**, not access control, and will happily register and execute any
NEW query on a cache-miss.

### The mechanism
APQ lets a client send just a query's `sha256Hash` in `extensions.persistedQuery` instead of the full
query text (saves bytes on repeat requests). The server looks the hash up in its cache:
- **Hash hit** → executes the cached query.
- **Hash miss** → responds `PersistedQueryNotFound`. The PROTOCOL then expects the client to retry the
  SAME request but with the full `query` string attached alongside the hash — and the server **executes
  it and caches it under that hash for next time**. Nothing in the spec/most implementations checks that
  the submitted query is on any pre-approved list; it just registers whatever you send.

### The attack (read-only recon step, always safe)
```json
// Step 1 — probe with a bogus hash, no query text:
POST /graphql
{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"0000...deadbeef"}}}
// → {"errors":[{"message":"PersistedQueryNotFound", ...}]}   confirms APQ is live

// Step 2 — retry with a full arbitrary query attached to the SAME (fake) hash:
POST /graphql
{"query":"query{__schema{types{name}}}",
 "extensions":{"persistedQuery":{"version":1,"sha256Hash":"<sha256 of the query string above>"}}}
// → executes normally if APQ (not true safelisting/persisted-operations) is what's deployed

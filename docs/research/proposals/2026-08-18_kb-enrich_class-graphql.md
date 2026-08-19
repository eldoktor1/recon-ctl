# PROPOSAL (proposal) for docs/knowledge/class-graphql.md — kb-enrich 2026-08-18
_Review and apply manually; not auto-merged into the KB._

## Alias/array batching bypasses HTTP-layer rate limiting (2025-2026)

**Mechanism:** most rate limiters count HTTP requests, not GraphQL operations. A single POST can
carry dozens/hundreds of independently-executed operations via query aliasing or array batching —
the limiter sees "1 request", the resolver executes N.

**Alias-batching payload (read/enum use — safe, single response, human-readable):**
```graphql
query {
  user(id: 1) { id name email }
  u2: user(id: 2) { id name email }
  u3: user(id: 3) { id name email }
  ... up to u100: user(id: 100) { id name email }
}

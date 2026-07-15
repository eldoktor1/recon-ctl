# PROPOSAL (proposal) for docs/knowledge/class-graphql.md — kb-enrich 2026-07-14
_Review and apply manually; not auto-merged into the KB._

## Batching/aliasing rate-limit bypass (added 2026-07-14)
Source: PortSwigger "GraphQL batching & aliases" research (2023, still the dominant driver of
2024-2025 GraphQL bounty payouts per Checkmarx/Wallarm/Escape.tech writeups).

**Mechanism:** GraphQL lets a client alias the same field/operation N times in one request; the
server executes all N, but naive rate limiters count HTTP requests, not GraphQL operations —
so 1 request = N operations, invisible to request-count throttling.

**Safe/unauth detection (fits our read-only primitive discipline):** send N aliased copies of an
already-safe query (`{__typename}` or a public non-sensitive query) in a single POST; compare
against sending N separate single-operation requests. If the batched form completes all N where
sequential single requests get rate-limited/blocked after M<N, mint `graphql:ratelimit-bypass`
(LEAD, not P0 — impact requires pointing it at a real throttled endpoint like login/OTP/password-reset,
which is a MUTATION and stays human-owned/2-account per doctrine).

**Companion pattern — nested-field authorization gap:** some backends authorize the top-level
query/mutation but not fields resolved underneath it (e.g. a public `product(id)` query whose
nested `product.owner.email` resolver skips its own auth check). Worth noting in the schema-walk
worklist as a distinct LEAD from top-level unauth mutation exposure — same schema-harvest pass,
different auth boundary.

Sources:
- https://checkmarx.com/blog/didnt-notice-your-rate-limiting-graphql-batching-attack/
- https://lab.wallarm.com/graphql-batching-attack/
- https://escape.tech/blog/graphql-batch-attacks-cause-dos/
- https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html

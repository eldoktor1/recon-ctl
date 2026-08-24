# PROPOSAL (proposal) for docs/knowledge/class-graphql.md — kb-enrich 2026-08-23
_Review and apply manually; not auto-merged into the KB._

## Nested-resolver BOLA — auth doesn't cascade past the root query (added 2026-08-23)
A distinct, higher-value bug class beyond "introspection enabled" or root-level IDOR: many
GraphQL servers enforce authorization only in the ROOT query resolver (e.g. a guard on
`user(id: ID!)`), but the SAME object type is also reachable as a nested field on a sibling/
parent type (e.g. `order(id) { user { ssn } }`, `booking { customer { paymentToken } }`) —
and that nested resolver never re-checks ownership because it only receives the parent object,
not the original auth context.

**Recon application (fits our read-only, schema-driven lane):**
1. From the harvested introspection schema, find every type reachable via more than one path —
   both as a root Query field AND as a field on another type that itself is reachable
   (directly or via an object the caller can legitimately reach).
2. Flag fields on that type that look sensitive (`ssn`, `paymentToken`, `jwtToken`,
   `sessionSecret`, `email`, `role`, `isAdmin`, `internalNotes`, etc.) — schema introspection
   only, no data query yet, matching our existing safe-only ranking step.
3. The actual confirm (querying the nested path with an object ID the operator doesn't own) is
   an object-level authz test — stays human/2-owned-account per our existing IDOR hard line;
   surface it as a ranked candidate in `graphql_candidates_<date>.md`, not an auto-probe.
This deepens our existing candidate ranker beyond flat "sensitive query" scoring — a field is
higher-EV if it's sensitive AND reachable via a path that plausibly skips the root guard.

Also useful for scoping: **differential-testing companion** — run the identical nested-path
query as two different owned-account roles and diff which fields come back; an authz gap shows
up as the lower-privileged account seeing fields it shouldn't, even if the top-level query
itself is correctly gated.

Sources:
- https://dev.to/crud5th-273-/authorization-bypass-in-graphql-reproduction-and-detection-techniques-893
- https://oneuptime.com/blog/post/2026-01-24-graphql-authorization-resolvers/view

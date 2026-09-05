# PROPOSAL (proposal) for docs/knowledge/class-graphql.md — detect-tune 2026-09-05
_Review and apply manually; not auto-merged into the KB._

## Relay `node(id:)` global-ID authz bypass (added 2026-09-05)
Any GraphQL schema exposing the Relay-spec root field `node(id: ID!): Node` (or `nodes`) is worth testing
separately from named queries: authz/security rules are frequently wired onto the named per-type query
(`book(id:)`, `order(id:)`) but the generic `node` resolver fetches by opaque global ID without re-running
that check. Detect via introspection: root `Query` type has a `node`/`nodes` field returning a `Node`
interface, AND the schema has authz-sensitive named queries returning types that implement `Node`.
Reference CVE: api-platform/core & api-platform/graphql <4.0.21/<3.4.16 (GHSA-cg3c-245w-728m) — PoC
`query { node(id:"/books/1"){ ... on Book { title } } }` returned data a direct `book(id:)` query
correctly blocked. This is a framework-agnostic pattern (Relay GID spec), not api-platform-specific —
check for it on ANY GraphQL target with introspection enabled. Global IDs are typically
`base64("TypeName:id")` — constructible from a type name plus an ID format seen elsewhere in the app.
STILL a human-confirm / 2-owned-account primitive per our hard line — never probe against IDs we don't
own; the LEAD is "does node exist + do named queries have authz the generic resolver skips."

## Hasura computed-field row-level-permission bypass (added 2026-09-05)
CVE-2026-54698 (GHSA-r27x-gc74-qmxh, CVSS 7.7): Hasura GraphQL Engine <2.49.2 (and 2.45.x <2.45.5) lets a
`where` clause filtering on a **computed field** brute-force protected row values, defeating role-scoped
row-level permissions. Version-gate like any other n-day: confirm the running Hasura version (`x-hasura-*`
response headers, `/v1/version` endpoint if exposed) is in the vulnerable range before treating this as
more than a LEAD.

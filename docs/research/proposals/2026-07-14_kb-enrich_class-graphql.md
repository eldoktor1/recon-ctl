# PROPOSAL (proposal) for docs/knowledge/class-graphql.md — kb-enrich 2026-07-14
_Review and apply manually; not auto-merged into the KB._

## Case studies + mutation-input bypass tricks — added 2026-07-14 (kb-enrich)

### Real disclosed case: airline GraphQL BOLA (validates our ranking spine)
A red-team writeup (Wiz, 2025) exploited a production airline GraphQL API with exactly the shape our
ranker looks for: `bookingRetrieveByBookingId(bookingId: 144)` — a SEQUENTIAL INTEGER object-ref arg,
reachable UNAUTHENTICATED (no session/token required at all). Every sequential ID returned a distinct
customer: name, DOB, gender, personal email/phone, masked card + billing address, 2-year flight history.
Introspection on the anonymous session exposed **514 queries and 428 mutations**, several dangerous
(`flightDelete`, `contactsChange`, `priceOverride`) — meaning the exposed schema wasn't just a read leak,
it was a write-capable anonymous session. Discovery method mirrors our lane exactly: (1) pull the API
gateway/token flow from JS bundles (jsintel), (2) introspect to enumerate the full op surface, (3) test
sequential IDs on the highest-signal query name. Use as a training example for how "IDOR via object
arguments" (item 2 in the ranking spine above) actually pays out — this one would have scored maximally
on our ranker (mutations present, sequential-int ID type, PII/financial fields, unauth-reachable).
Source: https://www.wiz.io/blog/red-agent-pov-bola

### Mutation-input bypass tricks (GraphQL-specific — distinct from the REST array/JSON-coercion
entries in class-idor.md; these exploit the SCHEMA'S input-type flexibility, not just JSON parsing)

**Array-wrapping a scalar object-ref variable.** A delete/update mutation typed to take a single scalar
ID (`deleteDocument(id: ID!)`) may have its ownership check written for the scalar path specifically.
Sending the SAME id wrapped in an array via a raw JSON variables payload (bypassing the typed client)
— e.g. `{"id": ["victimDocId"]}` against a mutation expecting `{"id": "victimDocId"}` — can reach the
resolver with the check skipped (GraphQL/JS deserializers are often lenient; the resolver's business
logic still extracts element 0 and executes). Test any mutation whose GraphQL-typed arg is a bare ID by
replaying with the value array-wrapped at the transport layer.

**Mass assignment via broad `*Input` types.** Mutations that accept a full input object
(`updateProfile(input: UpdateProfileInput)`) and persist it without allowlisting fields let a caller set
ANY field the schema exposes on that input type — including ones the UI never renders, e.g. `role`,
`isAdmin`, `verified`, `balance`. Introspection hands you the complete field list for the input type for
free (no source access needed) — always dump `UpdateXInput`/`CreateXInput` field lists for every mutation
in the ranked worklist and flag any privilege/financial/verification field that's settable alongside the
intended ones. This is the GraphQL-native version of REST mass-assignment, but the attack surface (which
fields exist) is handed to you by the schema rather than needing to be guessed.
Source: https://dev.to/crud5th-273-/authorization-bypass-in-graphql-reproduction-and-detection-techniques-893

### Concrete alias-batching brute-force payload + hardening signature
Reference payload for the alias-overload class (already in our graphql-cop `alias_overloading` check):
```graphql
mutation {
  login(username: "Tom", password: "password")
  second: login(username: "Tom", password: "password123")
  third: login(username: "Tom", password: "TomTheBest")
}

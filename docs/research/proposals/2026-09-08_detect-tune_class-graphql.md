# PROPOSAL (proposal) for docs/knowledge/class-graphql.md — detect-tune 2026-09-08
_Review and apply manually; not auto-merged into the KB._

## APQ (Automatic Persisted Queries) registration bypass — second unauth execution path (added 2026-09-08)
Distinct from field-suggestion/Clairvoyance schema recovery. Many GraphQL servers (Apollo and
compatible) expose an APQ cache-registration flow that does NOT re-apply the allowlist/introspection-
disabled checks enforced on the main query path:

1. POST `{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"<sha256 of a query>"}}}` (no
   `query` field). Expect `PERSISTED_QUERY_NOT_FOUND` if introspection/allowlist is otherwise locked down.
2. POST the SAME hash plus the full query text: `{"query":"<query>","extensions":{"persistedQuery":
   {"version":1,"sha256Hash":"<same hash>"}}}`. If the query executes, the server accepted an
   arbitrary registration — the allowlist is a main-path-only control, not enforced at APQ registration.

**Safe/read-only test:** use an introspection query (`{__schema{queryType{name}}}`) as the payload —
this stays inside our existing read-only schema-recon primitive; a success means "introspection
disabled" was not actually enforced. Never register a sensitive query/mutation this way — same
2-owned-account gate applies if you want to go further than schema recon.
**Add to `recon_graphql.sh`:** try this two-step whenever direct introspection is refused, before
falling back to Clairvoyance-style field-suggestion fuzzing. A successful APQ-bypass schema pull is
a stronger LEAD (proves the control itself is bypassable) than field-suggestion alone.
Source: https://dev.to/roxdavirox/graphql-apq-registration-bypasses-query-allowlists-and-introspection-controls-20p2 ; related: CVE-2025-32034 (Apollo Router), CVE-2026-32594 (Parse Server, already tracked).

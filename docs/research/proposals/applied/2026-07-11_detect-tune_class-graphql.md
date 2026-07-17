# PROPOSAL (proposal) for docs/knowledge/class-graphql.md — detect-tune 2026-07-11
_Review and apply manually; not auto-merged into the KB._

## Engine fingerprinting (graphw00f) — 2026-07-11
Before/alongside schema harvest, fingerprint the GraphQL engine via graphw00f-style probes
(mix of benign + malformed queries/directives, classify by distinct error text). 36+ engines
identified (Graphene, Ariadne, Strawberry, graphql-go, gqlgen, Hasura, WPGraphQL, Apollo, ...).
Engine ID lets us target engine-specific known-mutation/known-issue lists instead of generic
probing, and cross-reference against the GraphQL Threat Matrix. Tool: https://github.com/dolevf/graphw00f

## Introspection-disabled bypass before falling back to Clairvoyance
Many "introspection disabled" deployments are a naive regex grep on the request body for
`__schema` / `IntrospectionQuery`. Inserting a stray/whitespace character immediately after
`__schema` can slip the regex while the parser still executes the query. Try this cheap bypass
first (still read-only, `{__typename}`-class risk) before falling back to guaranteed-invalid
field-suggestion recovery. Introspection re-enabled-via-bypass is still Info/dup alone — same
gate as always; it only changes HOW MUCH schema we recover for the reasoning pass.

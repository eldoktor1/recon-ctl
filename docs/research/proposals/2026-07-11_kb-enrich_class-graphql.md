# PROPOSAL (proposal) for docs/knowledge/class-graphql.md — kb-enrich 2026-07-11
_Review and apply manually; not auto-merged into the KB._

## Nested-resolver BOLA gap + mass-assignment mutations (added 2026-07-11)
Two GraphQL-specific authorization patterns distinct from the top-level object-ref-arg check we already
rank — worth adding to the reasoning pass over the harvested schema:
- **Nested-resolver BOLA:** many GraphQL servers enforce auth only at the gateway / top-level
  query/mutation (a middleware wrapper that checks "is this user logged in"), but an inner resolver for
  a NESTED type (e.g. `order(id) { customer { email, ssn } }` or `invoice { billingAccount { iban } }`)
  trusts the parent object's id and does not re-check that the CURRENT session owns that parent. Net
  effect: a mutation/query that looks properly scoped at the top level can still leak or let you modify
  a nested object you don't own. When ranking schema fields, flag nested object types returned from a
  query/mutation that themselves carry sensitive scalar fields (PII/financial) — these deserve a 2-account
  test even when the outer field looks "me-scoped."
- **Mass assignment via full-input mutations:** mutations that accept a broad input TYPE rather than
  individual scalar args (`updateProfile(input: UpdateProfileInput)`) are a privesc vector when the
  input type includes fields the UI never sends (`role`, `isAdmin`, `accountTier`, `verified`) but the
  resolver doesn't allow-list before persisting. Detectable from the harvested introspection schema
  alone (no execution needed): diff the input type's full field list against what a normal client
  request sends (jsintel-observed request bodies) — any extra privileged-looking field in the schema
  that never appears in an observed request is a mass-assignment candidate worth a 2-account probe
  (send it, see if it's silently accepted).
- Real-world anchor: a fintech target combining public introspection + batch-query processing + nested
  IDOR reached CVSS 9.1 / $12,500 (2026).
Sources: https://infosecwriteups.com/graphql-security-how-i-found-and-exploited-critical-idor-and-authorization-bypass-in-a-42ab78e13642 ,
https://hivesecurity.gitlab.io/blog/api-security-jwt-oauth-graphql-attacks/

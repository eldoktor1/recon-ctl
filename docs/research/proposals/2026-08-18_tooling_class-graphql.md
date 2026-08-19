# PROPOSAL (proposal) for docs/knowledge/class-graphql.md — tooling 2026-08-18
_Review and apply manually; not auto-merged into the KB._

## Tool: graphql-cop (dolevf/graphql-cop, 686★, actively maintained)
Unauth-safe, non-destructive GraphQL misconfig scanner — 12 checks beyond bare introspection:
alias/batch/field-duplication/directive-overloading/circular-query DoS-capability detection,
**mutation-over-GET / CSRF-via-GET-query** (a REAL exploitable primitive, not an Info-FP —
means a state-changing mutation is reachable via plain GET, hence CSRF-able cross-site),
tracing/debug-mode leakage, GraphiQL exposure, field-suggestion harvesting. `-f/--force` probes
common GraphQL paths even with introspection off, and common paths without a known endpoint.
Run as a supplemental pass in `recon_graphql.sh` after schema harvest. A confirmed
mutation-reachable-via-GET hit is a CONFIRMED-tier primitive (executed unauth CSRF surface),
not a LEAD — distinct from "introspection enabled alone" which stays the #1 dup per this doc.
Source: https://github.com/dolevf/graphql-cop

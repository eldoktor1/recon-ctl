# PROPOSAL (proposal) for docs/knowledge/class-graphql.md — vulns 2026-09-11
_Review and apply manually; not auto-merged into the KB._

## Enumeration technique: alias-batching for IDOR candidate scoring (added 2026-09-11)
Source: https://medium.com/@M00xy/exploiting-graphql-a-complete-guide-for-bug-bounty-hunters-355fecb02eb0 , disclosed-report patterns summarized in Intigriti's 2026 bug-bounty tips.

When the introspected schema exposes a query/type field that takes a single scalar ID argument
(e.g. `user(id: ID!)`, `order(id: ID!)`), GraphQL lets a client send many aliased copies of that
field in ONE request:

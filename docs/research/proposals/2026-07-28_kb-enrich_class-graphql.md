# PROPOSAL (proposal) for docs/knowledge/class-graphql.md — kb-enrich 2026-07-28
_Review and apply manually; not auto-merged into the KB._

## Mass-assignment / over-posting via mutation input fields (added 2026-07-28)

Schema-diff technique for `recon_graphql.sh`: for every mutation, diff the introspection-declared
input-type field list against fields actually observed in captured/crawled traffic for that mutation.
Fields present in the schema but never sent by the real frontend (e.g. `role`, `isAdmin`, `balance`,
`isPremium`, `subscriptionStatus`, internal/audit fields) are mass-assignment/over-posting candidates —
the backend may deserialize the whole input object straight into the DB model without allow-listing,
so setting a privileged field the UI never exposes can silently succeed. This is HUMAN 2-owned-account
territory (state-changing mutation) — surface as a ranked LEAD in `graphql_candidates_<date>.md`, never
auto-fired (mutations are excluded from the autonomous read-only probe set).

Real payout precedent for this general class: Shopify H1 #2207248, $5,000, cross-tenant IDOR via
GraphQL `BillingDocumentDownload`/`BillDetails` queries.

Sources: medium.com/@merida- (Mass Assignment in APIs for bug bounty), meetcyber.net (GraphQL bug
bounty guide, May 2026).

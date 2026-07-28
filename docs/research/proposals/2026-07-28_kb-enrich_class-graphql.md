# PROPOSAL (proposal) for docs/knowledge/class-graphql.md — kb-enrich 2026-07-28
_Review and apply manually; not auto-merged into the KB._

## WebSocket subscription transport as a separate attack surface (2026-07-28)

`recon_graphql.sh` only probes HTTP (introspection / suggestions). GraphQL subscription
endpoints (commonly `/graphql-ws`, `/subscriptions`, protocol `graphql-ws` or
`subscriptions-transport-ws`) run a SEPARATE resolver path that often skips the input
validation the HTTP layer has — a real 2026 case chained IDOR→error-based SQLi this way
($2,000, critical):

- High-entropy numeric/UUID object IDs that look unenumerable over HTTP may still be
  injectable over WS: fuzz the ID argument with junk chars and watch the WS error frames
  for verbose DB errors (column/table names leaking = Postgres/MySQL error-based sink).
- Once a leaking column name is known, inject it back into the ID param to force a
  type-conversion error that reflects real row data in the error message; `||` (Postgres
  string concat) pulls multiple fields/rows through the same error channel without a
  UNION.
- Discovery signal: any in-scope host serving GraphQL should get a WS handshake attempt
  (`Upgrade: websocket` to the same path family) even if the HTTP endpoint looked clean —
  this is a distinct, currently-untested surface for us.
- Still HUMAN/authed-confirm only per our doctrine (injection primitives are never
  autonomous) — but the read-only introspection/discovery step (does a WS endpoint exist,
  does it accept subscriptions) is safe to add to the automated recon-graphql pass.

Source: https://medium.com/@DarkyOS/sql-injection-in-graphql-websocket-escalated-to-pii-document-leak-09ba7ad2800a

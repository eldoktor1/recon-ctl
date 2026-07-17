# PROPOSAL (proposal) for docs/knowledge/class-graphql.md — kb-enrich 2026-07-11
_Review and apply manually; not auto-merged into the KB._

## Apollo Federation attack surface — subgraph exposure + composition-logic CVEs (added 2026-07-11)

Distinct from single-schema GraphQL (existing doc). Federated graphs (Apollo Router + subgraphs) have an
attack surface the crowd doesn't check because the tooling (`recon_graphql.sh`, graphw00f, graphql-cop)
targets the gateway, not the subgraphs behind it.

### 1. `_service { sdl }` — schema disclosure that bypasses introspection-off
Every Apollo Federation subgraph implements a federation-layer field independent of core GraphQL
introspection — disabling `__schema` has **no effect** on it:
```graphql
{"query":"query{_service{sdl}}","operationName":null}

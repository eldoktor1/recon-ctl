# PROPOSAL (proposal) for docs/knowledge/class-graphql.md — tooling 2026-07-01
_Review and apply manually; not auto-merged into the KB._

## Tool additions (2026-07-01)

### graphql-cop — automated multi-check CLI
- GitHub: https://github.com/dolevf/graphql-cop | v1.16 Nov 2025
- Runs 12 checks in one call: introspection, **field suggestions** (clairvoyance-style near-miss probes), alias overloading, batch queries, GET-based queries, directive overloading, CSRF vectors
- Add to `recon_graphql.sh` after the introspection gate:
  ```
  graphql-cop -t https://<host>/graphql -o json
  ```
- Field suggestions check automates the manual "guaranteed-invalid 1-char near-miss probe" step; keep Clairvoyance for deep schema reconstruction when introspection is off.

### Clairvoyance — deep schema reconstruction (introspection-off targets)
- GitHub: https://github.com/nikitastupin/clairvoyance | v2.5.5 Dec 2025
- Use when introspection is disabled — iterates near-miss probes to reconstruct the full schema from field suggestions
- JSON schema output suitable for GraphQL Voyager or direct worklist generation
- If `recon_graphql.sh` hand-rolls the field-suggestion loop, replace that section with clairvoyance

### GraphQLer — operator-triggered deep mode only
- GitHub: https://github.com/omar2535/GraphQLer | v2.3.8 Mar 2026
- Dependency-graph fuzzer: chains queries based on schema, surfaces IDOR via object-ref args
- GATE: `--disable-mutations` required; operator-triggered only (not autonomous daemon). Sends real queries.

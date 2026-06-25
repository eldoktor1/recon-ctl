# PROPOSAL (proposal) for docs/knowledge/class-graphql.md — kb-enrich 2026-06-24
_Review and apply manually; not auto-merged into the KB._

## New techniques (2024–2025)

### Introspection bypass via fragment obfuscation (CVE-2024-37155, 2024)
Beyond the existing whitespace / `\n` bypass (already in this doc), query fragments evade regex-based
block filters that look for `__schema` at the top-level query:

```graphql
query { ...schemaFrag }
fragment schemaFrag on Query { __schema { types { name fields { name } } } }

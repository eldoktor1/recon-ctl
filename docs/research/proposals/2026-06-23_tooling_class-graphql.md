# PROPOSAL (proposal) for docs/knowledge/class-graphql.md — tooling 2026-06-23
_Review and apply manually; not auto-merged into the KB._

## Operator-side tooling addition (2026-06-23)

### InQL v6 (Burp Suite extension, Doyensec)
https://github.com/doyensec/inql

When `recon-graphql` produces a `graphql_candidates_<date>.md` briefing, load the harvested
introspection JSON into InQL in Burp. It auto-generates all possible queries/mutations from
the schema and organizes them for rapid iteration — cuts manual curl iteration substantially.

**Not a pipeline tool** — operator-side only for human-test evenings. Install in operator Burp;
load the introspection JSON from `recon_graphql.sh` output (the `.json` file it writes to
`~/recon/graphql/`).

# PROPOSAL (proposal) for docs/knowledge/class-graphql.md — tooling 2026-08-22
_Review and apply manually; not auto-merged into the KB._

## Tooling update (2026-08-22)
`dolevf/graphw00f` (https://github.com/dolevf/graphw00f, 845★, same author as graphql-cop
already adopted 2026-08-18) fingerprints the specific GraphQL engine and cross-references the
GraphQL Threat Matrix for that engine's default security posture (batching limits, introspection
default, query-depth limiting). Proposed as an optional pre-step in `recon_graphql.sh` before the
graphql-cop misconfig pass — knowing the engine's *expected* defaults makes an actual misconfig
hit (e.g. batching enabled on an engine that disables it by default) a stronger signal, not just
"a check fired." Unauth-safe, read-only fingerprint probes only.
Also noted: CVE-2026-19650 (GitLab GraphQL multiplex-query CSRF, CVSS 7.1) is a live real-world
instance of the "mutation reachable via GET → CSRF" primitive graphql-cop detects — confirms
that check is aimed at genuine impact, not a state-only Info-FP.

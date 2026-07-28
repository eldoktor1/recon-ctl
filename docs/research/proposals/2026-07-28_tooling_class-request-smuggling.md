# PROPOSAL (proposal) for docs/knowledge/class-request-smuggling.md — tooling 2026-07-28
_Review and apply manually; not auto-merged into the KB._

## Tooling update (2026-07-28)
Adopted **Smugglex** (github.com/hahwul/smugglex, Rust) as the detection primitive for this lane — covers CL.TE/TE.CL/TE.TE plus HTTP/2 vectors (H2C smuggling, H2→H1 downgrade via `h2-downgrade`) that our prior ad-hoc checks didn't reach. Actively maintained. Usage: `smugglex https://target.com`, structured output for pipeline ingestion. Detection is differential/timing-based (desync signal), non-destructive — fires as an unauth-safe LEAD; treat any positive as a LEAD requiring careful, rate-limited manual confirmation before minting CONFIRMED (never chain into exploitation/request desync against live production traffic).

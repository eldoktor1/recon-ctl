# PROPOSAL (proposal) for docs/knowledge/class-request-smuggling.md — tooling 2026-08-22
_Review and apply manually; not auto-merged into the KB._

## Tooling update (2026-08-22)
Supersede the `Smugglex` mention (2026-07-28 digest) with **`defparam/smuggler`**
(https://github.com/defparam/smuggler) as the primary detection tool for the planned
`recon_smuggling.sh` lane — 2.1k★, actively maintained through 2026, the tool referenced
in PayloadsAllTheThings' Request Smuggling page. Same posture as before: differential/
timing-based desync detection is unauth-safe and non-destructive; treat a confirmed
CL.TE/TE.CL desync as a LEAD needing careful, rate-limited manual confirmation before any
mint — never a destructive replay against production.

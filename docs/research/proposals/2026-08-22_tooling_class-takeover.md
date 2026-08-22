# PROPOSAL (proposal) for docs/knowledge/class-takeover.md — tooling 2026-08-22
_Review and apply manually; not auto-merged into the KB._

## Tooling note (2026-08-22)
`Stratus-Security/Subdominator` (https://github.com/Stratus-Security/Subdominator) ships a
`--validation` mode that checks a fingerprint-matched candidate against the provider's actual
claim mechanism, rather than stopping at fingerprint match — i.e. a maintained, multi-provider
version of our own claimability-confirm step ([[feedback_takeover_claimability_primitive]]).
Worth trialing as a confirmation-stage companion to badDNS (which stays for breadth — signature
sync from Nuclei/dnsReaper + second-order takeover via referenced client-side JS/CSS domains,
which Subdominator doesn't cover). Not yet adopted — pending a trial against known cname-lead
hosts to confirm it doesn't under/over-claim vs our existing per-provider checks.

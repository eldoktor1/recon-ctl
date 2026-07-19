# PROPOSAL (proposal) for docs/knowledge/class-cache-deception.md — vulns 2026-07-17
_Review and apply manually; not auto-merged into the KB._

## Varnish-specific poisoning primitive: CVE-2026-34475 (added 2026-07-17)
Beyond generic path-confusion WCD, Varnish < 8.0.1 (OSS) / < 6.0.16r12 (Enterprise) has a named CVE for root-path (`/`) canonicalization mishandling under HTTP/1.1 (CWE-180, validate-before-canonicalize) — see [[tech-varnish]]. Worth a dedicated test variant on Varnish-fronted hosts (`Via`/`X-Varnish` header present) alongside the existing generic WCD probes, same unique-cache-buster safety rule.

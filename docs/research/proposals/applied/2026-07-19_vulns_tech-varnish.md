# PROPOSAL (proposal) for docs/knowledge/tech-varnish.md — vulns 2026-07-19
_Review and apply manually; not auto-merged into the KB._

## CVE-2026-34475 — Varnish auth-bypass / cache-poisoning via req.url canonicalization (added 2026-07-19)
- Unchecked `req.url` handling for HTTP/1.1 requests with path `/` (validate-before-canonicalize,
  CWE-180) lets an attacker poison the shared cache or bypass URL-based access controls enforced
  at the Varnish layer.
- Affected: Varnish Cache < 8.0.1, Varnish Enterprise < 6.0.16r12.
- Unauth fingerprint: `X-Varnish` / `Via: 1.1 varnish` response headers → version-check against fix.
  Genuine confirmable primitive (not a heuristic) — prioritize over generic path-confusion WCD
  probes on any host that fingerprints as Varnish in this version band.
- Source: https://github.com/advisories/ghsa-m9gq-cmcj-p62x

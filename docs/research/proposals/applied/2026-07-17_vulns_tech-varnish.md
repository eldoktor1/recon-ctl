# PROPOSAL (proposal) for docs/knowledge/tech-varnish.md — vulns 2026-07-17
_Review and apply manually; not auto-merged into the KB._

## CVE-2026-34475 — req.url canonicalization cache-poisoning/auth-bypass (added 2026-07-17)
Varnish Cache < 8.0.1 / Varnish Enterprise < 6.0.16r12: validation-before-canonicalization bug (CWE-180) mishandles HTTP/1.1 requests with path `/` in unchecked-`req.url` VCL scenarios → cache poisoning or bypass of URL-based access-control logic in VCL. **Unauthenticated, no privileges required.** No public version-disclosure fingerprint yet — identify Varnish presence via `Via: 1.1 varnish`/`X-Varnish` headers, then treat as LEAD pending version confirmation. Ties directly into our WCD lane (`recon_wcd.sh`) — test root-path HTTP/1.1 requests with our unique cache-buster key per usual SAFE-detect-only rules; never poison the shared cache. Source: https://github.com/advisories/GHSA-m9gq-cmcj-p62x

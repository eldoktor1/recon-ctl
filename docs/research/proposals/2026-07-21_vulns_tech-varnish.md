# PROPOSAL (proposal) for docs/knowledge/tech-varnish.md — vulns 2026-07-21
_Review and apply manually; not auto-merged into the KB._

## CVE-2026-34475 — req.url canonicalization auth-bypass / cache-poisoning (2026-07-21)
- CWE-180 (validate-before-canonicalize): Varnish mishandles HTTP/1.1 requests with path `/` in
  certain unchecked `req.url` scenarios in VCL — malformed requests can bypass cache-key/auth
  logic that inspects `req.url`, enabling cache poisoning and potential VCL auth-check bypass.
- Affected: Varnish Cache < 8.0.1, Varnish Enterprise < 6.0.16r12. Patched: 8.0.1 / 6.0.16r12.
- No universal remote fingerprint (exploitability is VCL-config-dependent). Practical recon move:
  pull Varnish version from `Via`/`X-Varnish` response headers on in-scope hosts → if < 8.0.1
  (OSS) or < 6.0.16r12 (Enterprise), treat as a version-range LEAD and feed into `recon-wcd`'s
  path-confusion/cacheability-flip probe (same underlying class — req.url-based cache-key
  confusion — not a new tool).
- Not KEV, no public exploit as of 2026-07-21.
- Source: https://github.com/advisories/GHSA-m9gq-cmcj-p62x, https://security.glexia.com/cves/CVE-2026-34475

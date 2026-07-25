# PROPOSAL (proposal) for docs/knowledge/tech-varnish.md — vulns 2026-07-25
_Review and apply manually; not auto-merged into the KB._

## CVE-2026-34475 — auth-bypass / cache-poisoning via unchecked req.url (added 2026-07-25)
- CWE-180 (validate-before-canonicalize). Absolute-form HTTP/1.1 URIs with a **root path (`/` only)** get
  passed unchecked from `req.url` to a backend that accepts absolute-form URIs — can poison cache or
  bypass URL-based ACLs. Non-root paths (`/whatever`) are NOT affected — narrow attack surface.
- Affected: Varnish Cache ≤ 8.0.0, Varnish 6.0 LTS ≤ 6.0.16, Varnish Enterprise ≤ 6.0.16r11.
- Fixed: Varnish Cache 8.0.1 / 6.0 LTS 6.0.17 / Enterprise 6.0.16r12 / Vinyl Cache 9.0.
- Detect: `Via`/`X-Varnish` headers for version. Test via `recon_wcd.sh`-style differential probe with our
  own cache-buster key against the root path specifically — never against production traffic.
- Source: https://vinyl-cache.org/security/VSV00018.html

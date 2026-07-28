# PROPOSAL (proposal) for docs/knowledge/tech-varnish.md — vulns 2026-07-28
_Review and apply manually; not auto-merged into the KB._

## CVE-2026-34475 — absolute-form root-URL auth-bypass/cache-poisoning
- CWE-180 (validate-before-canonicalize): Varnish mishandles HTTP/1.1 absolute-form requests
  whose path is exactly `/` (`GET http://host/ HTTP/1.1`) when `req.url` passes unchecked to a
  backend accepting absolute-form URIs. Attack surface is root-URL only, not arbitrary paths.
- Affected: Varnish Cache < 8.0.1 and < 6.0.17 LTS; Varnish Enterprise < 6.0.16r12.
- Fixed: 8.0.1 / 6.0.17 LTS / Enterprise 6.0.16r12.
- Detect: `Via: varnish` / `X-Varnish` headers fingerprint Varnish; version rarely banner-disclosed
  — treat as version-unknown LEAD unless a version string leaks elsewhere (VCL error page, backend
  passthrough). Confirmation requires an absolute-form root-URL request diffed against cache
  behavior — this is a live cache-poisoning test against production traffic, so it's human-confirm
  on an owned test path only, never autonomous (out of bounds for the cache-buster-only safe probe).
- Source: https://vinyl-cache.org/security/VSV00018.html, https://github.com/advisories/GHSA-m9gq-cmcj-p62x

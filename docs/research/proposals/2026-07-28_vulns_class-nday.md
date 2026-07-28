# PROPOSAL (proposal) for docs/knowledge/class-nday.md — vulns 2026-07-28
_Review and apply manually; not auto-merged into the KB._

## 2026-07-28 addition — CVE-2026-23918 corrected to UNAUTHENTICATED (Apache HTTP/2 double-free)
Prior note (2026-07-25) incorrectly gated this behind authentication. Re-verified 2026-07-28: no auth
barrier stated in the vendor/advisory language.
- Affected: Apache HTTP Server 2.4.66 ONLY. Fixed: 2.4.67.
- RCE precondition: APR built with the `mmap` allocator (common on Debian-derived / default httpd
  Docker images) — not remotely fingerprintable.
- DoS precondition: `mod_http2` enabled + multi-threaded MPM (worker/event) — narrows via HTTP/2
  ALPN/alt-svc presence, still not conclusive.
- Detect: `Server: Apache/2.4.66` banner (often suppressed — absence = unknown, not clean).
- Doctrine: version-range LEAD only; do NOT run a crash/DoS probe (out of bounds for safe-probe —
  real availability impact). RCE path needs config we can't see externally either — LEAD, human-verify
  before any live test.
- Sources: https://security.berkeley.edu/news/critical-apache-2466-http2-flaw-allows-rce-dos-cve-2026-23918 ,
  https://www.cve.org/CVERecord?id=CVE-2026-23918

## 2026-07-28 addition — CVE-2026-34475 (Varnish Cache auth-bypass / cache poisoning)
- CWE-180: absolute-form root-path (`/`) HTTP/1.1 requests mishandled by `req.url` in VCL when passed
  unchecked to a backend accepting absolute-form URIs → cache poisoning or URL-based auth-check bypass.
  Surface is narrow: root path (`/`) only, not arbitrary paths.
- Affected: Varnish Cache < 8.0.1, 6.0 LTS < 6.0.17, Varnish Enterprise < 6.0.16r12. Fixed 2026-03-16.
- Detect: `Server: Varnish` / `X-Varnish` / `Via: varnish` headers; version rarely banner-disclosed →
  treat as version-unknown-in-range LEAD unless version is pulled from elsewhere (admin/CLI banner).
- Safe test: absolute-form `GET http://<host>/ HTTP/1.1` with OUR OWN cache-buster (same discipline as
  recon_wcd.sh) — never test against the live shared cache key.
- Fits existing WCD lane (recon_wcd.sh) as a Varnish-specific version-gated check, not a new tool.
- Sources: https://www.sentinelone.com/vulnerability-database/cve-2026-34475/ ,
  https://github.com/advisories/ghsa-m9gq-cmcj-p62x

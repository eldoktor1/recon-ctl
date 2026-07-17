# PROPOSAL (proposal) for docs/knowledge/class-cache-deception.md — vulns 2026-07-17
_Review and apply manually; not auto-merged into the KB._

## 2026-07 — Varnish CVE-2026-34475: real auth-bypass/cache-poison primitive (not just Info-FP)

CVE-2026-34475 (Varnish Cache < 8.0.1, Varnish Enterprise < 6.0.16r12): improper validate-before-canonicalize
handling (CWE-180) of a request whose URL path is exactly `/` for HTTP/1.1 — mishandling can lead to cache
poisoning or auth bypass. This is a genuine cacheability-flip primitive matching our WCD lane's confirm bar
(not the by-design-CDN FP pattern). Fingerprint via `Via: 1.1 varnish` / `X-Varnish` response headers, then
test the bare-`/`-path differential the same way `recon_wcd.sh` tests other path-confusion variants — unique
per-host cache-buster, never touch the shared cache. Fixed: 8.0.1 (OSS) / 6.0.16r12 (Enterprise) — version-gate
before treating as more than a LEAD.

Sources: https://nvd.nist.gov/vuln/detail/CVE-2026-34475 , https://github.com/advisories/GHSA-m9gq-cmcj-p62x

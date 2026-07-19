# PROPOSAL (proposal) for docs/knowledge/tech-nginx.md — vulns 2026-07-19
_Review and apply manually; not auto-merged into the KB._

## CVE-2026-42533 / CVE-2026-60005 / CVE-2026-56434 — nginx 1.30.4/1.31.3 security release (added 2026-07-19)
- CVE-2026-42533 (critical): heap buffer overflow in `map` directive regex-capture handling under
  crafted HTTP requests → worker crash / possible RCE if ASLR disabled. Affected 0.9.6-1.31.2
  (our observed nginx:1.29.7 fingerprint is in-range). Config-dependent (needs a specific vulnerable
  `map` construct referencing captures before the output var) — unauth probing can't confirm the
  config, so treat a bare version match as LEAD only.
- CVE-2026-60005 (medium, memory disclosure via `ngx_http_slice_module`) and CVE-2026-56434 (medium,
  UAF via `ngx_http_ssi_module`) share the same version band (1.15.8-1.31.2 / 0.8.11-1.31.2).
- Fixed: nginx-1.30.4 stable, nginx-1.31.3 mainline.
- Source: https://socprime.com/blog/cve-2026-42533-analysis/ , https://nginx.org/en/CHANGES

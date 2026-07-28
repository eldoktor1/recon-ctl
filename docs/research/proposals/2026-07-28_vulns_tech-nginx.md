# PROPOSAL (proposal) for docs/knowledge/tech-nginx.md — vulns 2026-07-28
_Review and apply manually; not auto-merged into the KB._

## 2026-07-28 update — two more module-gated CVEs on the 1.30.4/1.31.3 patch train
- **CVE-2026-60005** (ngx_http_slice_module, uninitialized memory disclosure, CVSS v4 8.8): requires `--with-http_slice_module` build + `slice` directive with unnamed regex captures, or a background cache update. Vulnerable 1.15.8–1.31.2.
- **CVE-2026-56434** (ngx_http_ssi_module, use-after-free, CVSS v4 8.3): requires SSI + `proxy_pass` + `proxy_buffering off` + attacker-manipulable upstream response. Vulnerable 0.8.11–1.31.2. No workaround besides upgrade.
- Both fixed in the same train as CVE-2026-42533/42945: nginx 1.30.4 (stable) / 1.31.3 (mainline) / NGINX Plus 37.0.3.1. A host still on `nginx/1.29.7` (our fingerprinted version) is in-range for the whole cluster (42533, 42945, 42926, 42946, 42934, 40460, 40701, 60005, 56434).
- CVE-2026-42533 exploitation is now described as "confirmed practical, observed in the wild" in multiple July sources — still version-banner-only detection, still LEAD-not-P0 per doctrine (no safe external trigger exists).
- Sources: https://orca.security/resources/blog/cve-2026-42533-nginx-heap-buffer-overflow/ , https://beazley.security/alerts-advisories/critical-memory-corruption-vulnerabilities-in-nginx-cve-2026-42533-cve-2026--56434-cve-2026-60005

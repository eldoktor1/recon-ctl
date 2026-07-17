# PROPOSAL (proposal) for docs/knowledge/tech-nginx.md — vulns 2026-07-17
_Review and apply manually; not auto-merged into the KB._

## 2026-07 — "Rift" wave: 3 stacked pre-auth heap-overflow CVEs (add to fingerprint/version table)

Our ES top-tech shows an exact running version `Nginx:1.29.7` — this IS in-range for two of the three below.

| CVE | Component | Affected | Fixed | Notes |
|---|---|---|---|---|
| CVE-2026-42945 ("NGINX Rift") | ngx_http_rewrite_module | 0.6.27–1.30.0 (OSS), Plus R32–R36 | 1.30.1 / 1.31.0 | Unauth heap overflow; DoS reliable, RCE only w/o ASLR. Needs unnamed-capture (`$1`/`$2`) + `?` in replacement + chained rewrite/if/set in config — version match alone is a LEAD, not confirmation. CVSS 9.2. |
| CVE-2026-9256 | ngx_http_rewrite_module (2nd overflow, overlapping captures) | 0.1.17–1.31.0 | 1.30.2 / 1.31.1+ | NOT closed by patching Rift — separate fix required. |
| CVE-2026-8711 | njs js_fetch_proxy | njs 0.9.4–0.9.8 | njs 0.9.9 | Only relevant if njs module + `ngx.fetch()` w/ client-controlled URL var is in use. |

Detection for unauth recon: version-fingerprint via `Server:` header (often suppressed — absence ≠ safe) to flag LEAD candidates in range; config-pattern (rewrite chain) can't be confirmed unauth without probing response-length/500 differentials on crafted `?`-bearing paths — treat as version-only LEAD until that differential is built.

Sources: https://nvd.nist.gov/vuln/detail/CVE-2026-42945 , https://lilting.ch/en/articles/nginx-njs-8711-rewrite-9256-second-wave , https://almalinux.org/blog/2026-05-13-nginx-rift-cve-2026-42945/

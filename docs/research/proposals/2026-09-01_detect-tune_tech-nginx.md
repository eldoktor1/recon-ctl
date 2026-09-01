# PROPOSAL (proposal) for docs/knowledge/tech-nginx.md — detect-tune 2026-09-01
_Review and apply manually; not auto-merged into the KB._

## 2026-09-01 update — two in-range CVEs for our fingerprinted Nginx:1.29.7

- **CVE-2026-42926** (HTTP/2 request injection via `ngx_http_proxy_module`, CVSS 5.8): affected 1.29.4–1.30.0
  (fixed 1.31.0+/1.30.1+). Requires `proxy_http_version 2` + `proxy_set_body` upstream config — not remotely
  visible, so a version match is LEAD-only. Confirm needs an active HTTP/2 desync differential probe
  (operator-reviewed, not unattended). Source: https://nginx.org/en/security_advisories.html
- **CVE-2026-42055** (heap overflow, `ngx_http_proxy_v2_module`/`ngx_http_grpc_module`, CVSS 8.1/9.2): version
  range DISPUTED between sources — ZeroPath says mainline 1.31.1 + stable 1.30.0–1.30.2; an nginx.org summary
  said 1.13.10–1.31.1 (which would include 1.29.x). ⚠️ NVD-verify before treating any 1.29.x host as in-range.
  Requires `ignore_invalid_headers off` + `large_client_header_buffers` >2MB + HTTP/2 proxy/grpc — not remotely
  visible, LEAD-only.
- **Action for `recon_nday.sh`:** add both CVE IDs to the version-gate table keyed on nginx banner version;
  since neither has a safe unauth confirm primitive, they mint LEAD (never P0) purely on version match, same
  as the existing KEV-unverified-version clamp.

# PROPOSAL (proposal) for docs/knowledge/tech-nginx.md — vulns 2026-07-01
_Review and apply manually; not auto-merged into the KB._

## Recent CVEs (add to Vulnerabilities section)

### CVE-2026-42530 — HTTP/3 UAF (NGINX 1.31.0–1.31.1)
- **CVSS:** 9.2 | Unauth: YES (requires HTTP/3 active)
- **Vector:** UAF in `ngx_http_v3_module` on QPACK encoder stream reopening
- **Fingerprint:** `Server: nginx/1.31.{0,1}` **AND** `Alt-Svc: h3=":443"` — both required
- **Patch:** 1.31.2
- **Source:** https://thehackernews.com/2026/06/f5-patches-two-critical-nginx-open.html

### CVE-2026-42055 — HTTP/2 heap overflow (NGINX 1.30.x, 1.31.1)
- **CVSS:** 9.2 | Unauth: CONDITIONAL (non-default config triple required)
- **Vector:** `ngx_http_proxy_v2_module` / `ngx_http_grpc_module` heap overflow via HPACK
- **Config triple (all required):** `proxy_http_version 2` OR `grpc_pass`; `ignore_invalid_headers off`; `large_client_header_buffers > 2MB`
- **Fingerprint:** Version in `Server:` + `content-type: application/grpc` in responses (gRPC = higher-prob config hit)
- **Patch:** 1.30.3 / 1.31.2; Plus R36 P6 / 37.0.2.1
- **Source:** https://thehackernews.com/2026/06/f5-patches-two-critical-nginx-open.html

### Unverified — NGINX rewrite module RCE (no confirmed CVE as of 2026-07-01)
- "18-year-old" rewrite flaw claimed; version range unconfirmed. Do NOT act. Verify at NVD.
- Source: https://thehackernews.com/2026/05/18-year-old-nginx-rewrite-module-flaw.html

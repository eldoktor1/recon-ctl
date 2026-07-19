# PROPOSAL (proposal) for docs/knowledge/tech-nginx.md — vulns 2026-07-17
_Review and apply manually; not auto-merged into the KB._

## 2026-07 CVE batch (added by research routine, 2026-07-17)
A cluster of nginx CVEs disclosed/exploited May–June 2026, all version-reasoned LEADs (confirm `Server` header version AND, where noted, the specific vulnerable directive/module usage — tech-class match alone is not enough per our KEV-FP doctrine):
- **CVE-2026-42945** (CVSS 9.2, ACTIVELY EXPLOITED) — heap overflow in `ngx_http_rewrite_module`, versions 0.6.27–1.30.0. Requires a `rewrite`/`if`/`set` directive with an unnamed PCRE capture (`$1`/`$2`) whose replacement contains `?`. RCE needs ASLR off; otherwise worker-crash DoS. Not detectable via banner alone — needs config-behavior confirmation (rewrite-driven URL transform visible in responses).
- **CVE-2026-42530** — use-after-free in `ngx_http_v3_module` (HTTP/3 — we track HTTP/3 as in-scope top tech; check `Alt-Svc: h3` header presence as a precondition signal).
- **CVE-2026-42055** — heap overflow, `ngx_http_proxy_v2_module`/`ngx_http_grpc_module`.
- **CVE-2026-8711** — `ngx_http_js_module`. **CVE-2026-9256** — `ngx_http_rewrite_module` (distinct from -42945). **CVE-2026-40701** — resolver UAF (OCSP). **CVE-2026-27654** — `ngx_http_dav_module` overflow (WebDAV-enabled hosts only).
Sources: https://thehackernews.com/2026/05/nginx-cve-2026-42945-exploited-in-wild.html , https://nginx.org/en/security_advisories.html

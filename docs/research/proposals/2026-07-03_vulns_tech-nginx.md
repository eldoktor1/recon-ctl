# PROPOSAL (proposal) for docs/knowledge/tech-nginx.md — vulns 2026-07-03
_Review and apply manually; not auto-merged into the KB._

## N-Day CVEs — 2026

### CVE-2026-42945 ("NGINX Rift") — Heap Overflow, ngx_http_rewrite_module
- **Affected:** NGINX Open Source 0.6.27–1.30.0; Plus R32–R36
- **Fixed:** 1.31.0 / 1.30.1
- **Class:** Heap buffer overflow (DoS / RCE)
- **Config dependency:** Only exploitable when a `rewrite` directive uses unnamed PCRE captures (`$1`/`$2`) with a `?` in the replacement AND another `rewrite`/`if`/`set` follows. Version alone = LEAD; config confirmation needed for CONFIRMED.
- **Fingerprint (unauth):** `Server: nginx/<version>` — any ≤ 1.30.0 in range.
- **PoC:** https://github.com/depthfirstdisclosures/nginx-rift
- **KEV/exploitation status:** Exploited in wild; not yet formally added to KEV as of 2026-07-03.

### CVE-2026-9256 — Buffer Overflow, ngx_http_rewrite_module
- **Affected:** NGINX 0.1.17–1.31.0; fixed in 1.31.1 / 1.30.2
- Same config-dependency as CVE-2026-42945. Broader version range.

### CVE-2026-42530 — Use-After-Free in HTTP/3 (QUIC)
- **Affected:** NGINX 1.31.0–1.31.1 ONLY; fixed in 1.31.2
- **Fingerprint:** `Alt-Svc: h3` response header (HTTP/3 support advertised)
- Very narrow range; flag only if version exactly 1.31.0–1.31.1.

**Source:** https://nginx.org/en/security_advisories.html

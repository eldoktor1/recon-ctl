# PROPOSAL (proposal) for docs/knowledge/tech-nginx.md — vulns 2026-06-21
_Review and apply manually; not auto-merged into the KB._

## CVE-2026-42945 — "NGINX Rift" — Heap Buffer Overflow in Rewrite Module (CVSS 9.2)
**Affected:** NGINX Open Source 0.6.27–1.30.0 (fixed 1.31.0+); NGINX Plus R32–R36 (fixed R37+); also F5 Ingress Controller, Gateway Fabric, Instance Manager, App Protect WAF/DoS.
**Mechanism:** Size mismatch between PCRE capture escaping passes in `ngx_http_rewrite_module` when unnamed captures (`$1`,`$2`) appear with `?` in the replacement string followed by another `rewrite`/`if`/`set` directive. Crafted HTTP request crashes the worker (reliable DoS); RCE when ASLR disabled.
**Detect (unauth, safe):** `curl -sI <host> | grep -i server` → `nginx/1.X.Y` where Y ≤ 30 = LEAD. Version-only — do NOT send crash-trigger payload (destructive).
**Our surface note:** `Nginx:1.29.7` is in top-tech data — all such hosts are in-range LEADs.
**Sources:** https://almalinux.org/blog/2026-05-13-nginx-rift-cve-2026-42945/ | https://my.f5.com/manage/s/article/K000161019

## CVE-2026-47774 — HTTP/2 HPACK Bomb — Multi-Server DoS (CVSS 7.5)
**Affected:** NGINX < 1.29.8; Apache mod_http2 < 2.0.41; IIS (June 2026 Patch Tuesday); Envoy < 1.35.11/1.36.7/1.37.3/1.38.1. Cloudflare Pingora: NOT affected.
**Mechanism:** HPACK decompression: 1 wire byte → 1 full header allocation; combined with zero-byte flow-control window → memory exhaustion DoS.
**Detect:** `curl --http2 -sI <host>` confirms HTTP/2; Server header version check. `Nginx:1.29.7` is in-range.
**Bounty value:** LOW — DoS-only class rarely paid. Include in n-day data but deprioritize for reporting.
**Source:** https://thehackernews.com/2026/06/new-http2-bomb-vulnerability-allows.html

## CVE-2026-8711 — NGINX JavaScript (njs) Module Heap Buffer Overflow
**Affected:** njs module (version range: see F5 advisory K000161307).
**Mechanism:** Heap-based buffer overflow → unauthenticated RCE/DoS.
**Detect:** `js_` directives in nginx config expose the njs attack surface. Version fingerprint via Server header. Error responses may reveal njs.
**Source:** https://my.f5.com/manage/s/article/K000161307

## CVE-2026-42530 — NGINX HTTP/3 (QUIC) Use-After-Free
**Affected:** ngx_http_v3_module; hosts with HTTP/3/QUIC enabled.
**Detect:** `curl -sI <host> | grep -i alt-svc` → `alt-svc: h3` header confirms QUIC exposure. Only QUIC-enabled hosts are in-range.
**Source:** https://my.f5.com/manage/s/article/K000161616

# Nginx — Security Fingerprints, CVEs, and n-day Detection

## Version Detection (primary fingerprint)

- `Server: nginx/X.Y.Z` response header (most reliable; many hosts leave it exposed)
- `/nginx_status` (stub_status module; often unauth-accessible on dev/admin vhosts)
- Error pages: default Nginx 404/50x pages contain `nginx/X.Y.Z` in footer
- Wappalyzer/Shodan: `http.component:"nginx"` + version extraction

## Active CVEs (version-reasoned, 2026)

### CVE-2026-42945 "NGINX Rift" ★ HIGH PRIORITY
- **Class:** Heap buffer overflow in `ngx_http_rewrite_module`
- **Affected:** Open Source 0.6.27 – 1.30.0 / Plus R32–R36
- **Patched:** Open Source 1.30.1 / 1.31.0; Plus R36 P1 / R37
- **Conditions:** Non-default config required (exact directive TBD from F5 advisory); RCE needs ASLR disabled; DoS unconditional once config met
- **Exploitation status:** Public PoC released at disclosure (May 2026); active exploitation confirmed against honeypots within 4 days
- **KEV status:** Likely added or imminent (in-wild confirmed)
- **Detection:** `Server: nginx/` < 1.30.1 → in-range; confirm with `recon-nday`
- **Source:** https://beazley.security/alerts-advisories/critical-18-year-old-rce-vulnerability-in-nginx-aka-nginx-rift-cve-2026-42945

### CVE-2026-42530 (HTTP/3 Use-After-Free)
- **Affected:** Open Source 1.31.0 – 1.31.1 only (HTTP/3/QUIC must be configured)
- **Patched:** 1.31.2
- **Conditions:** `ngx_http_v3_module` active; crafted HTTP/3 session; RCE only with ASLR bypassed
- **Source:** https://securityonline.info/nginx-vulnerabilities/

### CVE-2026-42055 (HTTP/2 Heap Overflow)
- **Affected:** Open Source 1.30.x / 1.31.x; Plus < R36 P6 / 37.0.2.1
- **Patched:** 1.30.3 / 1.31.2 / Plus R36 P6 / 37.0.2.1
- **Conditions:** All three non-default configs required: `grpc_pass` or `proxy_http_version 2` + `ignore_invalid_headers off` + `large_client_header_buffers` > 2MB — rare combination
- **Source:** https://securityonline.info/nginx-vulnerabilities/

## Hunting Dorks / Queries

- Shodan: `http.component:"nginx" version:<1.30.1`
- FOFA: `header="Server: nginx" && header="nginx/1.2" || header="nginx/1.29"`
- ES query: `tech:"nginx"` + version range; `jsintel` crawl headers for `Server:` value

## False Positive Notes

- CDN-fronted hosts (Cloudflare, Akamai) may proxy to Nginx backends but report CDN headers externally — portscan/version results are meaningless on CDN-fronted hosts.
- Nginx version string in `X-Powered-By` or custom error pages may lag behind actual version (staged rollout).


---
<!-- applied-proposal: 2026-06-21_vulns_tech-nginx -->
### Applied research — vulns (2026-06-21)

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


---
<!-- applied-proposal: 2026-06-25_vulns_tech-nginx -->
### Applied research — vulns (2026-06-25)

## CVEs — Active 2026

### CVE-2026-42945 — Heap Buffer Overflow in `ngx_http_rewrite_module` (CVSS 9.2)
- **Affected:** Nginx 0.6.27–1.30.0 (rewrite module is default-enabled)
- **Patched:** 1.30.1+
- **Fingerprint (unauth):** `Server: nginx/1.30.0` or earlier. Version parse from HEAD response. Any instance in range is a candidate — no config uncertainty since rewrite module is on by default.
- **Action:** n-day lane; LEAD from version detect; do NOT trigger actual overflow (destructive). File with `recon_nday.sh`.
- **Source:** https://thehackernews.com/2026/05/nginx-cve-2026-42945-exploited-in-wild.html

### CVE-2026-42530 — HTTP/3 Use-After-Free in `ngx_http_v3_module` (Critical, possible RCE)
- **Affected:** Nginx < 1.31.2 **with HTTP/3 enabled** (non-default — only `alt-svc: h3` hosts in range)
- **Patched:** 1.31.2+
- **Fingerprint (unauth):** `alt-svc: h3=":443"` response header + `Server: nginx/1.30.x` or earlier. HTTP/3-enabled Nginx is rare → low dup density.
- **Detect:** `curl -sI https://<host> | grep alt-svc` for h3 presence.
- **Action:** n-day LEAD; very high-value/low-volume. Source: https://socprime.com/blog/cve-2026-42530-critical-nginx-http-3-flaw-can-trigger-dos-and-possible-rce/

### CVE-2026-49975 — HTTP/2 Bomb (HPACK amplification, CVSS 7.5+)
- **Affected:** Nginx < 1.29.8; Apache mod_http2 < 2.0.41. Cloudflare Pingora unaffected (architecture).
- **Fingerprint (unauth):** `HTTP/2` in response + `Server: nginx/1.28.x` or `Apache/2.4.x` unpatched. 880k+ public servers exposed at disclosure.
- **Detect:** `curl -sI --http2 https://<host>` — HTTP/2 in response line = speaks HTTP/2.
- **Caveat:** DoS-class bug — confirm program pays for DoS/n-day before investing. Trigger is destructive; pipeline stops at version-detect LEAD.
- **Source:** https://thehackernews.com/2026/06/new-http2-bomb-vulnerability-allows.html


---
<!-- applied-proposal: 2026-06-30_detect-tune_tech-nginx -->
### Applied research — detect-tune (2026-06-30)

## Off-by-Slash Alias Traversal

**Vulnerability pattern:** `location /static { alias /srv/static/; }` — missing trailing slash on `location` block. Nginx concatenates the URI suffix directly, enabling `../` traversal one level up.

**Probe (on-demand, add to `recon-params crawl-host` post-crawl):**
```bash
# Detect traversal
curl -s -o /dev/null -w "%{http_code}" "https://<host>/static../"
# 200 (same as /static/) → vulnerable; try:
curl "https://<host>/static../.git/config"
curl "https://<host>/static../etc/passwd"


---
<!-- applied-proposal: 2026-07-01_vulns_tech-nginx -->
### Applied research — vulns (2026-07-01)

## CVE-2026-42945 "NGINX Rift" — Heap Buffer Overflow in ngx_http_rewrite_module

- **CVSS:** 9.2 (v4)
- **Affected:** Nginx Open Source 0.6.27–1.30.0; Plus R32–R36
- **Fixed:** 1.30.1 / 1.31.0 (Open Source); R32 P6 / R36 P4 (Plus)
- **Class:** Heap buffer overflow → reliable DoS; RCE if ASLR disabled or via LFI chain (PoC public)
- **Auth required:** None

### Vulnerable config pattern
```nginx
# VULNERABLE: unnamed PCRE capture + ? in replacement
rewrite ^/(.*)$ /index.php?$1 last;

# SAFE: named capture
rewrite ^/(?P<path>.*)$ /index.php?$path last;
```

### Applied research — vulns (2026-07-03)

## CVE-2026-9256 — Buffer Overflow in `ngx_http_rewrite_module`
- **Affected:** Nginx 0.1.17–1.31.0; **Fixed:** 1.31.1 / 1.30.2 — broader range than "Rift".
- **Class:** Buffer overflow (DoS / possible RCE). **Same config-dependency as CVE-2026-42945**: needs an
  unnamed PCRE capture (`$1`/`$2`) + `?` in the replacement, followed by another `rewrite`/`if`/`set`.
  **Version alone = LEAD; vulnerable-config confirmation required for CONFIRMED.**
- **Fingerprint (unauth):** `Server: nginx/<version>` ≤ 1.31.0.
- **Source:** https://nginx.org/en/security_advisories.html

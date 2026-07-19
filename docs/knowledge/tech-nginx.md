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
```

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


---
<!-- applied-proposal: 2026-07-11_vulns_tech-nginx + 2026-07-17_vulns_tech-nginx -->
### Applied research — vulns (2026-07-11 / 2026-07-17) — "Rift wave" consolidation + detection caveats

The three-CVE May-2026 "Rift" wave, consolidated (mostly detailed above — new here: version-range nuance
per CVE, PoC pointer, and the `server_tokens` detection caveat). Our ES top-tech shows an exact running
`Nginx:1.29.7` — IN RANGE for CVE-2026-42945 and CVE-2026-9256.

| CVE | Component | Affected | Fixed | Notes |
|---|---|---|---|---|
| CVE-2026-42945 ("NGINX Rift") | ngx_http_rewrite_module | 0.6.27–1.30.0 (OSS) / Plus R32–R36 | 1.30.1 / 1.31.0 (OSS); R32 P6 / R36 P4 (Plus) | Unauth heap overflow; DoS reliable, RCE only w/o ASLR. Config-gated (unnamed capture `$1`/`$2` + `?` in replacement + chained `rewrite`/`if`/`set`) → **version match alone = LEAD**. CVSS 9.2. Public PoC: github.com/depthfirstdisclosures/nginx-rift (verify vs source). |
| CVE-2026-9256 | ngx_http_rewrite_module (2nd overflow, overlapping captures) | 0.1.17–1.31.0 | 1.30.2 / 1.31.1+ | **NOT closed by patching Rift — separate fix required.** Same rewrite-config dependency as 42945. |
| CVE-2026-8711 | njs `js_fetch_proxy` / `ngx.fetch()` | njs 0.9.4–0.9.8 *(njs version range — verify vs F5 advisory K000161307)* | njs 0.9.9 | Only relevant if njs module in use AND `ngx.fetch()` called with a client-controlled URL var. Heap overflow → RCE/DoS. |

**Detection caveat (reusable):** `Server:`/error-page banner is the primary version fingerprint, but
`server_tokens off` suppresses it — **absence of a version banner ≠ clean/safe**; treat unbannered Nginx
hosts as unknown-version, not patched. The rewrite-config dependency (42945/9256) can't be confirmed
unauth from the version alone; a genuine CONFIRMED needs a safe non-destructive differential
(response-length / 500 on crafted `?`-bearing paths) — never a blind RCE/crash payload. Until that
differential is built, in-range version = LEAD only.

**Sources:** https://nvd.nist.gov/vuln/detail/CVE-2026-42945 · https://my.f5.com/manage/s/article/K000161019 ·
https://almalinux.org/blog/2026-05-13-nginx-rift-cve-2026-42945/ ·
https://lilting.ch/en/articles/nginx-njs-8711-rewrite-9256-second-wave *(2nd source obscure — CVE IDs/ranges verify vs NVD)*


---
<!-- applied-proposal: 2026-07-18_vulns_tech-nginx + 2026-07-19_vulns_tech-nginx -->
### Applied research — vulns (2026-07-18 / 2026-07-19) — full version table + 1.30.4/1.31.3 release

## 2026 CVE version table (as of 2026-07-18)

Our current in-scope fingerprint includes exact version `nginx/1.29.7`. Full nginx.org advisory table,
fixed-in vs vulnerable-range:

| CVE | Issue | Fixed In | Vulnerable |
|-----|-------|----------|-----------|
| CVE-2026-42533 | Buffer overflow (map + regex) | 1.31.3+, 1.30.4+ | 0.9.6-1.31.2 |
| CVE-2026-60005 | Memory disclosure (slice module) | 1.31.3+, 1.30.4+ | 1.15.8-1.31.2 |
| CVE-2026-56434 | Use-after-free (SSI module) | 1.31.3+, 1.30.4+ | 0.8.11-1.31.2 |
| CVE-2026-42530 | Use-after-free (HTTP/3) | 1.31.2+ | 1.31.0-1.31.1 |
| CVE-2026-42055 | Buffer overflow (proxy_v2/gRPC) | 1.31.2+, 1.30.3+ | 1.13.10-1.31.1 |
| CVE-2026-48142 | Buffer overread (charset module) | 1.31.2+, 1.30.3+ | 0.3.50-1.31.1 |
| CVE-2026-9256 | Buffer overflow (rewrite module) | 1.31.1+, 1.30.2+ | 0.1.17-1.31.0 |
| CVE-2026-42926 | HTTP/2 request injection (proxy module) | 1.31.0+, 1.30.1+ | 1.29.4-1.30.0 |
| **CVE-2026-42945** ("Rift") | Heap buffer overflow (rewrite), CVSS 9.2, ITW-exploited | 1.31.0+, 1.30.1+ | 0.6.27-1.30.0 |
| CVE-2026-42946 | Buffer overread (SCGI/uWSGI) | 1.31.0+, 1.30.1+ | 0.8.42-1.30.0 |
| CVE-2026-42934 | Buffer overread (charset module) | 1.31.0+, 1.30.1+ | 0.3.50-1.30.0 |
| CVE-2026-40460 | HTTP/3 address spoofing | 1.31.0+, 1.30.1+ | 1.25.0-1.30.0 |
| CVE-2026-40701 | Resolver use-after-free (OCSP) | 1.31.0+, 1.30.1+ | 1.19.0-1.30.0 |
| CVE-2026-27654/27784/32647/27651/28753/28755 | Various (DAV/mp4/CRAM-MD5/auth_http/stream OCSP) | 1.29.7+, 1.28.3+ | pre-1.29.7 |
| CVE-2026-1642 | SSL upstream injection | 1.29.5+, 1.28.2+ | 1.3.0-1.29.4 |

**Implication:** `nginx/1.29.7` (patched against the pre-1.29.7 batch) is STILL in-range for
CVE-2026-42945/42926/42946/42934/40460/40701 (all vulnerable through 1.30.0). CVE-2026-42945 is
config-dependent and unsafe to trigger (crashes the worker) — version-range LEAD only. CVE-2026-42926
(HTTP/2 request injection) is the most promising for a future safe differential-probe design.

## 2026-07-19 security release: nginx 1.30.4 stable / 1.31.3 mainline
- **CVE-2026-42533** (critical): heap buffer overflow in `map` directive regex-capture handling under
  crafted HTTP requests → worker crash / possible RCE if ASLR disabled. Affected 0.9.6-1.31.2;
  our observed `nginx:1.29.7` fingerprint is in-range. Config-dependent (needs a specific `map`
  construct referencing captures) — unauth probing can't confirm the config; treat bare version
  match as LEAD only.
- **CVE-2026-60005** (medium): memory disclosure via `ngx_http_slice_module` (1.15.8-1.31.2).
- **CVE-2026-56434** (medium): UAF via `ngx_http_ssi_module` (0.8.11-1.31.2).
- Fixed: nginx-1.30.4 stable, nginx-1.31.3 mainline.
- Sources: https://socprime.com/blog/cve-2026-42533-analysis/ , https://nginx.org/en/CHANGES ,
  https://nginx.org/en/security_advisories.html

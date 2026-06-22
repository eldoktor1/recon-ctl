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

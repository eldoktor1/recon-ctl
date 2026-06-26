# PROPOSAL (proposal) for docs/knowledge/tech-nginx.md — vulns 2026-06-25
_Review and apply manually; not auto-merged into the KB._

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

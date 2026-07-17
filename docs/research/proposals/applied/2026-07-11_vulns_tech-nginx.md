# PROPOSAL (proposal) for docs/knowledge/tech-nginx.md — vulns 2026-07-11
_Review and apply manually; not auto-merged into the KB._

## CVE-2026-42945 "NGINX Rift" — unauth heap overflow in ngx_http_rewrite_module (added 2026-07-11)
- Affects NGINX Open Source 1.0.0–1.30.0 (fixed 1.30.1/1.31.0), NGINX Plus R32–R36 (fixed R32 P6/R36 P4).
- Our corpus has a fingerprinted `Nginx:1.29.7` host(s) — IN RANGE. CVSSv4 9.2, public PoC (github.com/depthfirstdisclosures/nginx-rift).
- Trigger requires a specific server config (rewrite directive w/ unnamed capture `$1`/`$2`, `?` in replacement, followed by another rewrite/if/set in same scope) — NOT remotely fingerprintable from version alone. Version-in-range = LEAD only; escalate to CONFIRMED only via a safe non-destructive probe that reproduces the crash/overflow signal, never a blind RCE attempt.
- Detect version: `Server:`/error-page banner (often suppressed via `server_tokens off` — absence ≠ clean).
- Also from the same May 2026 F5 patch round (HTTP/2 & HTTP/3-only, unauth): CVE-2026-42530 (h3 UAF, CVSSv4 9.2) and CVE-2026-42055 (h2 HPACK heap overflow). Only relevant if Alt-Svc/h3 or h2 negotiated.
- Sources: https://thehackernews.com/2026/05/18-year-old-nginx-rewrite-module-flaw.html , https://my.f5.com/manage/s/article/K000161019 , https://nvd.nist.gov/vuln/detail/CVE-2026-42945

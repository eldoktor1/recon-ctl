# PROPOSAL (proposal) for docs/knowledge/tech-apache-http-server.md — vulns 2026-09-03
_Review and apply manually; not auto-merged into the KB._

## CVE-2026-34356 — mod_proxy_http heap overflow via ProxyPassReverseCookie (added 2026-09-03)
Heap buffer overflow in `ProxyPassReverseCookieDomain`/`ProxyPassReverseCookiePath` cookie-rewrite logic:
an oversized `Set-Cookie` Domain/Path attribute from the **backend** overflows a heap buffer during rewrite.
CVSS 7.5. Affected 2.4.0–2.4.67, fixed 2.4.68. Attacker needs influence over the reverse-proxied backend's
response (compromised origin or a chained SSRF/response-injection) — not a direct external unauth primitive.
Detect: `Server: Apache/2.4.x` header, version-in-range only, no safe way to confirm exploitability remotely.
Version-match ⇒ LEAD per KEV/version doctrine, do not attempt to trigger (crashes the worker).
Source: https://www.sentinelone.com/vulnerability-database/cve-2026-34356/

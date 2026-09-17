# PROPOSAL (proposal) for docs/knowledge/tech-apache-http-server.md — vulns 2026-09-17
_Review and apply manually; not auto-merged into the KB._

## CVE-2026-34356 — mod_proxy_http ProxyPassReverseCookie heap overflow (added 2026-09-17)
- Affects Apache HTTP Server 2.4.0 – 2.4.67; fixed 2.4.68.
- Trigger: `ProxyPassReverseCookie` directive + malicious backend response → heap buffer overflow (DoS, potential RCE).
- Detect: `Server: Apache/2.4.x` (x<68) = version-in-range LEAD only; `ProxyPassReverseCookie` usage is not remotely visible, so this never promotes past LEAD without config knowledge. Do not attempt to trigger (destructive/crash primitive).
- Source: https://www.sentinelone.com/vulnerability-database/cve-2026-34356/

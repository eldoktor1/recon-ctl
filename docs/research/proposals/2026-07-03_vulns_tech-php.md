# PROPOSAL (proposal) for docs/knowledge/tech-php.md — vulns 2026-07-03
_Review and apply manually; not auto-merged into the KB._

## N-Day CVEs — 2026

### CVE-2026-6722 — SOAP Extension Use-After-Free (CVSS 9.5)
- **Affected:** PHP 8.2.x < 8.2.31, 8.3.x < 8.3.31, 8.4.x < 8.4.21, 8.5.x < 8.5.6. NOT 7.x or 8.1.x.
- **Fixed:** May 7, 2026
- **Class:** Use-after-free in SOAP object deduplication on `apache:Map` duplicate keys → unauthenticated RCE against any exposed SOAP endpoint.
- **Fingerprint (unauth):** `X-Powered-By: PHP/8.2–8.5` header + GET `<path>?wsdl` returning XML = SOAP endpoint exposed. Both required for CONFIRMED exposure; version alone = LEAD.
- **Pipeline:** PoC circulating post-patch. Treat as LEAD until `?wsdl` confirmed accessible.
- **Sources:** https://securityonline.info/php-security-patch-rce-soap-cve-2026-6722/ · https://pinaka.sh/blog/cve-2026-6722-php-soap-use-after-free-rce/

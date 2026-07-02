# PROPOSAL (proposal) for docs/knowledge/tech-php.md — vulns 2026-07-01
_Review and apply manually; not auto-merged into the KB._

## CVE-2026-6722 — PHP SOAP Extension Use-After-Free RCE (CVSS 9.5)

- **Affected:** PHP < 8.2.31, < 8.3.31, < 8.4.21, < 8.5.6
- **Fixed:** 8.2.31 / 8.3.31 / 8.4.21 / 8.5.6
- **Class:** Use-after-free in SOAP extension object deduplication → arbitrary write → RCE
- **Auth required:** None — if SOAP endpoint accepts unauthenticated traffic

### Detection fingerprint
- Probe for WSDL endpoints: `/?wsdl`, `/soap`, `/api/soap`, `/services/*.php?wsdl`
- JS/jsintel: `SoapClient`, `soapClient`, `wsdl` references in endpoint output
- PHP version via `X-Powered-By: PHP/X.Y.Z` or error pages → confirm < patched branch
- Worker crashes (PHP-FPM segfaults after SOAP traffic) — observable in monitoring but not recon

### In-scope action
SOAP endpoint found + PHP version confirmed unpatched → LEAD. Do NOT send malformed SOAP body (exploitation, not detection). Version + endpoint = submittable n-day LEAD for programs that reward infra CVEs.

Sources: [cybersecuritynews](https://cybersecuritynews.com/php-soap-extension-vulnerabilities/) · [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-6722)

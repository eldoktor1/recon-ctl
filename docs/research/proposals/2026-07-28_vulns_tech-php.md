# PROPOSAL (proposal) for docs/knowledge/tech-php.md — vulns 2026-07-28
_Review and apply manually; not auto-merged into the KB._

## CVE-2026-7261 — SoapServer SOAP_PERSISTENCE_SESSION UAF (CVSS 9.8)
Companion bug to CVE-2026-6722 (apache:Map object-dedup UAF), same PHP security release.
- Root cause: SoapServer frees the persisted handler object on an erroring SOAP request but
  retains a dangling pointer; a follow-up request reuses freed memory → corruption/info-leak/crash,
  RCE-capable.
- Affected: PHP 8.2.x < 8.2.31, 8.3.x < 8.3.31, 8.4.x < 8.4.21, 8.5.x < 8.5.6 (any app with
  SoapServer + SOAP_PERSISTENCE_SESSION enabled).
- Detect unauth: `?wsdl`, `Content-Type: text/xml`/`application/soap+xml`, `SOAPAction` header,
  or WSDL file in jsintel/fulltext corpus + PHP version disclosure. Persistence-mode config isn't
  remotely fingerprintable → SOAP endpoint + in-range version = LEAD, not confirmed.
- Note: internet-wide scanning for this class spiked within 72h of the 2026-07 patch release
  (BitNinja) — treat any hit as time-sensitive.
- Source: https://www.sentinelone.com/vulnerability-database/cve-2026-7261/

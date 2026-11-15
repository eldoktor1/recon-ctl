# Magento / Adobe Commerce

## Fingerprinting (unauth, passive)
- Cookies: `Mage-Cache-Sessid`, `Mage-Messages`, `PHPSESSID` alongside `X-Magento-*` response headers
- `<meta name="generator" content="Magento...">` in page source (often stripped in hardened installs)
- Static asset paths: `/media/catalog/product`, `/static/version<N>/frontend/...`, `/skin/frontend/...` (older builds)
- Admin login page asset query-strings sometimes leak a version/build hash
- No safe unauth version-disclosure endpoint is publicly documented as of 2026-09; version confirmation generally requires authenticated/admin access or leaked `composer.lock`/`RELEASE_NOTES.md`

## CVE-2026-75650 "StyleSmuggler" — unauth RCE, CVSS 10.0
- Unauthenticated template/style-injection in Magento's rendering + failed-payment email pathway → arbitrary PHP execution
- Affected: Adobe Commerce 2.4.4–2.4.9, Adobe Commerce B2B 1.3.3–1.5.3, Magento Open Source 2.4.6–2.4.9 (through Aug 2026 builds)
- Fixed: hotfix VULN-39341 / APSB26-146 (2026-09-07). Active exploitation began 2026-09-04, before patch existed (Rust backdoor + PHP web shell implants observed).
- CISA KEV 2026-09-08.
- No public exploit/recon details disclosed (vendor and researcher writeups deliberately withhold). Treat any Magento/Adobe Commerce host as version-range LEAD only until build is confirmed patched — never attempt the injection (RCE, exploitation not detection).
- Sources: https://www.tenable.com/blog/stylesmuggler-cve-2026-75650-frequently-asked-questions-about-adobe-commerce-and-magento-zero , https://thehackernews.com/2026/09/unpatched-magento-and-adobe-commerce.html

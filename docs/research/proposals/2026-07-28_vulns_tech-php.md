# PROPOSAL (proposal) for docs/knowledge/tech-php.md — vulns 2026-07-28
_Review and apply manually; not auto-merged into the KB._

## 2026-07-28 update — CVE-2026-12184 / CVE-2026-14355 (July 6 coordinated patch, all 4 branches)
- **CVE-2026-12184** (CVSS 8.2): HTTP stream-wrapper TLS-handshake-failure use-after-free/null-deref — a malicious or MITM'd remote server the PHP app connects to (outbound HTTPS) can crash the whole PHP-FPM pool. Affected <8.3.32, <8.4.21, <8.5.6 (8.2.x unaffected). Not remotely triggerable *against* a target from our side — it's the target acting as a TLS client; relevant only as a patch-lag/version signal, not a probe.
- **CVE-2026-14355** (CVSS 4.8): heap corruption in `openssl_encrypt()` w/ AES-WRAP-PAD. Affected <8.2.32, <8.3.32, <8.4.23, <8.5.8. Narrow (specific cipher mode), low recon value.
- Detect version via `X-Powered-By` / error banners / `phpinfo` leaks (many hosts suppress — absence = unknown, not clean).
- Sources: https://securityonline.info/php-remote-dos-cve-2026-12184/ , https://www.josephcharnin.com/cybersecurity/php-fpm-tls-handshake-dos-cve-2026-12184/

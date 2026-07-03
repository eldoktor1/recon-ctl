# PROPOSAL (proposal) for docs/knowledge/tech-wordpress.md — vulns 2026-07-03
_Review and apply manually; not auto-merged into the KB._

## N-Day CVEs — 2026

### CVE-2026-1357 — WPvivid Backup & Migration ≤0.9.123, Unauthenticated RCE (CVSS 9.8)
- **Installs:** ~900,000
- **Fixed:** 0.9.124
- **Class:** `openssl_private_decrypt()` fail-open (null AES key) + path traversal → arbitrary PHP file write to `wp-content/uploads/` via unauthenticated POST.
- **Condition:** "receive backup from remote site" feature must be enabled (default in many deployments).
- **Fingerprint:** `/wp-content/plugins/wpvivid-backuprestore/readme.txt` for version.
- **Nuclei:** `halilkirazkaya/CVE-2026-1357`
- **Source:** https://www.bleepingcomputer.com/news/security/wordpress-plugin-with-900k-installs-vulnerable-to-critical-rce-flaw/

### CVE-2026-6433 — Custom CSS JS PHP ≤2.0.7, Unauthenticated SQLi→RCE (CVSS 10.0)
- **Class:** User input unsanitized into SQL query whose result is `eval()`'d → unauthenticated code execution.
- **Fingerprint:** `/wp-content/plugins/custom-css-js-php/readme.txt`
- **Source:** https://patchstack.com/database/wordpress/plugin/custom-css-js-php/vulnerability/wordpress-custom-css-js-php-plugin-2-0-7-unauthenticated-sql-injection-to-rce-vulnerability

### CVE-2026-4352 — JetEngine (Crocoblock) ≤3.8.6.1, Unauthenticated SQLi
- Unauth SQLi via CCT REST API search endpoint. Fingerprint: `/wp-content/plugins/jet-engine/readme.txt`.

### CVE-2026-2413 — Ally (Elementor addon) ≤4.0.3, Unauthenticated SQLi (~400k installs)
- SQLi via URL parameter. Fingerprint: `/wp-content/plugins/ally/readme.txt`.
- Source: https://www.wordfence.com/blog/2026/03/400000-wordpress-sites-affected-by-unauthenticated-sql-injection-vulnerability-in-ally-wordpress-plugin/

### CVE-2026-1581 — wpForo Forum ≤2.4.14, Unauthenticated Time-Based SQLi
- Via `wpfob` URL param. Fingerprint: `/wp-content/plugins/wpforo/readme.txt`.

### CVE-2026-2576 — Business Directory Plugin, Unauthenticated Time-Based SQLi
- Fingerprint: `/wp-content/plugins/business-directory-plugin/readme.txt`.

**Confirm gate for all SQLi:** `recon-params confirm sqli <host>` → `'` vs `''` differential → sqlmap verify (in-scope+paying, `--delay 1 --threads 1`, PoC-only).

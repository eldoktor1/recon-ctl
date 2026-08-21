# PROPOSAL (proposal) for docs/knowledge/tech-wordpress.md — vulns 2026-08-20
_Review and apply manually; not auto-merged into the KB._

## Plugin CVE wave — 2026-08 (unauth file-upload/SQLi, add to fingerprint rotation)
- **CVE-2026-32475** — Elementor Pro ≤4.2.1 (fixed 4.2.2, 2026-08-19): unauth file-upload→RCE via two-file-part trick on a form's File Upload field. Requires a live form with a File Upload field. CVSS 9.0. Source: https://www.ionix.io/threat-center/cve-2026-32475/
- **CVE-2026-15748** — Forminator Forms ≤1.56.1 (fixed 1.56.2, 2026-07-31): unauth file-upload→RCE via forged upload config on a form with both a Select field + File Upload field. CVSS 9.8, 300k+ still-vulnerable at disclosure. Source: https://securityonline.info/cve-2026-15748-forminator-rce/
- **CVE-2026-66447 / CVE-2026-17044** — "WordPress File Upload" plugin <5.1.8 (disclosed 2026-08-05): unauth SQLi via `uniqueuploadid` param. CVSS 9.3. Confirm via safe `'`/`''` differential only, never dump. Source: https://patchstack.com/database/wordpress/plugin/wp-file-upload/vulnerability/wordpress-wordpress-file-upload-plugin-5-1-7-sql-injection-vulnerability?_s_id=cve
Detect all three via plugin readme.txt `Stable tag` or JS bundle name in jsintel, same pattern as prior Kirki/Ajax-Search-Lite entries. All version-match = LEAD only; file-upload ones need form-shape confirmation (Select+Upload or bare Upload field) before treating as high-confidence.

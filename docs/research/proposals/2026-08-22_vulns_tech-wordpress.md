# PROPOSAL (proposal) for docs/knowledge/tech-wordpress.md — vulns 2026-08-22
_Review and apply manually; not auto-merged into the KB._

## Unauth file-upload-blocklist-bypass n-day cluster (Aug 2026)
Recurring pattern this month across multiple WP plugins: extension/MIME blocklist uses
exact-key matching, bypassed with pipe-alternative MIME-type keys or a two-part upload
trick that skips validation on a second file part for the same field → unauth arbitrary
PHP file write → RCE. Treat "upload field + blocklist" as a class to check version-first:
- **Elementor Pro ≤4.2.1** (fixed 4.2.2, 2026-08-19) — CVE-2026-32475, two-file-parts-same-field
  bypass, requires a published form with a File Upload field. CVSS 9.0.
- **Forminator ≤1.56.1** (fixed 1.56.2, 2026-07-31) — CVE-2026-15748, pipe-alternative
  MIME-key blocklist bypass, requires a form with File Upload + Select fields. CVSS 9.8.
Detection for both: plugin readme.txt `Stable tag` + jsintel bundle string match, then
confirm the site has a live form with the required field combo (visible in rendered DOM,
no probe needed). Don't fire the bypass autonomously — LEAD for operator confirm-then-stop.
Sources: thehackernews.com/2026/08/elementor-pro-flaw-could-let.html,
thehackernews.com/2026/08/forminator-wordpress-flaw-can-enable.html

# PROPOSAL (proposal) for docs/knowledge/tech-wordpress.md — vulns 2026-09-15
_Review and apply manually; not auto-merged into the KB._

## Recurring pattern (2026-09) — unauth comment/trackback as a deserialization/injection entry point
Four unrelated high-CVSS plugin CVEs this month share the same shape: an unauthenticated visitor submits
ordinary public content (a comment, a trackback) that plants a payload consumed later by a vulnerable
handler — not a direct HTTP endpoint hit.
- All-in-One WP Migration (CVE-2026-19949): trackback submission plants 2nd-order SQLi payload, fires on admin export/restore.
- The Events Calendar (CVE-2026-78006/78159): comment on an event page triggers PHP object injection / Gutenberg block markup abuse → RCE or admin password reset.
Detection heuristic: when fingerprinting a WP plugin for a "comment/trackback as attack surface" bug,
check whether the target post type actually has comments/trackbacks enabled (visible in rendered page,
no probe needed) before treating a version-match as a live LEAD — narrows false leads same as the
upload-field-presence check used for Elementor Pro/Forminator.

# PROPOSAL (proposal) for docs/knowledge/tech-wordpress.md — vulns 2026-09-03
_Review and apply manually; not auto-merged into the KB._

## Recurring 2026 pattern: unauth file-upload extension-blocklist bypass (WP plugins)
Three unauth-RCE-via-file-upload CVEs surfaced in WordPress plugins within a 2-week window
(Aug 20 – Sep 3, 2026), all sharing the same underlying flaw class — a check that's supposed
to gate uploaded file type/extension is skippable via an implementation quirk, not a missing
check outright:
- **Elementor Pro ≤4.2.1** (CVE-2026-32475, fixed 4.2.2) — submitting two file parts for the
  same Forms File-Upload field runs the extension-blocklist and the file-move step as separate
  loops with divergent empty-file handling; the second part skips the blocklist.
- **Forminator ≤1.56.1** (CVE-2026-15748, fixed 1.56.2) — `handle_file_upload()` blocklist does
  exact-key matching, bypassed with pipe-alternative MIME-type keys.
- **WPvivid Backup & Migration ≤0.9.123** (CVE-2026-1357, fixed 0.9.124) — `openssl_private_decrypt()`
  failure (`false`) is passed uncheck into phpseclib's Rijndael, which silently treats it as a
  predictable null key/IV; the decrypted payload's filename field isn't sanitized.

**Hunting implication:** when fingerprinting WordPress plugins (readme.txt Stable tag / jsintel
JS-bundle strings), treat "does this plugin process a user-controlled file upload" as a standing
question worth version-checking against the CVE feed each week, not just the three above — this
looks like a live bug-class the research community is actively mining in bulk-scanned plugins
(Elementor: form file-upload field; Forminator: file-upload+select field combo; WPvivid: remote
backup transfer). All three need a specific feature enabled/configured (published form w/
upload field; active wpvivid_api_token) that isn't remotely visible — version-match alone is a
LEAD, confirm feature-presence via DOM/page source where possible (Elementor/Forminator forms
render visibly; WPvivid's API-token state does not).

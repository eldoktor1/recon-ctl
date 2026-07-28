# PROPOSAL (proposal) for docs/knowledge/tech-wordpress.md — detect-tune 2026-07-28
_Review and apply manually; not auto-merged into the KB._

## Kirki plugin ≤6.0.6 — unauth account takeover (CVE-2026-8206, CVSS 9.8)
- Bug: `handle_forgot_password` (`CompLibFormHandler.php`) trusts an attacker-supplied `email` param alongside a known `username`, sending the password-reset link to the attacker instead of the real account owner. No auth required.
- Detect (safe, version-only): `curl -s <host>/wp-content/plugins/kirki/readme.txt` (also try `kirki-test`) → `Stable tag` ≤ 6.0.6. Also check `ver=` on `kirki.min.css`. Fixed 6.0.7 (2026-05-18).
- Confirm request (crosses into exploitation — human-gated, own test account only): `POST /wp-json/KirkiComponentLibrary/v1/kirki-forgot-password` with `username`, `email`, `emailBody`. HTTP 200 + "Email sent" = vulnerable behavior confirmed.
- Version match alone = LEAD (KEV doctrine), not P0.
- Source: https://zeropath.com/blog/cve-2026-8206-kirki-wordpress-privilege-escalation, https://github.com/Jenderal92/CVE-2026-8206

## Ninja Forms File Uploads ≤3.3.26 — unauth arbitrary file upload → RCE (CVE-2026-0740, CVSS 9.8)
- Bug: `NF_FU_AJAX_Controllers_Uploads::handle_upload` checks the extension of the source filename but writes to an attacker-supplied destination filename param (e.g. `image_jpg=shell.php` overrides the extension allowlist).
- Request chain: (1) `POST /wp-admin/admin-ajax.php action=nf_fu_get_new_nonce&field_id=<id>` → nonce; (2) `POST /wp-admin/admin-ajax.php action=nf_fu_upload&nonce=<nonce>&form_id=<id>&field_id=<id>&<slugified_filename>=<malicious_dest>` + `files-<field_id>=@<file>`.
- Detect (safe, version-only): grep page source for `nfpluginsettings\.js\?ver=[\d.]+` → ≤3.3.26 in-range. Fixed 3.3.27 (2026-03-19). Actively exploited in the wild since 2026-04-16 (Wordfence).
- Version match = LEAD only; an actual confirm requires a file write (crosses into exploitation) — operator-gated, benign non-executable marker only, never a real webshell.
- Source: https://blog.lexfo.fr/ninja-forms-uploads_rce.html, https://github.com/whattheslime/CVE-2026-0740

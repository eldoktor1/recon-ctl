# PROPOSAL (proposal) for docs/knowledge/tech-wordpress.md — vulns 2026-09-06
_Review and apply manually; not auto-merged into the KB._

## Unauth file-upload-bypass CVE cluster, Aug–Sep 2026 (pattern, not one-off)
Recurring bug class this cycle: WP plugin form/upload handlers skip extension/MIME blocklist checks under
specific request shapes, giving unauthenticated `.php` webshell upload → RCE. Confirmed members:
Elementor Pro (CVE-2026-32475, ≤4.2.1), Forminator (CVE-2026-15748, ≤1.56.1), WPvivid Backup (CVE-2026-1357,
≤0.9.123, via a crypto-fallback quirk not extension bypass but same upload-to-RCE shape), Everest Forms
(CVE-2026-19598, <3.0.9.5). Detection pattern: version-match via `readme.txt` `Stable tag` + jsintel plugin-slug
string, PLUS confirm the site actually renders a form with a file-upload field (visible in DOM, no probe
needed) before treating as a live LEAD — the plugin being present without an active upload-field form is not
exploitable. Never fire the bypass upload autonomously (crosses into RCE/exploitation); hand to operator for
confirm-then-stop, or use a PoC's "check mode" (writes a harmless file, not a webshell) if adopting an
automated safe-check.

## TranslatePress AJAX info-disclosure pattern (CVE-2026-19632)
`nopriv`-registered AJAX actions that return raw plugin data (including translated strings) are a real
unauth-info-disclosure surface on WP i18n plugins — check any plugin's `admin-ajax.php?action=...nopriv...`
handlers for sensitive data leaking through a "just returns translated content" endpoint. In TranslatePress's
case the leaked content included the admin password-reset key when auto-string-saving is on (default) and
the admin's locale is a secondary published language. Fixed 3.3.2 (2026-08-13).

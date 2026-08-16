# PROPOSAL (proposal) for docs/knowledge/tech-wordpress.md — vulns 2026-08-15
_Review and apply manually; not auto-merged into the KB._

## CVE-2026-64638 "XSS2Shell" (added 2026-08-15)
Pre-auth reflected XSS on `wp-login.php` via `log` param KSES/strip_tags differential, chainable to PHP
RCE via SOME + admin interaction. Affected: WP core 6.4–7.0.2. Patched: 7.0.3 (2026-08-06).
Detect: version via readme.html/`?ver=` on core assets; anomalous probe signature is `%3C` inside the
`log` POST param on wp-login.php (don't plant — version-range LEAD only, confirm via dalfox execution
if pursuing the XSS leg). Escalation-stage indicators: `_jsonp=`/`_method=GET`/`_envelope=1` REST params,
`wp-admin/authorize-application.php` with off-origin `success_url`.
Source: https://hadrian.io/blog/wordpress-xss2shell-unauthenticated-login-screen-xss-to-php-code-execution-cve-2026-64638

## CVE-2026-28139 — Ajax Search Lite plugin unauth PHP Object Injection (added 2026-08-15)
CVSS 9.8. Affected ≤4.14.4, patched 4.14.5 (2026-08-04). Fingerprint:
`/wp-content/plugins/ajax-search-lite/readme.txt` Stable tag, or `asl_*` AJAX actions in jsintel.
Version-gated LEAD; gadget-chain-dependent for RCE, don't exercise without a confirmed chain.

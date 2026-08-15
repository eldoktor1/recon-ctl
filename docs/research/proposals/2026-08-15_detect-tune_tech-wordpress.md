# PROPOSAL (proposal) for docs/knowledge/tech-wordpress.md — detect-tune 2026-08-15
_Review and apply manually; not auto-merged into the KB._

## CVE-2026-8457 — WooCommerce Social Login unauthenticated admin takeover (added 2026-08-15)
Plugin: WPWeb "WooCommerce – Social Login", ≤2.8.7 (fixed 2.8.8), disclosed 2026-08-01, CVSS 9.8.
Root cause: Apple `id_token` handler decodes only the base64 JWT payload — no signature check against
Apple's public keys, no iss/aud/exp validation. The nonce required to invoke the login AJAX action is
exposed unauthenticated via a localized JS object on the login page.
Exploit shape: unauth attacker reads the leaked nonce → submits a forged `id_token` payload whose email
claim matches a target WP user (incl. admin) → gets an authenticated session as that user. No login-bypass
needed, no password.
Detection: fingerprint via `/wp-content/plugins/woocommerce-social-login/readme.txt` (Stable tag ≤2.8.7)
or the plugin's login-page JS bundle. Genuine unauth-confirmable primitive (the whole chain — nonce read,
forge, POST — is unauthenticated) but confirmation must only ever target a researcher-owned test account's
email, never impersonate a real user/admin (that crosses the NEVER-list).
Sources: https://www.ionix.io/threat-center/cve-2026-8457/, https://github.com/advisories/GHSA-qwc9-q2f8-q72q

## CVE-2026-28139 — Ajax Search Lite unauthenticated PHP Object Injection (LEAD-not-P0, added 2026-08-15)
Plugin: Ajax Search Lite ≤4.14.4 (fixed 4.14.5), disclosed 2026-08-04, CVSS 9.8, unauthenticated PHP
Object Injection. Public advisories do NOT disclose the vulnerable parameter or a working POP gadget
chain. Per our KEV-clamp doctrine, treat as version-match LEAD only until a gadget chain against the
target's actual installed plugin set is demonstrated — PHP Object Injection without a usable gadget is
not RCE. Fingerprint via `/wp-content/plugins/ajax-search-lite/readme.txt`.
Source: https://vdp.patchstack.com/database/Wordpress/Plugin/ajax-search-lite/vdp

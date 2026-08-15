# PROPOSAL (proposal) for docs/knowledge/tech-wordpress.md — vulns 2026-08-15
_Review and apply manually; not auto-merged into the KB._

## CVE-2026-64638 "XSS2Shell" — pre-auth reflected XSS on wp-login.php, all core <7.0.3 (added 2026-08-15)
Crafted `log=` (username) param in the wp-login.php failed-login POST reflects unencoded into the
error page → unauth reflected XSS, no interaction beyond the failed login attempt. Bug present since
WP 4.7; fixed 7.0.3 (2026-08-06). Chains to PHP RCE only if a logged-in Administrator later visits
an attacker-controlled page (deployment-dependent, LEAD-only, don't chase).
- In-range check: core version <7.0.3 via readme.html / `?ver=` cache-busters on core JS/CSS.
- **Directly testable with our existing XSS confirm primitive** (`recon_xss_confirm.sh` /
  headless-Chromium execution check) pointed at `wp-login.php` — extend the XSS confirm target
  list to include the login endpoint on in-scope WordPress hosts, not just crawled app params.
- Source: https://thehackernews.com/2026/08/new-wordpress-pre-auth-xss-could-lead.html,
  https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-52p2-r8wf-jcrf

## CVE-2026-28139 (aka CVE-2026-16258) — Ajax Search Lite plugin unauth PHP Object Injection (added 2026-08-15)
Deserialization of untrusted input, CVSS 9.8. Affected ≤4.14.4, fixed 4.14.5 (~2026-08-04). RCE
requires a gadget chain (not guaranteed) — treat as version-in-range LEAD, escalate only w/ operator
sign-off given destructive-risk of gadget-chain probing.
- Detect: `/wp-content/plugins/ajax-search-lite/readme.txt` Stable tag, or `ajax-search-lite` string
  in jsintel enqueued-script paths.
- Source: https://patchstack.com/database/vulnerability/ajax-search-lite

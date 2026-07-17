# PROPOSAL (proposal) for docs/knowledge/tech-wordpress.md — vulns 2026-07-17
_Review and apply manually; not auto-merged into the KB._

## Two fresh unauth admin-takeover plugin CVEs, CVSS 9.8 (added 2026-07-17)
- **miniOrange OAuth SSO / Social Login & Register ≤ 38.5.8 — CVE-2026-57807**: auth bypass via password-recovery flow (CWE-288, alternate-path). Unauthenticated, no interaction. Disclosed by Patchstack 2026-07-09, **still unpatched** — high-value time-sensitive n-day target. Detect via plugin slug/version in `wp-content/plugins/` readme.txt or asset query-strings.
- **Hippoo Mobile App for WooCommerce ≤ 1.9.4**: unauth admin-account-takeover via REST API. Detect via plugin presence + REST namespace (verify exact route before probing).
Both fit our doctrine: unauth + no-interaction + high payout ceiling once version confirmed in-range. Sources: https://gbhackers.com/critical-wordpress-oauth-sso-plugin-flaw/ , https://cyberpress.org/wordpress-bug-enables-takeover/

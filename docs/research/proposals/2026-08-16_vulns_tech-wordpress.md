# PROPOSAL (proposal) for docs/knowledge/tech-wordpress.md — vulns 2026-08-16
_Review and apply manually; not auto-merged into the KB._

## WooCommerce Subscriptions — CVE-2026-18391 (unauth PHPObject Injection → RCE)
- Affected: WooCommerce Subscriptions < 9.1.0 (fixed 9.1.0), only exploitable when High-Performance
  Order Storage (HPOS) is enabled — `unserialize()` on unvalidated user input → gadget-chain RCE.
- Detect: plugin readme `Stable tag` at `/wp-content/plugins/woocommerce-subscriptions/readme.txt`
  or jsintel/fulltext hits for `woocommerce-subscriptions`. HPOS-enabled state is not remotely
  visible — version-in-range is LEAD only; do not fire the unserialize primitive (not a safe probe).
- Source: https://freshysites.com/security-bulletins/woocommerce-subscriptions-plugin-vulnerability-cve-2026-18391/ (added 2026-08-16)

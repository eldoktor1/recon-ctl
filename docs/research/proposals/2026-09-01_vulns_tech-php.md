# PROPOSAL (proposal) for docs/knowledge/tech-php.md — vulns 2026-09-01
_Review and apply manually; not auto-merged into the KB._

## Recurring class (2026-08/09): WP plugin unauth-unserialize gadget chains
Three unauth PHP-unserialize/object-injection bugs surfaced in WordPress plugins within a 3-week span
(2026-08-16 WooCommerce Subscriptions CVE-2026-18391, 2026-08-31→09-01 GiveWP CVE-2026-82222 CVSS 10.0).
Pattern: a plugin exposes a front-end-reachable input (order metadata, donation-flow field) that gets
passed to `unserialize()`/a "safe unserialize" helper without validation, and the plugin itself ships a
usable gadget class — no separate gadget-source plugin needed. Detection is identical to the existing
extension-blocklist-bypass-upload class (Elementor Pro, Forminator, 2026-08-20/22 digests): version via
`/wp-content/plugins/<slug>/readme.txt` `Stable tag` or the plugin's JS bundle string in jsintel. All of
these need a plugin-specific *state* precondition (HPOS enabled, a live donation form + gateway, a
form with specific field types) that isn't remotely visible — treat version-in-range as LEAD only, never
fire the actual deserialization/upload payload autonomously (crosses into RCE exploitation).
Actionable takeaway: when running `recon-mood wordpress`, also grep jsintel/readme hits for
`unserialize`/`safeUnserialize`/PHP-object-injection-prone plugin families, not just the classic
SQLi/XSS param signal — this is now a repeating unauth-RCE source on our top tech (WordPress/PHP).

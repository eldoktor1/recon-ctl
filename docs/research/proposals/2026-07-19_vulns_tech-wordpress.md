# PROPOSAL (proposal) for docs/knowledge/tech-wordpress.md — vulns 2026-07-19
_Review and apply manually; not auto-merged into the KB._

## CVE-2026-63030 + CVE-2026-60137 — "wp2shell" unauth RCE chain (added 2026-07-19)
- REST batch-route confusion (`/wp-json/batch/v1` or `?rest_route=/batch/v1`) lets a sub-request run
  under a different sub-request's handler; chained with a SQLi it becomes unauthenticated RCE.
- In-range: core 6.8.0-6.8.5 (SQLi component only), 6.9.0-6.9.4 and 7.0.0-7.0.1 (full RCE chain).
  Fixed 6.9.5 / 7.0.2.
- Unauth fingerprint: batch endpoint reachability (`/wp-json/batch/v1`) + core version disclosure
  (readme.html, `?ver=` query strings on core scripts, generator meta tag). Public PoC exists
  (GitHub, as of 2026-07-18) — version-in-range + reachable batch endpoint = candidate for
  `recon-nday`, still requires version confirmation before treating as more than a LEAD (our
  KEV-tech-class-without-verified-version rule applies the same way here).
- Source: https://thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html

# PROPOSAL (proposal) for docs/knowledge/tech-wordpress.md — vulns 2026-07-14
_Review and apply manually; not auto-merged into the KB._

## CVE-2025-9501 — W3 Total Cache pre-auth RCE (added 2026-07-14)
- Function: `PgCache_ContentGrabber::_parse_dynamic_mfunc()` → `eval()` on cached-page `mfunc` comment tags.
- Affected: W3 Total Cache ≤2.9.1 (1M+ installs); sanitize/parse regex mismatch (`\s+` vs `\s*`) means the bug survives the vendor's 2.8.13 patch through 2.8.15.
- Fingerprint (safe, unauth): `/wp-content/plugins/w3-total-cache/readme.txt` version string; W3TC-specific cache-control response headers.
- Exploit requires knowing the site's `W3TC_DYNAMIC_SECURITY` constant (usually secret) + comments-enabled-for-unauth + Page Cache active — treat a bare version match as a LEAD only (matches our KEV-tech-class-without-verified-primitive doctrine), don't attempt injection without confirming comment-post reachability first.
- Payload shape (reference only, for authorized confirm): `<!-- mfunc<SECRET> -->echo passthru($_GET[1337])<!-- /mfunc<SECRET> -->` submitted as a WP comment.
- Source: https://www.rcesecurity.com/2025/11/exploiting-a-pre-auth-rce-in-w3-total-cache-for-wordpress-cve-2025-9501/

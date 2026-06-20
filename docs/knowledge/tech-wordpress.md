# WordPress — Recon & Vuln KB

## Fingerprinting
- `X-Powered-By: WordPress` or `X-Generator: WordPress` headers
- `/wp-login.php`, `/wp-admin/`, `/wp-json/`, `/wp-content/plugins/` paths
- Meta tag: `<meta name="generator" content="WordPress X.X">`
- REST API version disclosure: `GET /wp-json/` → JSON with `name`, `url`, `gmt_offset`, `timezone_string`
- Plugin enumeration: `/wp-content/plugins/<slug>/readme.txt` — contains `Stable tag: X.X` version

## High-value unauth attack surface
- `/wp-json/wp/v2/users` — user enumeration (often unauth, leaks login names)
- `/wp-json/wp/v2/posts?author=N` — enumerate author IDs
- XML-RPC (`/xmlrpc.php`) — auth bypass attempts, user enumeration via `wp.getUsersBlogs`
- `/wp-login.php?action=lostpassword` — username oracle (different error for valid vs invalid)

## Plugin enumeration strategy
1. `cat jsintel/endpoints.jsonl | jq -r '.url' | grep '/wp-content/plugins/'` — mine loaded plugins from JS
2. Probe `readme.txt` for version: `curl https://$HOST/wp-content/plugins/$PLUGIN/readme.txt`
3. Cross-reference version vs WPScan vulnerability DB: https://wpscan.com/plugins

## Active CVEs (June 2026) — add to n-day lane
| CVE | Plugin | Versions | Type | Auth |
|-----|--------|----------|------|------|
| CVE-2026-2413 ⚠️ | Elementor Ally | ≤ 4.0.3 | SQLi (blind) | None |
| CVE-2026-1865 ⚠️ | User Registration & Membership | ≤ 5.1.2 | SQLi | Subscriber+ |
| CVE-2026-6271 ⚠️ | Career Section | ≤ 1.7 | File upload RCE | None |
| CVE-2026-3300 ⚠️ | Everest Forms Pro | ≤ 1.9.12 | PHP RCE | None |

⚠️ Verify CVE IDs at wpscan.com/vulnerability or nvd.nist.gov before adding to pipeline.

## Detection fingerprints for SQLi plugins
- Elementor Ally: `/wp-content/plugins/elementor-ally/` 200 OK → present
- User Registration: `/wp-content/plugins/user-registration/` 200 OK
- Safe SQLi probe: `'` vs `''` in `membership_ids[]` param for boolean diff

## FP patterns
- WordPress REST API returning 401/403 on `/wp-json/wp/v2/users` = hardened, not exploitable
- XML-RPC returning `405 Method Not Allowed` = disabled
- Version numbers in `readme.txt` may be outdated (plugin can be updated without readme change)

## Scope note
WordPress is shipped product in many programs — confirm per-asset scope before investing. 
`/wp-admin/` exposure ≠ finding unless unauth bypass demonstrated.

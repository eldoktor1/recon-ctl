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


---
<!-- applied-proposal: 2026-06-21_vulns_tech-wordpress -->
### Applied research — vulns (2026-06-21)

## June 2026 High-Severity WordPress Plugin CVEs — Unauth

### CVE-2026-8206 — Kirki Freeform Page Builder 6.0.0–6.0.6 — Unauth Admin Takeover (CVSS 9.8)
**Mechanism:** Password reset handler accepts attacker-supplied email without matching it to the target account → supply known admin username + attacker email → reset link to attacker → full admin takeover.
**Detect (unauth, safe):** `curl -s https://<host>/wp-content/plugins/kirki/readme.txt | grep 'Stable tag'` → version 6.0.0–6.0.6 = LEAD. Do NOT trigger the reset endpoint.
**Sources:** https://threat-modeling.com/kirki-wordpress-plugin-account-takeover-cve-2026-8206/ | https://orca.security/resources/blog/kirki-wordpress-plugin-vulnerability-cve-2026-8206/

### CVE-2026-8181 — Burst Statistics 3.4.0–3.4.1.1 — Unauth Admin Account Creation (CVSS 9.8)
**Mechanism:** `is_mainwp_authenticated()` returns null on failure; PHP coerces null→truthy in auth chain → REST API bypass → create new administrator.
**Detect (unauth, safe):** `/wp-content/plugins/burst-statistics/readme.txt` version check. Also probe `/wp-json/wp/v2/users` — returns user list = WP user enumeration baseline.
**Source:** https://cybersecuritynews.com/wordpress-plugin-vulnerability-exposes-websites/

### CVE-2026-4020 — Gravity SMTP — Unauth API Key / OAuth Token Leak (ACTIVELY EXPLOITED, 17M+ attempts)
**Mechanism:** Single unauthenticated request drains SMTP integration API keys and OAuth tokens from ~100K sites.
**Detect (unauth, safe):** `/wp-content/plugins/gravitysmtp/readme.txt`. Sites running Gravity Forms suite are high-probability candidates.
**Note:** Version range unconfirmed at NVD as of 2026-06-21 — verify before scoring.
**Source:** https://www.techtimes.com/articles/318768/20260621/wordpress-email-plugin-flaw-triggers-17-million-attacks-gravity-smtp-leaks-live-api-keys.htm

### Avada Builder < 3.15.4 — Unauth Arbitrary File Deletion (fixed 2026-06-02)
**Detect:** `curl -s https://<host>/wp-content/themes/avada/style.css | grep Version` → < 3.15.4 = LEAD. Also: `X-Powered-By: Avada` header or `/wp-content/themes/avada/` path.
**Endpoint:** `wp_ajax_nopriv_fusion_form_submit_ajax` — nopriv = unauthenticated. Do NOT send deletion payload.
**Sources:** https://cybersecuritynews.com/avada-wordpress-plugin-vulnerability/ | https://gbhackers.com/critical-wordpress-plugin-bug/amp/


---
<!-- applied-proposal: 2026-06-25_vulns_tech-wordpress -->
### Applied research — vulns (2026-06-25)

## Plugin CVE Wave — June 2026 (unauth disclosure/bypass)

### CVE-2026-4020 — Gravity SMTP: Unauthenticated API Key + OAuth Token Disclosure
- **Fingerprint:** WP host + `gravitysmtp` in JS bundles (jsintel) OR `/wp-content/plugins/gravitysmtp/` accessible
- **Probe (unauth, safe GET):** `GET /wp-json/gravitysmtp/v1/settings` — JSON response containing API keys/OAuth tokens = CONFIRMED disclosure
- **Note:** 17M+ exploit attempts/week as of June 7, 2026 — race window may be closing on saturated programs; prioritize fresh/low-volume WP targets
- **Source:** https://thenextweb.com/news/gravity-smtp-wordpress-plugin-vulnerability-cve-2026-4020-api-keys-exploit

### CVE-2026-8181 — Burst Statistics: Admin Impersonation via Unsigned MainWP Authorization Header (CVSS 9.8)
- **Requires:** MainWP integration active on the target WP instance
- **Fingerprint:** `/wp-content/plugins/burst-statistics/` presence + `mainwp` in JS or `/wp-json/mainwp/` accessible
- **Probe:** `GET /wp-json/burst/v1/<endpoint>` with `Authorization: MainWP <arbitrary>` header → 200/admin-scoped response = LEAD
- **Source:** https://cybersecuritynews.com/wordpress-plugin-vulnerability-exposes-websites/

### CVE-2026-8206 — Kirki Customizer: Unauthenticated Privilege Escalation (CVSS 9.8)
- **Affected:** Kirki 6.0.0–6.0.6; patched 6.0.7+
- **Fingerprint:** `/wp-content/plugins/kirki/readme.txt` → version string. `kirki` also appears in enqueued JS (jsintel).
- **Source:** https://www.wordfence.com/blog/2026/06/unauthenticated-privilege-escalation-vulnerability-patched-in-kirki-wordpress-plugin/

### UpdraftPlus — Unauthenticated Authentication Bypass (CVE TBD, June 2026)
- **Scope:** 3M+ installs; affects all WP hosts with UpdraftPlus installed below patched version
- **Fingerprint:** `/wp-content/plugins/updraftplus/` presence; version in `readme.txt`
- **Source:** https://www.wordfence.com/blog/2026/06/critical-unauthenticated-authentication-bypass-vulnerability-patched-in-updraftplus-wordpress-plugin/


---
<!-- applied-proposal: 2026-07-01_vulns_tech-wordpress -->
### Applied research — vulns (2026-07-01)

## High-Value Plugin CVEs — 2026 (add to Vulnerabilities / Plugin Targets section)

| CVE | Plugin | Installs | CVSS | Unauth | Vector | Fingerprint | Patch |
|-----|--------|----------|------|--------|--------|-------------|-------|
| CVE-2026-10795 | UpdraftPlus ≤ 1.26.4 | 3M+ | 8.1 | YES — actively exploited | RPC handler admin RCE | `/wp-content/plugins/updraftplus/readme.txt` → `Stable tag:` ≤ 1.26.4 | 1.26.5 |
| CVE-2026-1357 | WPvivid Backup ≤ affected ver | 900K | Critical | YES | Unauth PHP file upload → RCE | `/wp-content/plugins/wpvivid-backuprestore/readme.txt` | Updated ver |
| CVE-2026-8206 | Kirki Page Builder | 150K | 9.8 | YES | Password reset admin takeover | `/wp-content/plugins/kirki/readme.txt` | Updated ver |
| CVE-2026-1492/1779 | User Registration & Membership | — | Critical | Partial | Internal tokens in client-side context → admin bypass | `/wp-content/plugins/user-registration/readme.txt`; tokens in inline JS on reg pages | Updated ver |

**Detection pattern for n-day scanning:**
```bash
# Check multiple plugin readmes in one pass
for plugin in updraftplus wpvivid-backuprestore kirki user-registration; do
  curl -sk "https://<host>/wp-content/plugins/${plugin}/readme.txt" | grep -i "Stable tag"
done
```

### Applied research — vulns (2026-07-03)

## Unauth SQLi plugin CVEs — 2026 (add to n-day lane)

| CVE | Plugin | Affected | Vector | Fingerprint |
|-----|--------|----------|--------|-------------|
| CVE-2026-6433 ⚠️ | Custom CSS JS PHP | ≤ 2.0.7 | **Unauth SQLi → RCE (CVSS 10.0)** — SQL result `eval()`'d | `/wp-content/plugins/custom-css-js-php/readme.txt` |
| CVE-2026-4352 ⚠️ | JetEngine (Crocoblock) | ≤ 3.8.6.1 | Unauth SQLi via CCT REST API search | `/wp-content/plugins/jet-engine/readme.txt` |
| CVE-2026-1581 ⚠️ | wpForo Forum | ≤ 2.4.14 | Unauth time-based SQLi via `wpfob` param | `/wp-content/plugins/wpforo/readme.txt` |
| CVE-2026-2576 ⚠️ | Business Directory Plugin | — | Unauth time-based SQLi | `/wp-content/plugins/business-directory-plugin/readme.txt` |

**Confirm gate (all):** `recon-params confirm sqli <host>` → `'` vs `''` differential → sqlmap verify
(in-scope+paying, `--delay 1 --threads 1`, PoC-only, never mass `--dump`). ⚠️ = LLM-sourced CVE, NVD/version-verify before minting.

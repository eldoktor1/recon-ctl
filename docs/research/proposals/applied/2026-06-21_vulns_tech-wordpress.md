# PROPOSAL (proposal) for docs/knowledge/tech-wordpress.md — vulns 2026-06-21
_Review and apply manually; not auto-merged into the KB._

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

# PROPOSAL (proposal) for docs/knowledge/tech-wordpress.md — vulns 2026-06-25
_Review and apply manually; not auto-merged into the KB._

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

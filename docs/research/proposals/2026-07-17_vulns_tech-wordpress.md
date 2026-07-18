# PROPOSAL (proposal) for docs/knowledge/tech-wordpress.md — vulns 2026-07-17
_Review and apply manually; not auto-merged into the KB._

### Applied research — vulns (2026-07-17)

## CVE-2026-57807 — miniOrange OAuth SSO — Unauthenticated Full Account Takeover (CVSS 9.8, NO PATCH)
- **Mechanism:** CWE-288 auth bypass via an alternate path in the plugin's password-recovery handler — skips
  authentication entirely, lets an unauthenticated remote attacker log in as ANY user including admin.
- **Affected:** Enterprise builds ≤ 38.5.8. Free-repo build (6.26.x) applicability unconfirmed — verify.
- **Patch status:** none as of 2026-07-13; only mitigation is disabling the plugin. Treat any live version as in-range.
- **Detect (unauth, safe):** `/wp-content/plugins/miniorange-oauth-2.0-single-sign-on/readme.txt` → `Stable tag`;
  also `miniorange` string in login-page JS/jsintel.
- **Action:** version-match = LEAD (default in-range, no patched baseline exists). The bypass itself is a
  full-takeover primitive — do NOT exercise without following the authed/exploit escalation gate (ask operator
  first per hunt-flow step 8).
- **Sources:** https://gbhackers.com/critical-wordpress-oauth-sso-plugin-flaw/ | https://nvd.nist.gov/vuln/detail/CVE-2026-57807

## CVE-2026-15005 — Loco Translate — CSRF-chained RCE (CVSS 8.8)
- **Affected:** ≤ 2.8.5. Disclosed by Wordfence 2026-07-15.
- **Mechanism:** CSRF weakness chained to RCE — requires a logged-in privileged user to trigger a crafted
  request; NOT a bare unauth primitive.
- **Detect:** `/wp-content/plugins/loco-translate/readme.txt` → `Stable tag` ≤ 2.8.5 = LEAD (CSRF-delivery lane,
  not autonomous-probe eligible).
- **Source:** wordfence.com advisory (verify exact URL before citing in a report)

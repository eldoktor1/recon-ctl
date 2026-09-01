# PROPOSAL (proposal) for docs/knowledge/class-nday.md — vulns 2026-09-01
_Review and apply manually; not auto-merged into the KB._

## Metabase CVE-2026-72898 — unauth SQLi via password-reset, CVSS 10.0, KEV (added 2026-08-11)

- **Vulnerable endpoint:** `POST /api/session/reset_password` — SQL built from unsanitized input (CWE-89), zero auth.
- **Affected:** 0.58.0–0.58.23, 0.59.0–0.59.20, 0.60.0–0.60.16, 0.61.0–0.61.10, 0.62.0–0.62.8, 0.63.0–0.63.4
  (Enterprise = matching 1.x line). Fixed: 0.58.24 / 0.59.21 / 0.60.17 / 0.61.11 / 0.62.9 / 0.63.5.
- **Safe unauth fingerprint (no injection):**
  - `GET /api/session/properties` (unauthenticated) → JSON body contains `"version":{"tag":"v0.6x.y"}`.
  - Raw page body/HTML often embeds `window.MetabaseBootstrap = ` with version metadata.
- **KEV status:** added to CISA KEV 2026-08-11; confirmed real-world pre-patch victims (Framework, Anaconda,
  n8n — all Metabase Cloud tenants) per Dataminr threat intel. ~4,300 of ~11,000 scanned self-hosted
  instances still in vulnerable version ranges as of the runZero scan (2026-08).
- **Doctrine note:** version-in-range via the safe `/api/session/properties` fingerprint is a genuine
  real-fingerprint LEAD (not a bare tech-class guess) — but the actual injection primitive is a live,
  actively-exploited-in-the-wild KEV entry touching the app database, so treat as n-day-race: hand to
  operator for authorized confirm-then-stop, don't auto-fire the `'`/`''` differential unattended.
- **Sources:** https://www.ionix.io/threat-center/cve-2026-72898/, https://www.offsec.com/blog/cve-2026-72898-2/,
  https://www.runzero.com/blog/metabase/

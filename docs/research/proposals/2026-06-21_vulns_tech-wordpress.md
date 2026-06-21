# PROPOSAL (proposal) for docs/knowledge/tech-wordpress.md — vulns 2026-06-21
_Review and apply manually; not auto-merged into the KB._

## WordPress Plugin n-day Candidates — June 2026

### CVE-2026-6433 — Custom css-js-php ≤ 2.0.7 — UNAUTH RCE
**Root cause:** Unsanitized user input injected into SQL query; query result passed to `eval()` → full PHP code execution without authentication.  
**Detection:** Probe `/wp-content/plugins/custom-css-js-php/readme.txt` for version ≤ 2.0.7; plugin presence on any WP host.  
**Action:** Highest-priority WP n-day; version-confirm before reporting.  
**Source:** [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2026-6433/)

### CVE-2026-2413 — Elementor Ally ≤ 4.0.3 — UNAUTH SQLi
**Root cause:** Improper handling of URL path parameter fed directly to SQL query.  
**Detection:** `/wp-content/plugins/elementor-ally/readme.txt`; 250k+ affected sites. Elementor is extremely common.  
**Action:** `recon-params confirm sqli <host>` after plugin-path confirmation.  
**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/sqli-flaw-in-elementor-ally-plugin-impacts-250k-plus-wordpress-sites/)

### CVE-2026-2576 — Business Directory Plugin — UNAUTH Time-Based SQLi
**Detection:** `/wp-content/plugins/business-directory-plugin/`; look for BD search forms (`listingfields` param region).  
**Source:** [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2026-2576/)

# PROPOSAL (proposal) for docs/knowledge/tech-wordpress.md — vulns 2026-06-21
_Review and apply manually; not auto-merged into the KB._

## Critical Plugin CVEs — 2026

The following unauth-critical plugin vulns are active as of June 2026. Detect by checking for plugin paths in jsintel/crawl data:

| CVE | Plugin | CVSS | Class | Detection Path |
|---|---|---|---|---|
| CVE-2026-3300 | Everest Forms Pro | Critical | Unauth PHP file upload → RCE | `/wp-content/plugins/everest-forms-pro/`, `/wp-json/evf/v1/` |
| CVE-2026-23550 | Modular DS | 10.0 | Unauth priv esc → admin | Plugin active (check plugin list) |
| CVE-2026-3309 | ProfilePress ≤ 4.16.11 | Critical | Unauth shortcode exec via checkout | `/wp-content/plugins/profilepress/` |
| CVE-2026-1830 | Quick Playground | Critical | No-auth REST endpoints | `/wp-json/quick-playground/`, `/api.php` |
| CVE-2026-1357 | WPvivid Backup ≤ 0.9.123 | 9.8 | Full site takeover | `/wp-content/plugins/wp-vivid-backup/`, `/wp-json/wp-vivid-api/` |

**Hunting note:** For any WordPress host in ES, grep jsintel endpoints + crawl paths for these plugin slugs. Confirmed active plugin + unpatched version = n-day LEAD. Everest Forms RCE is highest-impact.

Sources: BleepingComputer, SentinelOne CVE database (June 2026)

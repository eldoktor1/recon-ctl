# PROPOSAL (proposal) for docs/knowledge/tech-wordpress.md — vulns 2026-07-01
_Review and apply manually; not auto-merged into the KB._

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

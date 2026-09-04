# PROPOSAL (proposal) for docs/knowledge/tech-wordpress.md — vulns 2026-09-04
_Review and apply manually; not auto-merged into the KB._

## Recurring plugin-CVE patterns, Aug–Sep 2026 (added 2026-09-04)
Two distinct unauth-RCE-adjacent families have recurred across multiple plugins this cycle —
treat both as ongoing classes to sweep for, not one-offs:
1. **Extension-blocklist-bypass file upload → RCE**: Elementor Pro (CVE-2026-32475), Forminator
   (CVE-2026-15748), WPvivid (CVE-2026-1357). Detect: plugin readme.txt `Stable tag` + plugin
   JS-bundle string in jsintel; confirm a live form has the relevant upload field before treating
   as more than a version-match LEAD.
2. **Second-order SQLi planted via public input, executed on a later privileged action**:
   All-in-One WP Migration (CVE-2026-19949) — payload via trackback, executes on admin restore.
   Not a same-session probe; requires the plugin's specific trigger action to fire.
Standard enumeration technique for both: `GET /wp-content/plugins/<slug>/readme.txt` → `Stable tag`
line, cross-checked against jsintel bundle strings for plugins that obscure their readme.

# PROPOSAL (proposal) for docs/knowledge/class-cdn-origin-bypass.md — kb-enrich 2026-09-01
_Review and apply manually; not auto-merged into the KB._

## 2026 update — origin-IP discovery + safe confirm technique

**Discovery vectors (passive, non-target-traffic — fits our archive/CT-recon lanes):**
- Apex-domain DNS-only misconfig: org proxies `www` through Cloudflare but leaves the apex (or a legacy
  `mail`/`autodiscover`/`direct`/`origin`/`staging` label) unproxied and pointing straight at the real IP —
  check every subdomain's proxy status, not just the primary host.
- Historical DNS (pre-Cloudflare A-records) via SecurityTrails / crt.sh cert history / Shodan cert-subject
  scoped to the target's cert CN (feeds our existing `recon-uncover` Shodan/Censys dork lane) — CT logs and
  DNS history frequently retain the origin IP from before the CDN was placed in front.
- cPanel/WHM auto-generated DNS entries and incomplete CDN migrations are a recurring source pattern per
  this research — worth a specific host-note flag when seen.

**Safe confirm (read-only, matches our `recon_safe_probe.sh` GET/HEAD primitive):**

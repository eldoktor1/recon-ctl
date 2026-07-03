# PROPOSAL (proposal) for docs/knowledge/tech-varnish.md — vulns 2026-07-03
_Review and apply manually; not auto-merged into the KB._

## N-Day CVEs — 2026

### CVE-2026-34475 — URL Mishandling, Cache Poisoning / Auth Bypass (CVSS 5.4)
- **Affected:** Varnish Cache < 8.0.1; Varnish Enterprise < 6.0.16r12
- **Class:** Mishandled root-path `/` requests in `unchecked req.url` scenarios → cache key confusion leading to cache poisoning or auth-boundary bypass.
- **Fingerprint (unauth):** `Via: 1.1 varnish` + `X-Varnish:` response headers; some configurations expose version in `X-Varnish-Backend` or via `varnishstat` endpoint.
- **WCD lane note:** This CVE directly amplifies the web-cache deception lane for Varnish hosts ≤ 8.0.0. Flag matched hosts in WCD briefing.
- **Source:** https://security.glexia.com/cves/CVE-2026-34475

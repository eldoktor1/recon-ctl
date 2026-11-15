# PROPOSAL (proposal) for docs/knowledge/tech-nextjs.md — vulns 2026-09-17
_Review and apply manually; not auto-merged into the KB._

## CVE-2026-3125 — OpenNext-on-Cloudflare SSRF via /cdn-cgi/image/ backslash bypass (added 2026-09-17)
- Affects `@opennextjs/cloudflare` npm package < 1.17.1 (Next.js deployed on Cloudflare Workers via the OpenNext adapter).
- Mechanism: dev-only `/cdn-cgi/image/` handler is meant to be edge-intercepted by Cloudflare in prod; `/cdn-cgi\image/` (backslash) bypasses the edge intercept, then the Worker's JS `URL` class re-normalizes it to match the handler → unvalidated server-side fetch of attacker-supplied URL (SSRF) + can serve attacker content from the victim origin + exposes protected `/cdn-cgi/` cache content.
- Fingerprint: Next.js + Cloudflare Workers hosting (CF headers + Next.js build markers in jsintel).
- Safe confirm: `GET /cdn-cgi\image/width=100/https://<our-interactsh-canary>` — OOB callback via interactsh is a clean unauth confirm primitive, same as our existing SSRF lane. CVSS 6.5.
- Source: https://github.com/opennextjs/opennextjs-cloudflare/security/advisories/GHSA-c7mq-gh6q-6q7c

# PROPOSAL (proposal) for docs/knowledge/tech-nextjs.md — vulns 2026-08-18
_Review and apply manually; not auto-merged into the KB._

## July 2026 security release — two probe-confirmable unauth primitives (added 2026-08-18)

Nine CVEs fixed in Next.js 16.2.11 (Active LTS) / 15.5.21 (Maintenance LTS) / 16.3.0-canary.92+,
released 2026-07-21. Full list: https://nextjs.org/blog/july-2026-security-release

Two are directly actionable for our unauth-safe pipeline — NOT mere version-match LEADs, because
the primitive itself is probe-confirmable:

### CVE-2026-64642 — middleware/proxy auth bypass (High, GHSA-6gpp-xcg3-4w24)
- Trigger: App Router built with **Turbopack** + a **single entry in `config.i18n.locales`**.
- Effect: a crafted request bypasses middleware entirely — any auth/security check the
  middleware performs (session gate, role check, geofence) is skipped.
- Affected: 16.0.0–16.2.10. Fixed: 16.2.11.
- **Confirm primitive:** identify a route that normally 401s/redirects-to-login when hit
  unauthenticated on an in-scope Next.js+Turbopack host with i18n configured; retry via the
  documented locale-prefix bypass pattern (see GHSA advisory for exact request shape); if the
  protected content is served instead of the auth challenge → CONFIRMED bypass. This is a real
  confirm primitive, not a tech-class LEAD.
- Detect Next.js/Turbopack: `x-powered-by: Next.js` header (often stripped), or
  `/_next/static/<BUILD_ID>/_buildManifest.js` presence. Turbopack use isn't remotely
  fingerprintable — treat build-tool as unknown until the bypass either works or doesn't.

### CVE-2026-64645 — SSRF/open-redirect via rewrites()/redirects() (High, CVSS 8.3, GHSA-p9j2-gv94-2wf4)
- Trigger: a `rewrites()`/`redirects()` rule whose external destination hostname is built from
  request-controlled input (query param / path segment feeding the rewrite target).
- Effect: destination can be pointed at an arbitrary host, ignoring the configured hostname
  suffix — SSRF for rewrites, open-redirect for redirects.
- Affected: ranges back to 12.0.0 for the rewrite SSRF flaw. Fixed: 16.2.11/15.5.21.
- **Confirm primitive (fits our interactsh SSRF lane directly):** on an in-scope Next.js host,
  find a rewrite/redirect route whose destination looks parameter-influenced; point the
  attacker-controlled portion at our interactsh canary domain; an OOB callback = CONFIRMED SSRF.
  Same doctrine as our existing SSRF class (`class-ssrf.md`) — OOB callback is definitive.

### Lower-priority items from the same release (DoS-only or narrow config trigger — not our safe-probe scope)
CVE-2026-64641 (Server Action CPU-exhaustion DoS), CVE-2026-64649 (Server Action SSRF via Host
header, custom servers only), CVE-2026-64644 (SVG image-opt DoS, needs remote-image config not
default), CVE-2026-64646 (Edge runtime memory DoS), CVE-2026-64643 (Server Function endpoint-ID
disclosure — recon value, worth folding into jsintel endpoint mining on Next.js hosts),
CVE-2026-64648/64647 (fetch response cache-confusion, narrow request shape).

Source: https://nextjs.org/blog/july-2026-security-release

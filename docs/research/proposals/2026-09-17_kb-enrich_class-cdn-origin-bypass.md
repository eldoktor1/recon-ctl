# PROPOSAL (proposal) for docs/knowledge/class-cdn-origin-bypass.md — kb-enrich 2026-09-17
_Review and apply manually; not auto-merged into the KB._

## "Trusted validation path" WAF-disable check (generalized from Cloudflare's Jan 2026 ACME disclosure)

**Background:** Cloudflare's `/.well-known/acme-challenge/{token}` path is designed to bypass WAF/edge
rules entirely when serving an ACME HTTP-01 challenge, because CA validation can't tolerate WAF
interference. The 2025/2026 bug (reported Oct 2025, patched Oct 27 2025, disclosed Jan 21 2026) was
that WAF got disabled BEFORE token verification, and a foreign-zone token still reached origin
unfiltered — this specific Cloudflare instance is now fixed; do not spend time re-testing it there.
Sources: https://thehackernews.com/2026/01/cloudflare-fixes-acme-validation-bug.html ,
https://securityaffairs.com/187156/security/acme-flaw-in-cloudflare-allowed-attackers-to-reach-origin-servers.html

**Generalized check for OTHER CDNs in our scope (safe, unauth, single-request per path):**
Every major CDN carries at least one path class that MUST reach origin/serve locally unfiltered by
design — domain-validation challenges, health-checks, or internal cache-purge callbacks. For each
CDN vendor fronting an in-scope host, identify its documented well-known/validation paths
(`/.well-known/acme-challenge/*`, `/.well-known/pki-validation/*`, CDN-specific health-check paths)
and send a single GET with an arbitrary/non-existent token. A response that DIFFERS from the CDN's
normal WAF-blocked-path behavior (e.g. reaches origin and returns an app-level 404 instead of the
CDN's branded block page) is a LEAD that the path class is CDN-trusted-passthrough on this host —
confirms an origin-exposure primitive worth chaining (origin IP/headers/error pages leak), not a
scan artifact. This is READ-ONLY reconnaissance (one GET, no token forgery, no cert issuance
attempted) — never attempt to obtain a real cert or claim a domain via this path.

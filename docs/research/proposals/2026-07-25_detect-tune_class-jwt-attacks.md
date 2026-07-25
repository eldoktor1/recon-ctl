# PROPOSAL (proposal) for docs/knowledge/class-jwt-attacks.md — detect-tune 2026-07-25
_Review and apply manually; not auto-merged into the KB._

## Additional 2026 JWT verification-bypass instances (Hono / Parse Server / Apache Camel) — added 2026-07-25 (detect-tune)
Same generalized pattern as the pac4j-jwt / HarbourJwt proposal filed today by the vulns run — three more
concrete library instances worth checking tech-fingerprints against:
- **CVE-2026-22817 (Hono JWT middleware, <4.11.4, Cloudflare Workers/Deno/Bun/Node):** alg derived from
  token header instead of pinned → RS256→HS256 public-key-as-HMAC-secret forgery.
- **CVE-2026-27804 (Parse Server OAuth adapters, <8.6.3 and ≥9.0.0 <9.3.1-alpha.4, Google/Apple/FB auth):**
  alg taken directly from header → `none`-bypass and RS256→HS256 both viable.
- **CVE-2026-23552 (Apache Camel KeycloakSecurityPolicy, 4.15.0–4.17.x):** signature checked correctly but
  `iss` claim NOT validated against the configured realm → cross-realm/cross-tenant token reuse on
  multi-tenant Camel+Keycloak gateways. Different bug shape (claim-validation gap, not alg confusion) —
  worth its own "is `iss` pinned?" check whenever we see Keycloak+Camel together.
All three: unauth-testable, read-only (craft/replay token, observe accept/reject) — same LEAD-not-confirmed
rule as the existing `alg`-swap signal; forging a working signature is the active-PoC step, human-in-the-loop.
Source: https://dev.to/iamdevbox/jwt-algorithm-confusion-attacks-cve-2026-22817-cve-2026-27804-and-cve-2026-23552-fix-guide-4ac4

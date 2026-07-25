# Research digest — detect-tune — 2026-07-25

# Detection & Verification Tuning — Digest (2026-07-25, supplemental)

Checked before searching: today's `vulns` run already filed proposals for `class-jwt-attacks.md` (pac4j-jwt CVE-2026-29000, HarbourJwt CVE-2026-23993) and `tech-varnish.md` (CVE-2026-34475). Cross-checked against those plus the existing KB — wp2shell (WordPress core RCE chain), Salesforce AuraInspector, GraphQL introspection-bypass techniques, dalfox v3, HTTP smuggling parser-discrepancy detection, and favicon-hash fingerprinting are **all already fully documented** in our KB/recent digests. No re-surfacing needed there.

## 1. One more JWT algorithm-confusion cluster, distinct libraries (minor addendum)
Same bug class as today's pac4j/HarbourJwt proposal, but three *different* libraries/products worth having on the version-fingerprint radar if our JS-intel/tech-detection ever flags them (Cloudflare Workers APIs, Parse-Server-backed mobile backends, or Camel/Keycloak gateways):

| CVE | Library | Vulnerable | Mechanism |
|---|---|---|---|
| CVE-2026-22817 | Hono JWT middleware (Cloudflare Workers/Deno/Bun/Node) | < 4.11.4 | Derives verify-alg from token header instead of pinning it → RS256→HS256 forgery with the public key as HMAC secret |
| CVE-2026-27804 | Parse Server OAuth adapters (Google/Apple/FB) | <8.6.3, ≥9.0.0 <9.3.1-alpha.4 | `alg` taken directly from token header → both `none`-bypass and RS256→HS256 |
| CVE-2026-23552 | Apache Camel `KeycloakSecurityPolicy` | 4.15.0–4.17.x | Signature validated correctly but `iss` claim not checked against configured realm → cross-tenant/cross-realm token reuse in multi-tenant Camel/Keycloak deployments |

All three are unauth-testable read-only checks (craft/replay a token, observe accept/reject) — same doctrine as the existing `alg`-swap LEAD-only rule in `class-jwt-attacks.md` (signal ≠ confirmation; forging a working signature is the active-PoC step, human-in-the-loop).

Sources: [dev.to CVE summary](https://dev.to/iamdevbox/jwt-algorithm-confusion-attacks-cve-2026-22817-cve-2026-27804-and-cve-2026-23552-fix-guide-4ac4)



Nothing else this cycle cleared the bar for new/actionable — the detect-tune surface (WordPress core, Varnish, Salesforce, GraphQL, smuggling, dalfox, bucket exposure, favicon-hashing) is currently well-covered by the last two weeks of digests plus today's vulns run.

# PROPOSAL (proposal) for docs/knowledge/class-jwt-attacks.md — detect-tune 2026-08-25
_Review and apply manually; not auto-merged into the KB._

## 2026 library-specific alg-confusion / issuer-bypass CVEs — escalation triggers

When tech-fingerprinting identifies one of these stacks, escalate an alg-swap LEAD faster (known-vulnerable
library, not just theoretical):

- **Hono JWT middleware < 4.11.4** (Cloudflare Workers/Deno/Bun/Node) — CVE-2026-22817: no server-side
  `alg` pinning; HS256-signed-with-RS256-public-key-as-HMAC-secret bypasses auth.
- **Parse Server < 8.6.3 / ≥9.0.0 <9.3.1-alpha.4**, Google/Apple/Facebook OAuth adapters — CVE-2026-27804:
  same `alg`-trust bug on the social-login path; `alg:none` or `alg:HS256`+pubkey = full account takeover
  via OAuth login.
- **Apache Camel `KeycloakSecurityPolicy` 4.15.0–4.17.x** — CVE-2026-23552: **NOT alg-confusion** —
  signature validation is correct but the `iss` (issuer) claim is never checked against the configured
  Keycloak realm. A token from ANY Keycloak realm is accepted, breaking multi-tenant isolation.
  **New confirm-primitive:** on a Keycloak-fronted target, in addition to the alg-swap probe, test whether
  a token minted from a *different* realm/tenant you control (throwaway self-registered realm, or a
  second in-scope tenant you own) is accepted — a distinct cross-issuer/audience-validation bypass,
  independent of the signing algorithm.

**`kid`-header path-traversal nuance:** `kid: ../../../../dev/null` can drive some HMAC key-resolution
code down a path that resolves to a zero-length "key," which certain implementations accept as valid —
the traversal doesn't need to hit a real key file, just needs to make key resolution fail in the
attacker's favor.

Sources: https://dev.to/iamdevbox/jwt-algorithm-confusion-attacks-cve-2026-22817-cve-2026-27804-and-cve-2026-23552-fix-guide-4ac4 ,
https://www.thehackerwire.com/fast-jwt-algorithm-confusion-re-enabled-cve-2026-34950/

# Research digest — detect-tune — 2026-08-25

# Research digest — detect-tune — 2026-08-25

## 1. Shopify `shopify_app` gem (Ruby) — cross-shop authz bypass via `shop` param, CVE-class AIKIDO-2026-135231 (HIGH PRIORITY — new IDOR fingerprint, feeds `class-idor.md`)
Any third-party Shopify **embedded app** built on the `shopify_app` Ruby gem, versions **22.1.0–23.0.2** (fixed 23.0.3), is vulnerable to a cross-shop authorization bypass in token-exchange controllers. The `current_shopify_domain` helper resolves to the **`shop` query parameter** before falling back to the verified Shopify ID-token/session identity — so a request authenticated as Shop A but carrying `?shop=victim-shop.myshopify.com` executes in Shop B's context.
- **Why it matters for us:** Shopify sits in our top-tech data, but this is NOT the Shopify platform itself — it's a specific Rails gem used by independent Shopify Partner apps (which frequently run their own bounty programs). It's dup-resistant precisely because most hunters target Shopify core, not gem-based third-party apps.
- **Fingerprint:** app responds to `/auth/shopify/callback`, cookies/JS reference `shopify_app`/`ShopifyAPI` Rails conventions, embedded-app iframe with App Bridge — check for the gem via exposed `/assets`/error-page stack traces or a leaked `Gemfile.lock`.
- **Test (2-owned-account, human-in-loop per doctrine):** authenticate as Shop A, replay an authenticated request substituting `?shop=<Shop B you own>` — a 200 with Shop B's data = confirmed cross-tenant bypass.
- **Source:** [intel.aikido.dev/cve/AIKIDO-2026-135231](https://intel.aikido.dev/cve/AIKIDO-2026-135231)

## 2. Three fresh named JWT-library CVEs — sharpens WHEN to escalate an alg-confusion LEAD, plus a genuinely new bypass class (`iss`-mismatch) (feeds `class-jwt-attacks.md`)
Our existing alg-swap LEAD primitive is confirmed still the right approach, but three concrete 2026 library CVEs give escalation triggers when tech-fingerprinting identifies these stacks:
- **CVE-2026-22817 (Hono JWT middleware, <4.11.4, Cloudflare Workers/Deno/Bun/Node):** extracted `alg` from the token header without server-side pinning — HS256-signed-with-public-key-as-HMAC-secret bypasses auth outright.
- **CVE-2026-27804 (Parse Server Google/Apple/Facebook OAuth adapters, <8.6.3 and ≥9.0.0 <9.3.1-alpha.4):** same `alg` trust bug in the OAuth login path — `alg:none` strips the signature, `alg:HS256`+pubkey = full account takeover via social login.
- **CVE-2026-23552 (Apache Camel `KeycloakSecurityPolicy`, 4.15.0–4.17.x) — DISTINCT TECHNIQUE, not alg-confusion:** validates the signature correctly but never checks the `iss` claim matches the configured Keycloak realm. **A token from ANY Keycloak realm (including one the attacker controls, if self-registration is open) is accepted** — breaks multi-tenant isolation. **New confirm-primitive idea:** on any Keycloak-fronted target, alongside the alg-swap probe also test whether a token minted from a *different* realm/tenant (own throwaway realm if self-serve Keycloak registration exists, or a second in-scope tenant you own) is accepted — this is a cross-issuer/audience-validation bypass, independent of algorithm.
- **Kid-header path-traversal nuance:** confirmed a real-world variant beyond "kid used as file path" — `kid: ../../../../dev/null` can force some HMAC key-resolution code down a zero-length-key path that certain implementations accept as valid, i.e. `kid` traversal doesn't need to *find* a real key file, just needs to make key resolution fail cheaply in the app's favor.
- **Sources:** [dev.to/iamdevbox JWT CVE fix guide](https://dev.to/iamdevbox/jwt-algorithm-confusion-attacks-cve-2026-22817-cve-2026-27804-and-cve-2026-23552-fix-guide-4ac4), [thehackerwire fast-jwt CVE-2026-34950](https://www.thehackerwire.com/fast-jwt-algorithm-confusion-re-enabled-cve-2026-34950/)

## Checked, not new
- **Nginx CVE table / 1.29.7 in-range status** — already fully and correctly documented in `tech-nginx.md` (verified against nginx.org's current advisory list today; no drift, no new CVEs since the 2026-07-19 entry).
- **Varnish HTTP/2 smuggling (CVE-2026-50052)** — already covered 2026-08-18.
- **GraphQL alias-overloading/batching DoS** — real class but DoS-shaped (resource exhaustion), which our NEVER-list excludes from active testing and most programs decline; not actionable for us as a mint-able primitive, skipping.
- **Cloudflare Bot Management evasion research** — all scraping/automation-evasion framing, not applicable to our detect/confirm tuning.

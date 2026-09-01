# Research digest — detect-tune — 2026-08-31

# Research digest — detect-tune — 2026-08-31

## 1. GraphQL-over-WebSocket **auth-handshake** bypass — a new 2026 CVE cluster across 3 independent frameworks (HIGH PRIORITY — new confirm primitive for `recon_graphql.sh`)

Distinct from what's already in `class-graphql.md` (hidden WS ops, session-persists-after-revocation, WS→SQLi chain). This is the auth **mechanism itself** failing on the WS transport — three unrelated GraphQL implementations shipped the identical bug pattern in 2026:

- **Parse Server — CVE-2026-32594** (CVSS 6.9): the GraphQL WebSocket subscription endpoint bypasses the Express middleware chain entirely — no app/API key needed to execute operations, introspection works even when disabled over HTTP, and query-complexity limits don't apply. Fixed 8.6.40 / 9.6.0-alpha.14.
- **strawberry-graphql — CVE-2026-35523**: the legacy `graphql-ws` subprotocol handler processes a subscription `start` message **without ever requiring `connection_init`** — the auth hook (`on_ws_connect`) is simply never invoked. Both subprotocols (legacy `graphql-ws` + modern `graphql-transport-ws`) are enabled by default and the *client* picks which one via `Sec-WebSocket-Protocol` — so a tester can just ask for the legacy one. Fixed 0.312.3 (vulnerable ≤0.312.2).
- **@neo4j/graphql — GHSA-fcpg-3fw5-vc65**: `connectionParams.jwt` is trusted **unverified** — any client can forge `sub`/`roles` claims in the WS handshake and the library treats them as authenticated identity for `@authentication`/`@subscriptionsAuthorization` directives. Affects 5.0.0–5.12.13, 6.x, 7.0.0–7.5.5.

**Why this matters for us:** it's a *confirm primitive*, not just a discovery signal — and it's unauth-safe to test (introspection/`__typename` only, never real subscription data): open the WS upgrade on the GraphQL endpoint, request the **legacy** `graphql-ws` subprotocol (`Sec-WebSocket-Protocol: graphql-ws`), send a `start`/subscribe message *without* a prior `connection_init` (or with a `connection_init` carrying an obviously-forged JWT), and see if the server executes it anyway (introspection query returns data, or an innocuous field resolves) where the equivalent HTTP request would 401/403. A positive result is a genuine unauth-primitive finding (matches CHAIN-TO-IMPACT LAW — the WS handshake bypass itself is the impact, no further exploitation needed to prove it), not just "introspection enabled."

**Actionable for `recon_graphql.sh`:** after graphw00f engine fingerprint identifies Parse-Server / Strawberry / neo4j-graphql (or any stack exposing a `graphql-ws`/`subscriptions` WS upgrade), add a step: attempt WS connect with the legacy subprotocol + skip/forge `connection_init`, retry the existing introspection query over that channel. If it succeeds where the HTTP endpoint requires auth, mint a LEAD at higher confidence than plain "WS ops exist" (current doc) — this is auth *bypassed*, not merely *undocumented*.

- Sources: [OffSeq CVE-2026-32594](https://radar.offseq.com/threat/cve-2026-32594-cwe-306-missing-authentication-for--2bea7820), [GHSA-vpwc-v33q-mq89 (strawberry-graphql)](https://github.com/strawberry-graphql/strawberry/security/advisories/GHSA-vpwc-v33q-mq89), [GHSA-fcpg-3fw5-vc65 (neo4j/graphql)](https://github.com/neo4j/graphql/security/advisories/GHSA-fcpg-3fw5-vc65)



## Notes on other angles checked this run (no new item)
- **Nginx CVE-2026-42533 / CVE-2026-27654** (map-regex heap overflow; DAV module overflow) — both already exhaustively tracked in `tech-nginx.md` and `class-nday.md` including the exact `nginx/1.29.7` in-range implication and the config-dependent/unsafe-to-probe caveat. Nothing new to add.
- Cloudflare origin-IP bypass and TruffleHog verification tuning — searched, found only material we already apply (Shodan/favicon-hash origin hunting, `--only-verified` gating); no new fingerprint or FP pattern worth a KB change.

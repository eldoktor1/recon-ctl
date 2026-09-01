# PROPOSAL (proposal) for docs/knowledge/class-graphql.md — detect-tune 2026-08-31
_Review and apply manually; not auto-merged into the KB._

## GraphQL-over-WebSocket AUTH-HANDSHAKE bypass — a distinct CVE class from "hidden WS ops" (added 2026-08-31)

The WS-transport notes already in this doc (added 2026-06-21/06-27/07-14) cover *hidden operations*
not visible in HTTP introspection, and *session-persists-after-revocation*. 2026 surfaced a THIRD,
more powerful pattern across three independent GraphQL implementations: the auth **handshake itself**
can be skipped or forged, meaning the WS channel needs **no valid credential at all**, not just a
stale one.

### The pattern (confirmed across 3 unrelated frameworks in 2026)
- **Parse Server (CVE-2026-32594, CVSS 6.9):** the GraphQL WS subscription endpoint bypasses the
  Express middleware chain entirely — executes operations with no app/API key, introspection works
  even when disabled over HTTP, complexity limits don't apply. Fixed 8.6.40 / 9.6.0-alpha.14.
- **strawberry-graphql (CVE-2026-35523):** the **legacy** `graphql-ws` subprotocol handler processes
  a `start` (subscribe) message without ever requiring `connection_init` first — the `on_ws_connect`
  auth hook is never invoked for this code path. Both `graphql-ws` and `graphql-transport-ws` are
  enabled by default; the CLIENT selects the subprotocol via `Sec-WebSocket-Protocol`, so an external
  tester can simply request the vulnerable legacy one. Fixed 0.312.3 (vulnerable ≤0.312.2).
- **@neo4j/graphql (GHSA-fcpg-3fw5-vc65):** `connectionParams.jwt` is trusted **unverified** —
  any client forges `sub`/`roles` claims in the WS handshake payload and the library treats them as
  real authenticated identity for `@authentication`/`@subscriptionsAuthorization` directive checks.
  Affected: 5.0.0-5.12.13, all of 6.x, 7.0.0-7.5.5 (requires `features.subscriptions` +
  `features.authorization` both enabled).

### SAFE confirm primitive (autonomous-eligible, read-only)
1. Find the WS upgrade path (graphw00f/jsintel already surface `graphql-ws`/`/subscriptions` refs
   per the existing notes in this doc).
2. Open the WS handshake requesting the **legacy** subprotocol: `Sec-WebSocket-Protocol: graphql-ws`
   (not `graphql-transport-ws`).
3. Immediately send a subscribe/`start` message with the standard `{__typename}` or standard
   introspection query — WITHOUT sending `connection_init` first (or send `connection_init` with an
   obviously-forged `connectionParams: {jwt: "<fabricated>"}`, never a real/stolen token).
4. Compare to the equivalent HTTP `/graphql` request with no auth header: if HTTP 401/403s but the
   WS channel returns data → **auth-bypass confirmed** on the WS transport specifically. This is
   the impact itself (unauth code execution against a supposedly-gated resolver), not a discovery-only
   signal — mint LEAD at higher confidence than "WS ops exist" per the CHAIN-TO-IMPACT law (the
   handshake failing IS the primitive; no further exploitation needed to prove it).
5. Never use a real subscription to pull actual user data — introspection/`__typename` proves the
   bypass without a harvest.

### Fingerprint prior
graphw00f engine ID = Parse Server / Strawberry / neo4j-graphql (or any stack whose response headers/
error strings match these) + a live WS upgrade on the GraphQL path → run the above before falling back
to the generic "probe hidden WS ops" pass. Version-gate like any n-day: confirm the engine version is
in the vulnerable range before treating a positive WS response as more than a config-hardening check
(some deployments override defaults).

Sources: [Parse Server CVE-2026-32594](https://radar.offseq.com/threat/cve-2026-32594-cwe-306-missing-authentication-for--2bea7820) · [strawberry-graphql GHSA-vpwc-v33q-mq89](https://github.com/strawberry-graphql/strawberry/security/advisories/GHSA-vpwc-v33q-mq89) · [neo4j/graphql GHSA-fcpg-3fw5-vc65](https://github.com/neo4j/graphql/security/advisories/GHSA-fcpg-3fw5-vc65)

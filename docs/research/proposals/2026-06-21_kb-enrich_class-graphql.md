# PROPOSAL (proposal) for docs/knowledge/class-graphql.md — kb-enrich 2026-06-21
_Review and apply manually; not auto-merged into the KB._

## GraphQL over WebSocket — hidden attack surface (added 2026-06-21)

### Why this matters
The graphql-ws transport (`wss://host/graphql-ws`, `wss://host/subscriptions`) is a SEPARATE
code-path from the HTTP `/graphql` endpoint. Authz middleware that protects the HTTP path may
not cover the WS upgrade handler. Keep-alive messages (`{"type":"ka"}`) signal a live WS connection
that may expose internal operations NOT visible in the standard HTTP introspection schema.

### Vulnerability 1 — Token-only-on-connect (subscription hijacking)
The graphql-ws protocol validates credentials once at `connection_init`. After that, the session
is live until the socket closes. Disclosed on Shopify: a user whose role was removed mid-session
retained the WS subscription and continued executing GraphQL operations until the connection dropped.

**Test (operator — authed):** log in as low-priv A, capture the WS `connection_init` payload,
downgrade the role server-side (via A's own admin if you have it, or wait for a session boundary),
then attempt a subscription/query that should now be unauthorized. If data flows = session not
revalidated.

**Fingerprint:** look for `{"type":"connection_init"}` / `{"type":"ka"}` in browser DevTools →
Network → WS frames. Protocol header: `Sec-WebSocket-Protocol: graphql-ws` or `graphql-transport-ws`.

### Vulnerability 2 — IDOR via hidden WS operations
Client-side JS often contains graphql-ws operation calls that never appear in introspection (they
skip the HTTP schema). Reverse-engineer `main.js` / `chunk.*.js` for `createClient`, `subscribe`,
or `execute` calls — these reveal operation names + variable shapes.

**Discovery (autonomous, safe):** JS-intel (`recon_jsintel.sh`) already collects `main.js`; grep
for `graphql-ws`, `createClient`, `subscribe(`, `SubscriptionClient`, WebSocket URLs containing
`/graphql`. Operation names found this way → add to the graphql_candidates worklist.

### Vulnerability 3 — IDOR→SQLi escalation chain (high-entropy ID bypass)
High-entropy IDs (UUIDs, 25-digit numeric strings) are NOT safe from IDOR if the endpoint also
has injection. April 2026 real chain (fintech):
1. GraphQL WS endpoint handles `readDocument(id:)` — IDOR exists but ID has 25-digit entropy.
2. Fuzz the `id` param with `'`, `||'|'||` (PostgreSQL concat), `"`, `1 AND 1=1` etc.
3. Verbose PostgreSQL error fires → error-based SQLi → column names / table names extracted.
4. Craft `id: "1||'|'||(SELECT id FROM documents LIMIT 1)||'|'||1"` → leaks real high-entropy IDs.
5. Feed leaked IDs back into the original IDOR endpoint → confirmed cross-user document read.

**Lesson:** "UUIDv4 / high-entropy ID = needs-harvest" is still valid for RANKING, but do NOT
write off an IDOR candidate purely because the ID has high entropy — check every adjacent op on
the same resource for injection. If SQLi fires on any path touching that object, the IDOR is
escalatable.

**Payload starters (error-based PostgreSQL via WS):**

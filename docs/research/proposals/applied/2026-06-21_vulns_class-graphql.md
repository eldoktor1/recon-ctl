# PROPOSAL (proposal) for docs/knowledge/class-graphql.md — vulns 2026-06-21
_Review and apply manually; not auto-merged into the KB._

## GraphQL WebSocket (graphql-ws) — SQLi + IDOR Chain Technique

**Source:** [Medium — DarkyOS, April 2026](https://medium.com/@DarkyOS/sql-injection-in-graphql-websocket-escalated-to-pii-document-leak-09ba7ad2800a)

### Why graphql-ws is under-hunted
Most scanners and hunters probe `/graphql` only. WebSocket-upgrade endpoints (`/graphql-ws`, `/graphql/subscriptions`, `/subscriptions`) carrying GraphQL-over-WebSocket (the `graphql-ws` protocol) are routinely missed. Operations on these endpoints often lack the same authorization checks as their HTTP counterparts, and error handling is frequently more verbose.

### Attack chain pattern
1. `/graphql-ws` appears to send only keepalive frames (`{"type":"ka"}`) — looks dormant.
2. Client JS contains hidden operations (e.g. `readDocument`, `lockDocument`) that accept an `id` param.
3. Fuzzing the `id` field with alphanumeric/special chars triggers **verbose database errors** exposing schema details (column names, table names, DB engine).
4. Error-based SQLi (PostgreSQL `||` string concat / type-coercion) extracts actual user records including high-entropy IDs that protect IDOR.
5. Extracted IDs fed to the auth-blind WS operation → full IDOR / document access.

**Key insight:** Neither bug alone is exploitable (IDOR gated by high-entropy IDs; SQLi without IDOR is limited) — but chained, they yield a critical. The SQLi "unlocks" the IDOR.

### Detection / hunting steps
- Crawl/jsintel for: `/graphql-ws`, `/graphql/subscriptions`, `/subscriptions`, `/ws/graphql`
- Attempt WebSocket upgrade (`Connection: Upgrade`, `Upgrade: websocket`, `Sec-WebSocket-Protocol: graphql-ws`)
- Extract operations from client JS bundles (look for `graphql-ws` npm package usage, subscription queries)
- Fuzz `id`/`documentId`/`nodeId` params with: `'`, `"`, `1'`, `1 OR 1=1`, alphanumeric strings, special chars
- Watch response bodies for: PostgreSQL/MySQL/MSSQL error strings, column names, schema identifiers
- If SQLi fires → LEAD for human 2-account chain (never enumerate third-party IDs)

### FP notes
- A WS endpoint that only accepts valid UUID/numeric IDs and returns generic 400s = no SQLi surface
- Authorization checks at the WS layer (JWT validated per-message) = IDOR unlikely — still check SQLi
- Verbose errors in dev/staging but sanitized in prod = LEAD, not confirmed

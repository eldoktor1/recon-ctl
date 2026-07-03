# PROPOSAL (proposal) for docs/knowledge/class-graphql.md — vulns 2026-06-27
_Review and apply manually; not auto-merged into the KB._

## GraphQL WebSocket Endpoint Blind Spot (added 2026-06-27)

Standard HTTP introspection probes and scanners target `/graphql` HTTP endpoints only. WebSocket-based GraphQL endpoints (`/graphql-ws`, `/subscriptions`, `/ws`) are hidden from them, carry the same resolver logic, and often lack WAF coverage. Find them via:
- JS-intel: search endpoints.jsonl for `graphql-ws`, `/subscriptions`, `/ws`
- `recon-kr` kiterunner: kitebuilder wordlist includes WS-adjacent paths

**Independent probing required:** Test object-ref arg ownership and type-mismatch inputs separately from the HTTP schema.

**Two-stage IDOR→SQLi chain (April 2026, $2k Critical):** An IDOR with high-entropy IDs (not bruteforceable alone) became critical when the same endpoint had a type-mismatch SQLi. Sending alphanumeric where numeric expected triggered verbose PostgreSQL errors leaking table/column names → error-based extraction of valid IDs → fed back into IDOR to access other orgs' documents. The injection point was the *ID type constraint*, not a string argument. Source: https://medium.com/@DarkyOS/sql-injection-in-graphql-websocket-escalated-to-pii-document-leak-09ba7ad2800a

## GraphQL Batch Query Abuse for IDOR Rate-Limit Bypass (added 2026-06-27)

GraphQL batching (POST body as a JSON array: `[{"query":"..."},{"query":"..."}]`) is supported by Apollo, Hasura, and most frameworks by default. Per-request rate limits don't apply per operation in a batch — use this when object-ownership IDOR exists but per-request throttling would prevent enumeration. 

Test: POST `[{operationName:null, query:"{ sensitiveQuery(id: 1) { ... } }"}, ...]` — if the server returns an array of results, batching is enabled.

Paid $12,500 CVSS 9.1 on a fintech GraphQL API (April 2026). Source: https://infosecwriteups.com/graphql-security-how-i-found-and-exploited-critical-idor-and-authorization-bypass-in-a-42ab78e13642

# PROPOSAL (proposal) for docs/knowledge/class-idor.md — kb-enrich 2026-06-21
_Review and apply manually; not auto-merged into the KB._

## Authorization bypass techniques — new section (added 2026-06-21)

These patterns are NOT the "where the id hides" surface enumeration already in this doc — they
are AUTHZ BYPASS TRICKS: ways to get the server to skip the ownership check even after the id
is found.

### 1. Outdated API version
`/v2/invoices/123` → 403; `/v1/invoices/123` → 200 with data. Authz enforcement is often added
on the NEW version and backported inconsistently (or the v1 endpoint was simply forgotten).
**Test:** when a target has `/v2/` or `/api/v2/` in paths, always replay IDOR candidates against
`/v1/` and `/v3/` variants. `recon_jsintel.sh` endpoint mining often surfaces old version paths
that no longer appear in the current UI.

### 2. Array / JSON-type coercion
Some authz middleware checks `if (param.userId === session.userId)` — a strict equality that fails
when the param is an array. Sending `{"userId": [victimId]}` instead of `{"userId": victimId}` can
bypass the comparison: the array passes deserialization, the business logic extracts `[0]`, the
authz check sees an array (truthy, not equal to a string → guard skips or throws a handled exception
that defaults to "allowed").

Variants:
- `{"id": [123]}` instead of `{"id": 123}`
- `{"id": {"eq": 123}}` (object injection — some ORMs accept filter-shape inputs)
- `{"id": "123"}` vs `{"id": 123}` — type coercion across string/int can also skip a guard

### 3. Filter-object IDOR (REST + GraphQL)
APIs that appear self-scoped (`GET /me/orders`) sometimes expose a POST body or URL param that
overrides the session-derived scope:
- REST: `POST /orders/search` body `{"filter": {"userId": "victimId"}}` — the resolver uses
  the filter value directly instead of the session identity.
- GraphQL: `query { orders(filter: { userId: "victimId" }) { ... } }` — same pattern, common
  on search/list resolvers.
- Nested inputs: `{"input": {"account": {"id": victimId}}}` — buried two levels deep.

These are ESPECIALLY common on list/search endpoints because the dev added filtering for
admin use-cases and forgot that the filter runs pre-auth.

### 4. Content-type switching
Changing `Content-Type: application/json` → `application/x-www-form-urlencoded` or
`application/xml` can route through a different middleware stack. Authz validation added
only for the JSON path is skipped for the alternate content-type.
**Quick test:** replay the IDOR probe with `Content-Type: application/x-www-form-urlencoded`
and body `id=victimId`. Some frameworks auto-parse both forms; the authz guard may only wrap
the JSON parser.

### 5. High-entropy UUID ≠ safe from IDOR (the escalation trap)
"UUIDv4 / 25-digit high-entropy ID = needs a leak vector" is correct for RANKING, but do NOT
write off a UUID-IDOR candidate purely on entropy grounds. The April 2026 chain:
- A 25-digit document ID was "unguessable" → IDOR deprioritized.
- Fuzzing the SAME endpoint with SQLi payloads revealed error-based PostgreSQL injection.
- The injection leaked real document IDs from the DB.
- Those IDs fed back into the IDOR endpoint confirmed cross-user document access.

**Rule:** when ranking IDOR candidates, pair UUID-type entries with a note "check for injection on
same resource path." If `recon_xss_sqli_candidates.py` or jsintel surfaces an injectable param on
the same host + same path prefix, escalate the UUID-IDOR candidate's priority.

### Sources
- IDOR checklist (2025): https://ahmed-tarek.gitbook.io/security-notes/owsap-top-10-2025/a01-broken-access-control/checklists/idor-checklist
- UUID IDOR → SQLi chain: https://medium.com/@DarkyOS/sql-injection-in-graphql-websocket-escalated-to-pii-document-leak-09ba7ad2800a (Apr 2026)
- Nextcloud BOLA/IDOR disclosed: https://hackerone.com/reports/3382343 (Apr 2026)

# PROPOSAL (proposal) for docs/knowledge/class-idor.md — kb-enrich 2026-08-15
_Review and apply manually; not auto-merged into the KB._

## 2026-08-15 addition — empirical BOLA taxonomy (source: arxiv.org/abs/2605.25865, 84 confirmed cases)

### Six BOLA families (know all of them, not just direct-object-reference)
1. **Action-Level Object BOLA (41.7%, MOST COMMON)** — unauthorized *state-changing* op, not read.
   Pattern: attacker supplies victim's identifier (email/id) in a request BODY to a mutating endpoint
   without the server cross-checking it against the authenticated session. Example (Mozilla real case):
   `POST /v1/account/destroy` with victim's email in body, no session-email verification → account deleted.
   **Implication for us: our IDOR ranker currently weights read/GET endpoints heavily — state-changing
   POST/PUT/DELETE endpoints that accept an object-owner field in the BODY (not just the URL) are now the
   single largest confirmed BOLA family and should be ranked at least as high.**
2. **Direct Object Reference (36.7%)** — classic ID-in-URL swap. Still dominant; sequential integers are
   36.9% of all identifier types even in 2023-2026 disclosures from *mature* programs.
3. **Tenant Isolation BOLA (8.3%)** — arbitrary `organization_id`/`tenant_id`/`workspace_id` param lets
   cross-org access (real case: HackerOne's own `POST /bugs.json` accepting arbitrary org_id).
4. **Workflow-Context BOLA (6.0%)** — authorization checked at object CREATION time but never re-evaluated
   as the object's lifecycle changes (deactivated user, archived record) — stale permission grants.
5. **Chained Disclosure BOLA (4.8%)** — requires harvesting an identifier from one endpoint before it's
   usable against a second, unrelated endpoint. Worth flagging endpoint PAIRS, not just singles.
6. **Object Rebinding BOLA (2.4%)** — server trusts a client-supplied ownership field in the body
   (`owner_id`, `msg.Sender`) instead of deriving ownership from the session.

### Identifier-type exploitation notes
- GraphQL global IDs (9.6% of cases): base64 "opaque" IDs decode to `Gid://App/Model/<sequential-int>` —
  decode/increment/re-encode. See [[class-graphql]] cross-ref below.
- Non-sequential IDs (UUID/hash, 39.2%) are NOT automatically safe — the ID is usually leaked via a
  *different* endpoint (listing/search/notification/webhook payload) even when the primary endpoint is
  unguessable. Always check adjacent endpoints for ID leakage before writing off a UUID-keyed resource.

### Severity signal
- Horizontal (peer-to-peer) is 85.7% of cases but Vertical (priv-esc, standard-user→admin-object) is only
  11.9% of cases yet disproportionately Critical severity — worth flagging vertical candidates for
  priority even though they're rarer.
- Action distribution: Read 52.4%, Modify 20.2%, Delete 15.5% (often irreversible + evades monitoring),
  Trigger 10.7% (forced workflow initiation — e.g. re-sending a payment/notification as another user).

### Meta note (methodology caution)
Only 42% of HackerOne reports *tagged* IDOR/IAC by researchers were confirmed genuine in-scope BOLA under
rigorous review — i.e. self-tagging is noisy; don't trust a report's own IDOR label without re-deriving
the primitive.

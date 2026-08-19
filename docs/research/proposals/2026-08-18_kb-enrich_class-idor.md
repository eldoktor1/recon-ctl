# PROPOSAL (proposal) for docs/knowledge/class-idor.md — kb-enrich 2026-08-18
_Review and apply manually; not auto-merged into the KB._

## Empirical BOLA taxonomy (arXiv 2605.25865, 84 confirmed bug-bounty BOLA cases, 2023-2026)

**Six-category breakdown by prevalence — test in this order, highest-yield first:**
1. **Action-Level Object BOLA (41.7%)** — unauthorized state-changing ops (delete/modify/trigger)
   on an object you don't own. Higher yield than read-only IDOR; prioritize mutation/action
   endpoints (`DELETE`, `PATCH`, `/trigger`, `/cancel`, `/approve`) over GET when ranking 2-account
   swap candidates.
2. **Direct Object Reference (36.9%)** — classic ID-substitution, mostly read access.
3. **Tenant Isolation BOLA (8.3%)** — crossing org/workspace boundaries (not just object-owner
   boundaries) — test multi-tenant SaaS APIs for org_id/workspace_id swap, not just user_id.
4. **Workflow-Context BOLA (6.0%)** — exploiting an object's lifecycle STATE (e.g. accessing an
   object only reachable mid-workflow, like a draft/pending-approval record, after the workflow
   moved on or before it started).
5. **Chained Disclosure BOLA (4.8%)** — multi-step: one endpoint LEAKS another user's object ID,
   a second endpoint consumes it. Cross-endpoint leakage alone is 7.1% of cases — always check
   what IDs a "safe" list/search endpoint discloses before ruling an app clean.
6. **Object Rebinding BOLA (2.4%)** — client-supplied ownership field trusted server-side (e.g. a
   PATCH body containing `"owner_id": <other-user>"` and the server re-parents the object to you).
   Rare but distinctive — check every mutation body for an ownership/owner_id/user_id field the
   client shouldn't be allowed to set.

**Identifier-format reality check:** sequential integers are still 36.9% of ALL cases and 60.8%
among cases with a determined format — the single most common exploitation mechanism (22.6% of
all 2023-2026 disclosures) is still plain sequential enumeration, even at sophisticated orgs.
**UUIDs/opaque IDs do NOT eliminate risk** (39.2% of known-format cases were non-sequential:
UUID/encoded/username/email/hash) — don't deprioritize a target just because IDs look opaque.

**GraphQL Global ID (GID) decode/increment/re-encode pattern** (9.6% of confirmed cases combined,
seen on HackerOne/GitLab/Shopify disclosures): GraphQL GIDs are base64(`Type:123`)-style opaque
strings. Attack: base64-decode a GID you own → note the underlying sequential integer → increment
→ re-encode → substitute into a `node(id: ...)` query or mutation referencing a different user's
object. Standalone encoded-ID manipulation is 6.0%, GID leakage specifically 3.6%. Add to
`recon-graphql` candidate reasoning: any GID-shaped argument (base64 string in a `node`/object arg)
is a decode-and-check candidate, not just a raw numeric-ID one.

Source: [Broken Object Level Authorization in the Wild — arXiv 2605.25865](https://arxiv.org/html/2605.25865v1)

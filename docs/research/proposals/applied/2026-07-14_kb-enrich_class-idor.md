# PROPOSAL (proposal) for docs/knowledge/class-idor.md — kb-enrich 2026-07-14
_Review and apply manually; not auto-merged into the KB._

## Bypass payload shapes when a direct ID-swap is blocked (added 2026-07-14)
Source: 2024-2025 bug-bounty case studies + OWASP A01:2025 (Broken Access Control).

When a straightforward `?id=<victim>` swap correctly 403s/404s, these SHAPES are documented to
routinely bypass the same authorization check because the backend framework auto-coerces them
before the check runs (or the check only looks at the "canonical" param form). Human-tester
checklist, 2-owned-account only, try each against the SAME endpoint that blocked the naive swap:
- **HTTP Parameter Pollution**: duplicate the param — `user_id=<mine>&user_id=<victim>` — try both
  orderings (some stacks take first occurrence, some last).
- **Array wrap**: `{"user_id":[<victim>]}` or `{"user_id":[<mine>,<victim>]}` — ORM/query-builder
  layers sometimes silently `IN`-match an array where the auth check only validated a scalar.
- **Nested-object wrap**: `{"user":{"id":<victim>}}` instead of a flat `user_id`.
- **Type juggling**: send the numeric ID as a string (`"123"` vs `123`) or vice versa — loose
  equality in the authz check vs strict equality in the data-fetch layer can diverge.

**Adjacent class — mass assignment (auto-binding).** If an endpoint auto-binds JSON body fields
onto a backend model without an allowlist, a client can add fields never in the API's documented
schema (`role`, `is_admin`, `owner_id`, `verified`) to a normal update/create call. Test by diffing
a request against the endpoint's OpenAPI/Swagger/GraphQL-schema field list (we already harvest
these via jsintel/recon-graphql) — any writable field NOT in the documented request schema is a
mass-assignment candidate. Own-account PoC only (set a benign field on your own object; never a
privilege field on a shared/third-party resource).

Sources:
- https://0xgaurang.medium.com/case-study-bypassing-idor-via-parameter-pollution-78f7b3f9f59d
- https://owasp.org/www-community/attacks/insecure_direct_object_reference
- https://arxiv.org/pdf/2507.15984 (BACFuzz, broken-access-control fuzzing, Jul 2025)
- https://arxiv.org/pdf/2405.01111 (mining REST APIs for mass assignment)

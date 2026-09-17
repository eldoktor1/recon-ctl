# PROPOSAL (proposal) for docs/knowledge/class-idor.md — kb-enrich 2026-09-17
_Review and apply manually; not auto-merged into the KB._

## Bypass technique: HTTP Parameter Pollution on the ID param
When an endpoint checks the FIRST or LAST occurrence of a duplicated parameter inconsistently between the
authz-check layer and the data-fetch layer, supplying the same ID parameter twice — once with your own
(owned) ID and once with the target ID — can pass the ownership check against one value while the query
executes against the other. Test both orderings (`id=<own>&id=<target>` and reverse) since frameworks split
on first/last inconsistently (PHP tends to use the LAST, ASP.NET/Node often the FIRST — verify per-app, don't
assume). This is a variant worth adding to our differential-testing pass alongside the existing UUID/numeric
ID-type scoring. — [0xgaurang case study](https://0xgaurang.medium.com/case-study-bypassing-idor-via-parameter-pollution-78f7b3f9f59d), [Intigriti advanced IDOR guide](https://www.intigriti.com/blog/news/idor-a-complete-guide-to-exploiting-advanced-idor-vulnerabilities)

## Bypass technique: IDOR + mass assignment stacked (own-account escalation, not third-party access)
Distinct from classic IDOR: an update endpoint (`PUT/PATCH /api/users/{id}`) correctly checks that `{id}` ==
the caller's own ID (so it's NOT vulnerable to cross-user IDOR) — but the body-binding layer accepts EXTRA
properties beyond the ones the UI sends (e.g. `role`, `is_admin`, `tier`, `org_id`, `verified`) with no
allowlist. On your OWN account, send the update with an added privileged field; if it sticks, that's a
mass-assignment privesc, not a cross-tenant IDOR — reportable under our ACTIVE-PoC doctrine (own-account,
minimal, prove-then-stop) without ever touching another user's object. Also test with `X-HTTP-Method-Override:
PATCH`/`PUT` on a plain POST — some frameworks only apply field-allowlisting middleware to the "real" verb,
not an overridden one. — [Mass assignment vulnerability overview](https://en.wikipedia.org/wiki/Mass_assignment_vulnerability), [CodeAnt 2026 IDOR guide](https://codeant.ai/blogs/idor-vulnerabilities)

## Cross-endpoint HTTP-method authorization gap
Authorization middleware is sometimes bound to specific verbs (e.g. only GET is auth-checked, PUT/DELETE
inherit a shared route but skip the check, or vice versa). When an object-ref endpoint 403s on GET, always
retry PUT/POST/DELETE/HEAD/OPTIONS and vice versa before concluding the endpoint is protected — a
verb-scoped gap is a distinct root cause from ID-based IDOR and won't show up in our current param-based
ranker at all. — [0xSs0rZ 401/403 bypass notes](https://0xss0rz.gitbook.io/0xss0rz/pentest/web-attacks/bypass-403-401)

**Confidence note:** a broader empirical taxonomy of 100+ disclosed BOLA reports (arXiv 2605.25865,
"Broken Object Level Authorization in the Wild") confirms predictable/sequential ID encoding and
direct-object-mapping-without-abstraction as the dominant real-world pattern — consistent with our
existing numeric>UUID ranking, no ranker change indicated. PDF text extraction was partial; treat as
directional confirmation, not a new source of hard rules.

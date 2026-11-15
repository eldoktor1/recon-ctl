# PROPOSAL (proposal) for docs/knowledge/class-idor.md — kb-enrich 2026-09-08
_Review and apply manually; not auto-merged into the KB._

## Batch/bulk-endpoint authorization gap (2026-09-08)
**Batch endpoints (array-of-IDs body/param) commonly authorize the ROUTE but not each object
inside the array** — ownership is checked once for the caller, then every ID in the array is
processed without a per-object ownership re-check. Shapes to flag at the same priority as a
single object-ref param: `POST .../batch {"ids":[...]}`, bulk export/delete, and GraphQL
mutations taking `ids: [ID!]!`. A clean single-ID IDOR test on the same route does NOT rule this
out — the batch variant is a distinct test. Confirm only with 2 OWNED IDs (mixed-array probe:
`[own_id_A, own_id_A, own_id_B]` where B is your second owned account) per our IDOR hard line —
never a guessed/third-party ID in the array.
Source: https://www.levo.ai/resources/blogs/bola-idor-waf-fail

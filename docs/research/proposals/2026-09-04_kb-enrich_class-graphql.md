# PROPOSAL (proposal) for docs/knowledge/class-graphql.md — kb-enrich 2026-09-04
_Review and apply manually; not auto-merged into the KB._

## Batch-position auth/cache bypass — a new LEAD shape (added 2026-09-04)

Distinct from the existing "aliasing rate-limit bypass" (throttle-blindness) and "nested-field auth
gap" (field-resolver skips auth) notes above — this is a **batch-array-position** bypass:

1. **First-op-only auth check:** some authorization middleware validates only the first query/
   mutation object in a batched JSON-array POST (`[{query:"..."},{query:"..."}]`), then treats the
   rest of the array as pre-authorized. Test: batch a benign already-permitted query first, followed
   by a sensitive object-ref query second — if the second returns data that a solo unauth request to
   the same query would 401/403 on, the batch position itself is the bypass.
2. **Cache-warmup-then-piggyback:** if a shared response cache sits in front of the resolver and
   keys loosely (by field+args, not by caller identity), a batch that queries your OWN object first
   can warm a cache slot; a subsequent aliased field for a DIFFERENT object id in the same batch may
   ride the warm cache path and skip re-authorization. No disclosed report found for this run — flag
   as an UNCONFIRMED testing hypothesis, not a proven technique; worth a quick differential test
   (solo request vs batched-after-own-query) next time a sensitive object-ref query is on the
   candidates worklist, but don't write it up as a known-class until we've seen it fire.

Detection stays unauth-safe: batch your own already-authorized query + a second aliased query
against a DIFFERENT object id (owned second account only — never a guessed/third-party id), compare
against the same second query sent solo. A result-shape difference (data vs auth-error) is the LEAD;
still human/2-account confirm per the existing hard line — this only adds a batch-position test to
the existing worklist methodology, no new autonomous primitive.

### Sources (roundup-level, not a single disclosed case — lower confidence than our other entries)
- ringsafe.in/graphql-security-beyond-introspection
- beaglesecurity.com/blog/article/graphql-attacks-vulnerabilities.html

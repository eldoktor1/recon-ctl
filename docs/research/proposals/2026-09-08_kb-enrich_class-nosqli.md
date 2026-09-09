# PROPOSAL (proposal) for docs/knowledge/class-nosqli.md — kb-enrich 2026-09-08
_Review and apply manually; not auto-merged into the KB._

## Nested-operator sanitizer bypass (2026-09-08)
**Denylist sanitizers that only walk the top level of the filter object miss operators nested
inside `$or`/`$and`/`$nor`.** Reference case: CVE-2025-23061 (GHSA-vg7j-7cwx-8wgw, CVSS 9.1) — a
Mongoose fix blocked `$where` at the top level of a `populate().match` object, but `{$or:
[{$where: "..."}]}` still reached the query engine because the check never recursed into arrays
under logical operators. Fixed Mongoose ≥8.9.5/7.8.4/6.13.6, but the PATTERN is general: any
hand-rolled Express/Mongo input sanitizer that denylists `$where`/`$function`/`$accumulator`/
`$expr` by inspecting only top-level keys has the same blind spot. Safe unauth/differential test:
compare response/timing for `{"field":{"$or":[{"$where":"sleep(3000)"}]}}` against the flat
(already-blocked) form — a difference proves the gap without any data harvest.
Sources: https://github.com/advisories/GHSA-vg7j-7cwx-8wgw ,
https://www.opswat.com/blog/technical-discovery-mongoose-cve-2025-23061-cve-2024-53900

# PROPOSAL (proposal) for docs/knowledge/class-sqli.md — kb-enrich 2026-08-18
_Review and apply manually; not auto-merged into the KB._

## ORM raw-query escape hatches + unparameterizable ORDER BY (2025-2026)

Every major ORM (Hibernate, Django ORM, ActiveRecord, Prisma) parameterizes VALUES correctly by
default but exposes raw-SQL escape hatches for edge cases (Prisma `$queryRawUnsafe`, ActiveRecord
`.where("... #{input}")`, Django `.raw()`/`.extra()`) — when a target's stack is one of these
(check jsintel/error pages for stack traces), a param that looks "safe" because most endpoints are
parameterized may still hit one of these raw paths on a specific route (sort/filter/search/export
endpoints are the common offenders).

**ORDER BY is structurally unparameterizable** — no ORM/query builder can bind a column name or
ASC/DESC as a value, only as string interpolation, so any `?sort=`/`?order=`/`?orderBy=` param is a
disproportionately high-yield target for our `'` vs `''` differential even on apps that are otherwise
fully parameterized. Prioritize sort/order params in the SQLi candidate ranker.

⚠️ Note: a "JSON-based WAF bypass" (JSON_LENGTH() payload) surfaced in this search is Claroty Team82
research from **Dec 2022**, already patched by AWS/Cloudflare/F5/Imperva/Palo Alto (F5 sig 200102064)
— NOT new, do not treat as a live bypass against current WAF versions.

Sources: [Afine — SQLi in the age of ORM](https://afine.com/sql-injection-in-the-age-of-orm-risks-mitigations-and-best-practices), [Hive Security — SQLi 2026 guide](https://hivesecurity.gitlab.io/blog/sql-injection-complete-guide-2026/)

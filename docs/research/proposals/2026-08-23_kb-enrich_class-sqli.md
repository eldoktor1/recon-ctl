# PROPOSAL (proposal) for docs/knowledge/class-sqli.md — kb-enrich 2026-08-23
_Review and apply manually; not auto-merged into the KB._

## JSON-syntax WAF bypass + ORM raw-query escape hatches (added 2026-08-23)

### JSON-wrapped payload bypass (foundational technique, absent from our KB — flag as
mostly-patched-but-still-useful-as-a-fallback, not a fresh universal hole)
WAF signature libraries historically don't parse SQL keywords wrapped inside JSON function
syntax on JSON-supporting backends (MySQL/PostgreSQL/MSSQL/SQLite):

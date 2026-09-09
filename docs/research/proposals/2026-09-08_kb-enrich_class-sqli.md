# PROPOSAL (proposal) for docs/knowledge/class-sqli.md — kb-enrich 2026-09-08
_Review and apply manually; not auto-merged into the KB._

## WAF-bypass addendum (2026-09-08)
**JSON-wrapped SQLi bypasses signature-based WAFs.** MySQL/PostgreSQL/SQLite/MSSQL all execute
SQL functions embedded in JSON syntax, and as of Claroty Team82's disclosure most major WAF
vendors (Palo Alto, AWS, Cloudflare, F5, Imperva — patched post-disclosure) did not parse JSON
in their SQLi signature engine. Example bypass form:
`' or JSON_LENGTH("{}") <= 8896 union distinctrow select @@version#`
When our safe `'` vs `''` differential gets blocked by an obvious WAF interstitial (not a 403 from
the app itself), retry the SAME differential JSON-wrapped before marking the param protected —
this is a bypass check on an existing safe primitive, not a new destructive technique.
Source: https://www.picussecurity.com/resource/blog/waf-bypass-using-json-based-sql-injection-attacks

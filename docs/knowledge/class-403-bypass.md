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

---

# 403 TAXONOMY — classify before you chase (measured 2026-08-16)

A 403 in `recon_alive` is FOUR different things. Chasing them as one class is what turns an
evening into dead ends. Classify FIRST — the discriminator is cheap.

| what you see | real cause | recoverable? |
|---|---|---|
| Real page renders in browser, 403 to curl | curl fingerprint / managed challenge | **YES — use the browser** |
| `Attention Required! \| Cloudflare` in the BROWSER too | CF custom Firewall Rule (err 1020) matching our ASN | No — different exit didn't help |
| `Error: Access denied` + page prints **your own IP** | CF 1020, IP/ASN-matched | No |
| `Request forbidden by administrative rules.` (~106 B) | origin nginx/Apache **path ACL**, blocks everyone | No — by design, not about us |
| CF **522 Connection timed out** | origin is DOWN | Not a block at all |
| Redirects to an SSO/SAML login (e.g. Cloudflare Access) | auth-gated app | Not a block — needs creds |

## The discriminators (cheapest first)
1. **curl default UA vs curl browser UA** — measured on 28 hosts: 24/28 identical 403 both ways
   ⇒ **User-Agent is almost never the cause.** Don't bother spoofing UA.
2. **Real browser (JS + TLS fingerprint + cookies)** — the only thing that recovers the challenge
   class. Verified: `au.seek.com` and `a23.paddypower.com` both 403 to curl, both render in Brave
   on the SAME Mullvad exit.
3. **Read the block page body** — it names the cause. CF prints your IP + a Request ID for 1020;
   nginx prints `Request forbidden by administrative rules`; 522 says connection timed out.

## Egress findings (2026-08-16, measured not assumed)
- **Switching Mullvad exit does NOT clear a CF 1020 rule.** Tested Tzulo `23.234.92.199` →
  DataPacket `37.19.210.35` (Denver): `*.onlineauth.prod.outfra.xyz` still 403 on all three hosts.
  The rule matches ASN/datacenter category, not a single IP ⇒ that SEEK estate is out of reach;
  deprioritise rather than re-probe.
- **Never trade the VPN for reachability.** Mullvad stays sole egress; a non-VPN path is not an
  option regardless of how much surface it would unblock.
- **Sizing honesty:** ES showed 111k in-scope+paying 403s, 31.5k with Cloudflare Bot Management.
  A 5-host browser sample recovered 1. Do NOT treat the Bot-Management count as a recovery
  estimate — the pile is mostly genuine WAF rules, dead origins and SSO-gated apps.

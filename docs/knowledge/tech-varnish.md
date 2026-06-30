# Varnish Cache Detection & Attack Surface

Fingerprinting and exploitation surface for Varnish-fronted hosts. Relevant for web-cache deception (WCD) and unauthenticated cache management bugs.

## Detection fingerprints

| Header | Value | Meaning |
|--------|-------|---------|
| `X-Varnish` | single integer | Cache MISS (this request only) |
| `X-Varnish` | two space-separated integers | Cache HIT (stored-id + request-id) |
| `Via` | `1.1 varnish (Varnish/6.x)` | Version leak |
| `Age` | `0` | Just missed / not cached |
| `Age` | `>0` | Cached; value = seconds since stored |
| `X-Cache` | `HIT` or `MISS` | Common VCL config output |

**Confirm Varnish:** `X-Varnish` header present + `Via` contains "varnish" = confirmed Varnish. One header alone is insufficient (other proxies emit similar headers).

## Unauthenticated PURGE (reportable bug)

```bash
curl -X PURGE https://<target>/<path> -sv 2>&1 | grep -E "< HTTP|< Age|< X-Varnish"

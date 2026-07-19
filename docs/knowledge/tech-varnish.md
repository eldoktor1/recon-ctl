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
```

### Safe (non-state-changing) detection — OPTIONS `Allow:` probe (added 2026-07-11)
The `curl -X PURGE` above is a **state-changing** action (issues a real cache invalidation) and stays
operator-gated — NOT part of the autonomous safe-probe set. To fingerprint the misconfig *without* issuing
a PURGE, send `OPTIONS` and inspect the `Allow:` response header for `PURGE` (with no auth challenge):
```bash
curl -X OPTIONS https://<target>/<path> -sv 2>&1 | grep -iE "< allow|< HTTP"
```
`Allow: ...PURGE...` on an unauthenticated OPTIONS = LEAD (deployment likely accepts unauth PURGE). Zero
risk — nothing is purged. Confirming actual unauth cache invalidation/poisoning (the real `-X PURGE`) stays
operator-gated.

## Active CVEs (2026)

### CVE-2026-34475 — URL Mishandling → Cache Poisoning / Auth Bypass (CVSS 5.4)
- **Affected:** Varnish Cache < 8.0.1; Varnish Enterprise < 6.0.16r12.
- **Class:** Mishandled root-path `/` requests under an `unchecked req.url` VCL → cache-key confusion →
  cache poisoning or auth-boundary bypass.
- **Fingerprint (unauth):** `Via: 1.1 varnish` + `X-Varnish:` headers; some configs leak version in
  `X-Varnish-Backend`.
- **WCD lane note:** directly amplifies the web-cache-deception lane for Varnish ≤ 8.0.0 — flag matched
  hosts in the WCD briefing.
- **Source:** https://security.glexia.com/cves/CVE-2026-34475 · ⚠️ LLM-sourced — NVD/version-verify before minting.


---
<!-- applied-proposal: 2026-07-17_vulns_tech-varnish + 2026-07-19_vulns_tech-varnish -->
### Applied research — vulns (2026-07-17 / 2026-07-19) — CVE-2026-34475 priority note

## CVE-2026-34475 — probe priority guidance (2026-07-19)
The CVE-2026-34475 primitive (req.url canonicalization, see Active CVEs section above) is a genuine
confirmable primitive — not a heuristic path-confusion guess — on any host fingerprinted as Varnish
< 8.0.1. **Prioritize this over generic path-confusion WCD probes** on matched hosts: the root-path
HTTP/1.1 differential is a named CVE with a defined mechanism, higher confidence than a generic
suffix-path cacheability flip. Unauth fingerprint: `X-Varnish` / `Via: 1.1 varnish` response
headers → version-gate before treating as more than a LEAD (version usually not banner-exposed —
confirm behaviorally). Source: https://github.com/advisories/ghsa-m9gq-cmcj-p62x

# tech-unifi — Ubiquiti UniFi OS: Recon, Fingerprinting & Known Vulns

## Product overview
UniFi OS is Ubiquiti's controller OS for network hardware (UDM-Pro, UCG, CloudKey). Bug-bounty programs covering Ubiquiti infrastructure include large hardware estates (27+ consoles confirmed in our ES under wildcard scopes). The product-class endpoint `/proxy/users/...` is suppressed as a fanout dup — but OS-level vulns (CVEs) are independently reportable.

## Fingerprinting (unauth)

- Login page title: `UniFi OS` or `UniFi Network`
- Default ports: 443 (HTTPS) or 8443 (legacy)
- `GET /api/self` → always returns JSON (unauthenticated); includes `softwareVersion` field
- `GET /api/system` → returns build/version data unauthenticated on some versions
- HTTP response header: `X-Frame-Options: SAMEORIGIN`, `X-Content-Type-Options: nosniff`
- JS bundle path: `/static/js/main.*.chunk.js` (large React SPA)

## Version detection (for n-day racing)
```bash
curl -sk https://<host>/api/self | jq .data.softwareVersion
# e.g. "5.0.7" → below 5.0.8 = vulnerable to CVE-2026-34908/34909/34910

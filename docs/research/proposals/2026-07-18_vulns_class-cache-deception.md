# PROPOSAL (proposal) for docs/knowledge/class-cache-deception.md — vulns 2026-07-18
_Review and apply manually; not auto-merged into the KB._

## Varnish-specific poisoning primitive: CVE-2026-34475 (added 2026-07-18)

Varnish Cache OSS <8.0.1 / Enterprise <6.0.16r12: HTTP/1.1 requests with a root path (`/`) in certain
`req.url` scenarios are validated at the wrong pipeline stage (CWE-180), enabling cache poisoning or
auth bypass. CVSS 5.4. Distinct from our generic path-confusion WCD detector — this is a Varnish-internal
root-path validation-order bug, not a suffix/path-confusion trick. Fingerprint Varnish via `Via: varnish`
/ `X-Varnish` response headers, then check version if exposed (`X-Varnish-*` or config-disclosure). No
public PoC details beyond the advisory as of 2026-07-18 — treat as a LEAD to design a root-path probe
variant for `recon_wcd.sh`, not yet a ready confirm primitive.
Source: https://github.com/advisories/GHSA-m9gq-cmcj-p62x

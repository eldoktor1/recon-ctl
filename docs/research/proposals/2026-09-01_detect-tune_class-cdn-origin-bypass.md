# PROPOSAL (proposal) for docs/knowledge/class-cdn-origin-bypass.md — detect-tune 2026-09-01
_Review and apply manually; not auto-merged into the KB._

## Correction (2026-09-01): Censys free-tier API access removed early 2026
The favicon-hash origin-pivot section lists Shodan and Censys as parallel options. Censys
killed free-tier API access in early 2026 (tools like CloudFlair built on it are now broken
without a paid key). Treat Shodan `http.favicon.hash:<hash>` (budget-gated per
`reference_api_credit_budget`) as the PRIMARY path; only use Censys if we're confirmed to hold
a paid Platform-tier PAT.
Source: https://medium.com/@zeroska/eng-osint-techniques-how-to-find-a-server-behind-cloudflare-cfc48a1c56a0

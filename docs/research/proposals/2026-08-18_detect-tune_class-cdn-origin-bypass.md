# PROPOSAL (proposal) for docs/knowledge/class-cdn-origin-bypass.md — detect-tune 2026-08-18
_Review and apply manually; not auto-merged into the KB._

## Favicon-hash Shodan/Censys pivot to find true origin IP (added 2026-08-18)
Complementary fingerprint for finding a CDN-fronted host's real origin (relevant given our top
in-scope tech is Cloudflare/CloudFront/Google Cloud CDN heavy, and CDN-fronting is exactly what
makes `recon_port_proto.py` skip a host — "a CDN ACKs every port"). Hash the confirmed in-scope
host's favicon (MurmurHash3 — the Shodan-native hash format) and dork
`http.favicon.hash:<hash>` (Censys equivalent: `services.http.response.favicons.hashes:<hash>`).
Shared infra (dev/staging/build boxes not yet behind the CDN) frequently shares the exact same
favicon and surfaces on a bare IP — turning a previously-skipped CDN-fronted host into one where
port/protocol confirmation chains (Redis/Elastic/Docker/kubelet probes) are actually meaningful.
Fits inside the existing Shodan monthly budget (`recon_uncover.sh`, 60/100 cap) as one more query
type — no new credit source needed.
Sources: https://hivesecurity.gitlab.io/blog/favicon-hash-shodan-infrastructure-fingerprinting/, https://payatu.com/blog/favicon-hash/

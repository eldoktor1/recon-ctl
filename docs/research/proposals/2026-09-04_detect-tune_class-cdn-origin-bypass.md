# PROPOSAL (proposal) for docs/knowledge/class-cdn-origin-bypass.md — detect-tune 2026-09-04
_Review and apply manually; not auto-merged into the KB._

## Origin-IP discovery playbook (2026 update — unwaf v2.0 consolidation)

Passive-only (OSINT, not target traffic — runs as d0k, no Mullvad gate), same trust tier as
recon_uncover.sh/recon_permute.sh. Goal: turn a "CDN-fronted, port-confirm skipped" host into
a verified-origin host eligible for `recon_port_proto.py`.

**Methods, cheapest/highest-signal first:**
1. Favicon hash correlation: mmh3-hash the site's favicon, search Shodan `http.favicon.hash:<hash>`
   for the same app on a non-CDN IP. Devs almost never randomize favicons per environment.
2. TLS cert SHA-1 fingerprint: grab the CDN-fronted cert's fingerprint, search Shodan
   `ssl.cert.fingerprint:<sha1>` for other IPs presenting the identical cert.
3. crt.sh: forgotten subdomains/staging hosts frequently still resolve straight to origin.
4. MX + SPF (`ip4:` directives): mail infra rarely rides the CDN.
5. IPv6 AAAA record: often forgotten when only the A record is CDN-proxied. Check this — we
   likely don't today.
6. GitHub code search for IP literals in `.env`/`.yaml`/`.tf`/`.conf` — fold into `recon_ghleaks.sh`
   query set (accidental commits).
7. Historical/passive DNS: AlienVault OTX + HackerTarget (SecurityTrails free tier and Censys
   free access for this use case are both gone as of 2026 — don't budget for them here).
8. Common subdomain brute (`direct`,`origin`,`backend`,`staging`,`dev`,`cpanel`,...) — DNS only,
   covered by our existing permutation lane's wordlist; make sure these tokens are in it.

**Verification (don't mint on a bare IP match — same discipline as bucket name-match ≠ ownership):**
candidate IP's HTML/title similarity to the CDN-fronted response, AND/OR TLS cert SAN containing
the target domain when connecting directly to the candidate IP with the target's SNI. Tool:
`unwaf` (github.com/mmarting/unwaf) automates discovery + this verification in one pass.

**Payoff for us specifically:** a *verified* origin match reclassifies the host from
"CDN-fronted → port-confirm skipped" (CHAIN-TO-IMPACT law exemption) to eligible for the
open-port→speak-the-protocol chain (`recon_port_proto.py`) — new money-chain surface, not just recon.
Source: ddactic.net origin-discovery writeup, github.com/mmarting/unwaf, 2026-09.

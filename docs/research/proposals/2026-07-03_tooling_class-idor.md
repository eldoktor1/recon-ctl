# PROPOSAL (proposal) for docs/knowledge/class-idor.md — tooling 2026-07-03
_Review and apply manually; not auto-merged into the KB._

## Tool Addition: Subdominator for Takeover Lane

### Subdominator
- **GitHub:** https://github.com/Stratus-Security/Subdominator
- **What it does:** Subdomain takeover detector with 97 service fingerprints. Traces the **full CNAME chain to the terminal A record** (other tools stop at first hop). Also matches A/AAAA records for IP-only takeovers. Dynamic Azure validators reduce FPs. ~8x faster than Subjack/Subdover.
- **Vs existing tools:** Complements BadDNS (second-order NS/MX delegation detection) rather than replacing it. More fingerprints than nuclei takeover templates (~72). Use both in sequence.
- **Doctrine fit:** Unauth, read-only DNS queries only. Maps directly to our confirmed-takeover primitive (NXDOMAIN + unclaimed fingerprint).
- **Wire into:** Takeover pass after subfinder resolves, alongside BadDNS.
- **Last verified:** 2026-07-03 · v1.72 Sept 2024, 310★.

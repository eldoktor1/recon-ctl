# PROPOSAL (proposal) for docs/knowledge/class-cdn-origin-bypass.md — vulns 2026-07-28
_Review and apply manually; not auto-merged into the KB._

## Additional discovery technique: apex/www split-DNS diff (added 2026-07-28)
Cheap, zero-target-traffic passive check: for each in-scope root domain, resolve BOTH the
apex (`example.com`) and the `www` label separately. Legacy organizations frequently keep
apex DNS pointed at old infra (mail routing, legacy load balancer) while only migrating
`www`/subdomains behind Cloudflare/CDN — a mismatch between the two A records is a strong
origin-IP candidate. A published bulk sweep found 30+ confirmed exposures across ~40k
domains checked this way (https://medium.com/@smitgharat0001/cloudflare-bypass-origin-server-deserves-some-love-too-e8bd2182cfea).
Run as a batch `dig`/passive-DNS diff over our in-scope root-domain list (d0k, public
resolvers, not target traffic) alongside the existing favicon-hash/CT-log/grey-cloud
techniques already in this doc; feed any mismatch into the same CloudFlair-style
Host-header verification primitive before treating it as more than a candidate.

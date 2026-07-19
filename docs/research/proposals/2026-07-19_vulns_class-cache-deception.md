# PROPOSAL (proposal) for docs/knowledge/class-cache-deception.md — vulns 2026-07-19
_Review and apply manually; not auto-merged into the KB._

## PortSwigger "Gotta Cache 'Em All" (Jan 2026) + CacheKiller tool (added 2026-07-19)
- Generalizes cache attacks beyond path-suffix WCD to URL/HTTP **parser discrepancies between edge
  and origin**; demonstrates chaining cache-key confusion with an otherwise "non-exploitable" open
  redirect to rewrite a cached static-JS response for cross-domain execution.
- Companion OSS tool `CacheKiller` (github.com/PortSwigger/cache-killer) automates discrepancy
  discovery — evaluate as a `recon_wcd.sh` companion for broader-than-path-confusion detection on
  CDN-fronted in-scope hosts; keep it detect-only with our own cache-buster key (same safety
  primitive as the current lane).
- CVE-2026-34475 (Varnish req.url canonicalization bug, see tech-varnish.md) is a confirmable
  cache-poisoning/auth-bypass primitive on any fingerprinted Varnish < 8.0.1 host.
- Source: https://portswigger.net/research/a-hacking-hat-trick-previewing-three-portswigger-research-publications-coming-to-def-con-amp-black-hat-usa

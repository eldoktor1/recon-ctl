# PROPOSAL (proposal) for docs/knowledge/class-cache-deception.md — vulns 2026-07-11
_Review and apply manually; not auto-merged into the KB._

## CVE-2026-34475 — Varnish Cache auth-bypass / cache-poisoning via root-path req.url (added 2026-07-11)
- Varnish Cache <8.0.1 / Varnish Enterprise <6.0.16r12: unchecked `req.url` handling mishandles certain HTTP/1.1 requests whose path is `/`, leading to cache poisoning or auth bypass. CVSSv3.1 5.4, remote unauth-reachable but high attack complexity.
- Gives a concrete root-path-confusion variant to add to recon_wcd.sh's probe set beyond generic suffix path-confusion — worth a probe variant requesting `/` with our unique cache-buster and checking for anomalous cached auth-state leakage.
- Detect Varnish presence via `Via`/`X-Varnish` headers; version is not usually banner-exposed — confirm behaviorally, not by version string.
- Source: https://www.sentinelone.com/vulnerability-database/cve-2026-34475/ , https://github.com/advisories/GHSA-m9gq-cmcj-p62x

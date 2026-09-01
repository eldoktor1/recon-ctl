# PROPOSAL (proposal) for docs/knowledge/tech-varnish.md — vulns 2026-08-31
_Review and apply manually; not auto-merged into the KB._

## CVEs (added 2026-08-31 research digest)

- **CVE-2026-50052** — HTTP/2→HTTP/1.1 conversion request-smuggling / auth bypass. Improper
  validation of HTTP/2 pseudo-headers/framing lets Varnish and the backend disagree on request
  boundaries → cache poisoning, auth bypass, info disclosure. Affected: Varnish Cache < 9.0.3,
  Varnish Enterprise ("Vinyl Cache") < 9.0.1. Only reachable when HTTP/2 is explicitly enabled on
  the Varnish front (off by default — check via observed ALPN h2 negotiation, a passive/safe
  check). Fixed 9.0.3. Published 2026-06-04.
  Source: https://www.sentinelone.com/vulnerability-database/cve-2026-50052/

- **CVE-2026-34475** — CWE-180 (validate-before-canonicalize). Unchecked `req.url` for HTTP/1.1
  requests with a bare `/` path desyncs cache-key logic from backend routing → cache
  poisoning/auth-bypass. Affected: Varnish Cache < 8.0.1, Varnish Enterprise < 6.0.16r12. CVSS 5.4.
  Fixed 8.0.1. Published 2026-03-27.
  Source: https://github.com/advisories/GHSA-m9gq-cmcj-p62x

- **CVE-2026-40396** — DoS: HTTP/1 request-pipelining triggers a workspace-buffer overflow →
  daemon panic/crash. Affected: Varnish Cache 9.0.0 (regression from the HTTP/2 non-blocking
  architecture port). Destructive (crashes the worker) — never fire; version-match LEAD only.
  Source: https://www.sentinelone.com/vulnerability-database/cve-2026-40396/

**Remote detection:** Varnish version is not exposed by default; check `Via`/`X-Varnish` response
headers (some configs leak `Varnish/x.y`) and jsintel/Wappalyzer version strings. All three CVEs are
config-dependent (HTTP/2 enabled, or a specific req.url pattern reachable) — per our KEV-tech-class
doctrine, a version-in-range match alone is a LEAD, never a mint. No safe unauth exploit primitive
exists for any of the three; do not attempt smuggling/cache-poison/crash PoCs autonomously.

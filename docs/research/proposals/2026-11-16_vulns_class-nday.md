# PROPOSAL (proposal) for docs/knowledge/class-nday.md — vulns 2026-11-16
_Review and apply manually; not auto-merged into the KB._

## 2026-11-16 — Apache HTTP Server CVE-2026-119618 (mod_http2 unauth RCE)
- Affected: httpd 2.4.55–2.4.70 (mod_h2 standalone 2.0.8–2.0.42); fixed 2.4.71 (2026-11-11).
- HARD PRECONDITION: HTTP/2 must be enabled (`Protocols` directive / ALPN `h2`) — HTTP/1.1-only hosts are not vulnerable, so version-in-range alone is insufficient per our n-day doctrine.
- Detect unauth-safe: Server header version (if not suppressed) AND/OR ALPN negotiation offering `h2` on the TLS handshake.
- Public PoC only reproduces crash/memory-corruption, not demonstrated RCE as of 2026-11-16 → treat as LEAD (confirmed version+protocol), never auto-P0.
- Sources: https://www.securityweek.com/apache-patches-critical-http-server-rce-found-by-anthropic-google/ , https://www.rescana.com/post/apache-httpd-mod-http2-cve-2026-119618-patch-now

## 2026-11-16 — WordPress Core CVE-2026-119977 (KEV, update-window TOCTOU RCE)
- Affected: WP Core 4.7–7.1.3. CVSS 8.1, added to CISA KEV 2026-11-03.
- Exploit window only exists DURING a live full-package core auto-update: files stage briefly under a predictable `wp-content/upgrade/` path before replacing the live install.
- Fits the n-day RACING lane specifically: watch for in-scope WP hosts about to pull a fresh core release and probe `wp-content/upgrade/` during that window. Not a standing/background check — timing-dependent.
- Source: https://labs.beazley.security/advisories/BSL-A1241

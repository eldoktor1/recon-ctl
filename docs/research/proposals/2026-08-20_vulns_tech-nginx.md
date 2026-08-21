# PROPOSAL (proposal) for docs/knowledge/tech-nginx.md — vulns 2026-08-20
_Review and apply manually; not auto-merged into the KB._

## CVE-2026-42945 — rewrite-module heap overflow (2026-08, DO NOT PROBE)
Config-dependent (unnamed PCRE capture in `rewrite` + `?` in replacement + trailing rewrite/if/set in same scope) heap overflow in `ngx_http_rewrite_module`, CVSS 9.2, OSS 0.6.27–1.30.0 / Plus R32–R36 (fixed 1.30.1/1.31.0, R32 P6/R36 P4). Triggering it crashes the worker (DoS) — do not build an active probe; version-in-range alone is low-confidence since it needs a specific, uncommon directive combo not visible remotely. Note only. Source: https://socprime.com/blog/cve-2026-42945-critical-nginx-rewrite-flaw/

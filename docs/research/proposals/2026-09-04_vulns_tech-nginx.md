# PROPOSAL (proposal) for docs/knowledge/tech-nginx.md — vulns 2026-09-04
_Review and apply manually; not auto-merged into the KB._

## CVE-2026-42945 "NGINX Rift" (added 2026-09-04)
- Heap overflow in `ngx_http_rewrite_module`, CVSS 9.2, unauth-reachable but **config-dependent**
  (needs a `rewrite` with unnamed capture `$1`/`$2` + `?` in replacement + another rewrite/if/set
  in same scope — not remotely visible).
- Affected: nginx OSS 0.6.27–1.30.0, Plus R32–R36. Fixed 1.30.1/1.31.0.
- **Our `Nginx:1.29.7` in-scope fingerprint falls inside this range** — version-match = LEAD,
  never probe (destructive worker-crash primitive; RCE only without ASLR).
- Source: https://socprime.com/blog/cve-2026-42945-critical-nginx-rewrite-flaw/

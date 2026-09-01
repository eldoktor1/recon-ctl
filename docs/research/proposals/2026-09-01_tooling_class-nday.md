# PROPOSAL (proposal) for docs/knowledge/class-nday.md — tooling 2026-09-01
_Review and apply manually; not auto-merged into the KB._

## CVE-2026-42530 — nginx HTTP/3 (QUIC/QPACK) use-after-free
- Affected: nginx Open Source 1.31.0–1.31.1 (ngx_http_v3_module, HTTP/3 enabled only). Patched: 1.31.2 (2026-06-17), 1.30.3.
- CVSS 3.1: 8.1 HIGH / CVSS 4: 9.2. Unauthenticated remote attacker reopens a QPACK encoder stream via a crafted QUIC session → UAF in the worker process → crash/DoS; RCE possible if ASLR disabled/bypassable.
- Detection: BANNER/VERSION ONLY (Server header, error page). Do NOT build or run an active PoC — the exploit primitive is itself a DoS trigger, which violates our non-destructive doctrine regardless of scope/pays. No public nuclei template exists as of 2026-09-01 (checked); do not author one that exercises the UAF.
- Relevance: nginx and HTTP/3 are both top in-scope tech for us. Treat like every other KEV-tech-class match — version-confirm via recon_nday.sh, LEAD not P0, never auto-fire.
- Sources: https://www.ionix.io/threat-center/cve-2026-42530/ ; https://socprime.com/blog/cve-2026-42530-critical-nginx-http-3-flaw-can-trigger-dos-and-possible-rce/ ; nginx security advisory (F5).

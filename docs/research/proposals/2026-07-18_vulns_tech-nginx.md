# PROPOSAL (proposal) for docs/knowledge/tech-nginx.md — vulns 2026-07-18
_Review and apply manually; not auto-merged into the KB._

## 2026 CVE version table (added 2026-07-18 research cycle)

Our current in-scope fingerprint includes exact version `nginx/1.29.7`. Full nginx.org advisory table,
fixed-in vs vulnerable-range, current as of 2026-07-18:

| CVE | Issue | Fixed In | Vulnerable |
|-----|-------|----------|-----------|
| CVE-2026-42533 | Buffer overflow (map + regex) | 1.31.3+, 1.30.4+ | 0.9.6-1.31.2 |
| CVE-2026-60005 | Memory disclosure (slice module) | 1.31.3+, 1.30.4+ | 1.15.8-1.31.2 |
| CVE-2026-56434 | Use-after-free (SSI module) | 1.31.3+, 1.30.4+ | 0.8.11-1.31.2 |
| CVE-2026-42530 | Use-after-free (HTTP/3) | 1.31.2+ | 1.31.0-1.31.1 |
| CVE-2026-42055 | Buffer overflow (proxy_v2/gRPC) | 1.31.2+, 1.30.3+ | 1.13.10-1.31.1 |
| CVE-2026-48142 | Buffer overread (charset module) | 1.31.2+, 1.30.3+ | 0.3.50-1.31.1 |
| CVE-2026-9256 | Buffer overflow (rewrite module) | 1.31.1+, 1.30.2+ | 0.1.17-1.31.0 |
| CVE-2026-42926 | HTTP/2 request injection (proxy module) | 1.31.0+, 1.30.1+ | 1.29.4-1.30.0 |
| **CVE-2026-42945** ("Rift") | Heap buffer overflow (rewrite module), CVSS 9.2, ITW-exploited | 1.31.0+, 1.30.1+ | 0.6.27-1.30.0 |
| CVE-2026-42946 | Buffer overread (SCGI/uWSGI) | 1.31.0+, 1.30.1+ | 0.8.42-1.30.0 |
| CVE-2026-42934 | Buffer overread (charset module) | 1.31.0+, 1.30.1+ | 0.3.50-1.30.0 |
| CVE-2026-40460 | HTTP/3 address spoofing | 1.31.0+, 1.30.1+ | 1.25.0-1.30.0 |
| CVE-2026-40701 | Resolver use-after-free (OCSP) | 1.31.0+, 1.30.1+ | 1.19.0-1.30.0 |
| CVE-2026-27654/27784/32647/27651/28753/28755 | Various (DAV/mp4/CRAM-MD5/auth_http/stream OCSP) | 1.29.7+, 1.28.3+ | pre-1.29.7 |
| CVE-2026-1642 | SSL upstream injection | 1.29.5+, 1.28.2+ | 1.3.0-1.29.4 |

**Implication for us**: exact `nginx/1.29.7` (patched against the pre-1.29.7 batch) is STILL in-range for
CVE-2026-42945/42926/42946/42934/40460/40701 (all vulnerable through 1.30.0). CVE-2026-42945 is config-dependent
(rewrite directive w/ unnamed PCRE capture + `?` in replacement) and unsafe to trigger (crashes the worker) —
version-range LEAD only, never fire it. CVE-2026-42926 (HTTP/2 request injection) is the most promising for a
future safe differential-probe design. Source: nginx.org/en/security_advisories.html (2026-07-18 pull).

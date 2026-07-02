# PROPOSAL (proposal) for docs/knowledge/tech-nginx.md — vulns 2026-07-01
_Review and apply manually; not auto-merged into the KB._

## CVE-2026-42945 "NGINX Rift" — Heap Buffer Overflow in ngx_http_rewrite_module

- **CVSS:** 9.2 (v4)
- **Affected:** Nginx Open Source 0.6.27–1.30.0; Plus R32–R36
- **Fixed:** 1.30.1 / 1.31.0 (Open Source); R32 P6 / R36 P4 (Plus)
- **Class:** Heap buffer overflow → reliable DoS; RCE if ASLR disabled or via LFI chain (PoC public)
- **Auth required:** None

### Vulnerable config pattern
```nginx
# VULNERABLE: unnamed PCRE capture + ? in replacement
rewrite ^/(.*)$ /index.php?$1 last;

# SAFE: named capture
rewrite ^/(?P<path>.*)$ /index.php?$path last;

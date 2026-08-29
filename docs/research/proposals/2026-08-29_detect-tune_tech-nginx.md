# PROPOSAL (proposal) for docs/knowledge/tech-nginx.md — detect-tune 2026-08-29
_Review and apply manually; not auto-merged into the KB._

## 2026 CVE batch — 1.29.x branch (added 2026-08-29)
Our observed in-scope version `Nginx:1.29.7` sits inside the vulnerable range of 6 CVEs fixed only in
1.30.1+/1.31.0+ (nginx.org security advisories, https://nginx.org/en/security_advisories.html):

- **CVE-2026-42926** — HTTP/2 request injection in `ngx_http_proxy_module`. Only triggers when the
  proxied backend config uses `proxy_http_version 2` **and** `proxy_set_body` — NGINX frames the
  substituted body as raw HTTP/2 DATA frames without escaping, letting attacker-controlled bytes forge
  frame headers the upstream then parses as a second request. Range 1.29.4–1.30.0. Not blindly probable
  unauth (needs upstream-specific payload); version-gate to LEAD, escalate only if a reverse-proxy
  signal (`X-Accel-*`, visible upstream error, Via header) is also present. Source:
  https://github.com/advisories/GHSA-v43f-895r-chhh
- **CVE-2026-42945 / -42946 / -42934** — buffer overflow/overread in rewrite / scgi+uwsgi / charset
  modules, all ≤1.30.0. Version-gate only, no safe unauth confirm primitive.
- **CVE-2026-40460** — HTTP/3 address spoofing, ≤1.30.0.
- **CVE-2026-40701** — resolver use-after-free on OCSP requests, ≤1.30.0.

Fingerprint: `Server: nginx/1.29.x` (server_tokens on) or version leak via error pages/`nginx.org` default
pages. All are version-gated KEV-class LEADs per our KEV doctrine — never auto-P0 without confirming the
specific precondition (esp. CVE-2026-42926's proxy config requirement).

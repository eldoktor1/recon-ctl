# Apache HTTP Server — recon notes

## Fingerprinting
- `Server:` response header leaks exact version when `ServerTokens Full`/default (common on unhardened installs) — check every in-scope host's raw header, not just Wappalyzer's coarse `tech:Apache` tag.
- jsintel/full-text scan for `Apache/x.y.z` strings in error pages (403/404 defaults often leak version even when the header is stripped).

## Known n-day windows (2026)
- **CVE-2026-23918** (CVSS 8.8) — `mod_http2` double-free via crafted HTTP/2 HEADERS + early RST_STREAM (non-zero error code) → unauth crash/possible RCE. Affected **2.4.66 only**, fixed **2.4.67**. No public PoC as of 2026-09-01. Do not fire — crash/RCE primitive, not a safe confirm. Source: [Orca Security](https://orca.security/resources/blog/apache-http-server-http2-vulnerability-cve-2026-23918/).
- **CVE-2026-34356** — `ProxyPassReverseCookie*` heap buffer overflow. Affected 2.4.0–2.4.67, fixed 2.4.68. **Not client-triggerable** — requires a malicious/compromised backend server behind the reverse proxy to feed the crafted cookie header, so this is not a remote unauth primitive from our vantage point unless we control a backend the target proxies to (out of scope for a normal recon target). Low priority; noted for completeness. Source: [openwall/oss-security](https://www.openwall.com/lists/oss-security/2026/06/08/7).
- Apache 2.4.68 (2026-06-08) also fixed a use-after-free, DoS, and XSS in the same release train — re-check `httpd.apache.org/security/vulnerabilities_24.html` when version-matching any 2.4.x host below 2.4.68.

## Doctrine reminder
Version-in-range on any of the above = LEAD only per KEV-tech-class-without-config-confirmation rule — none of these have a safe unauth confirm primitive (all are crash/RCE-class), so they stay detect-only, never auto-fired.

# PHP Framework Fingerprinting

Reusable fingerprints for identifying PHP frameworks from passive signals (headers, cookies, paths, error pages) — enabling targeted IDOR/debug-panel/RCE hunting without active probing.

## Laravel

**Passive signals (ES / jsintel / header scan):**
- Cookie: `laravel_session` — default session cookie name, commonly unchanged
- Cookie: `XSRF-TOKEN` — CSRF token in cookie (coexists with `laravel_session`)
- HTML meta: `<meta name="csrf-token">` in page head
- Path in endpoints.jsonl / jsintel: `/_ignition/health-check`, `/_ignition/execute-solution`, `/telescope`, `/horizon`, `/__clockwork`, `/log-viewer`, `/sanctum/csrf-cookie`
- Static asset paths prefixed `/vendor/laravel/` or `/build/` with version hash

**High-value paths to probe (on-demand, not daemon):**
- `/_ignition/execute-solution` — Laravel Ignition RCE if `APP_DEBUG=true` (POST, CVE-2021-3129 pattern; still fires on unpatched installs). Probe: `GET /_ignition/health-check` → 200 with `{"can_execute_commands":true}` = debug mode ON = CONFIRMED RCE candidate → operator hands-on.
- `/telescope` — Laravel Telescope: all requests, exceptions, DB queries, cache, queue, mail — **high-payout info disclosure** when exposed publicly
- `/horizon` — Laravel Horizon: job queue dashboard, often exposes internal job data
- `/__clockwork` — Clockwork profiler: full request/response data including DB queries

**FP pattern:** `/sanctum/csrf-cookie` returning 200 = normal (it's a public route). Only flag if Telescope/Horizon/Ignition paths return 200 with data.

**ES query:**
```json
{"bool": {"should": [
  {"match": {"jsintel_endpoints_text": "_ignition"}},
  {"match": {"headers_text": "X-Debug-Token"}},
  {"match": {"cookies_text": "laravel_session"}},
  {"match": {"jsintel_endpoints_text": "telescope"}},
  {"match": {"jsintel_endpoints_text": "horizon"}}
]}}


---
<!-- applied-proposal: 2026-07-01_vulns_tech-php -->
### Applied research — vulns (2026-07-01)

## CVE-2026-6722 — PHP SOAP Extension Use-After-Free RCE (CVSS 9.5)

- **Affected:** PHP < 8.2.31, < 8.3.31, < 8.4.21, < 8.5.6
- **Fixed:** 8.2.31 / 8.3.31 / 8.4.21 / 8.5.6
- **Class:** Use-after-free in SOAP extension object deduplication → arbitrary write → RCE
- **Auth required:** None — if SOAP endpoint accepts unauthenticated traffic

### Detection fingerprint
- Probe for WSDL endpoints: `/?wsdl`, `/soap`, `/api/soap`, `/services/*.php?wsdl`
- JS/jsintel: `SoapClient`, `soapClient`, `wsdl` references in endpoint output
- PHP version via `X-Powered-By: PHP/X.Y.Z` or error pages → confirm < patched branch
- Worker crashes (PHP-FPM segfaults after SOAP traffic) — observable in monitoring but not recon

### In-scope action
SOAP endpoint found + PHP version confirmed unpatched → LEAD. Do NOT send malformed SOAP body (exploitation, not detection). Version + endpoint = submittable n-day LEAD for programs that reward infra CVEs.

Sources: [cybersecuritynews](https://cybersecuritynews.com/php-soap-extension-vulnerabilities/) · [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-6722)

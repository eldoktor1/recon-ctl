# Research digest — detect-tune — 2026-06-30

Both agents done. Compiling the digest now.

---

## detect-tune digest — 2026-06-30

### 1. PHP Framework Debug-Panel Lane (NEW HIGH-PAYOUT SURFACE)

PHP is our #3 in-scope tech and we have zero framework-specific fingerprinting. Laravel and Symfony both leak debug surfaces that are HIGH-payout when exposed.

**Laravel signals (query ES / jsintel for any of these):**
- Cookie: `laravel_session` (default, commonly unchanged)
- Cookie: `XSRF-TOKEN` (coexists with `laravel_session`)
- Path in jsintel/endpoints: `/_ignition/health-check`, `/_ignition/execute-solution`, `/telescope`, `/horizon`, `/__clockwork`, `/log-viewer`
- `/_ignition/execute-solution` — **RCE if `APP_DEBUG=true`** (Laravel Ignition CVE-2021-3129 pattern; still fires on unpatched/misconfigured installs)

**Symfony signals:**
- Response header: `X-Debug-Token: <hash>` → profiler enabled
- Response header: `X-Debug-Token-Link: /_profiler/<hash>` → **direct path to stack traces, env vars, full route list**
- Paths: `/_profiler/`, `/_wdt/`, `/_profiler/phpinfo`

**ES action:** add to Kibana / ES query for IDOR/debug lane:
```json
"should": [
  {"match": {"jsintel_endpoints_text": "_ignition"}},
  {"match": {"headers_text": "X-Debug-Token"}},
  {"match": {"cookies_text": "laravel_session"}},
  {"match": {"jsintel_endpoints_text": "telescope"}}
]
```
Pull these hosts into the ai-hunter worklist as "debug-panel candidate" — even without RCE the profiler route leaks internal API structure that feeds IDOR ranking.

Sources: [HackTricks Laravel](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/laravel), [AllAboutBugBounty Laravel](https://github.com/daffainfo/AllAboutBugBounty/blob/master/Technologies/Laravel.md)

---

### 2. Varnish PURGE Unauth — Direct Reportable Bug

Varnish is in our top tech. Unauthenticated cache PURGE is a reportable bug (HackerOne paid $4,850 on one instance).

**Detection oracle (add to recon-wcd pipeline):**
```
X-Varnish: <single int>          → cache MISS
X-Varnish: <int> <int>           → cache HIT (two IDs = stored + request)
Via: 1.1 varnish (Varnish/6.x)  → version leak
Age: 0                           → just-missed
```

**Confirm primitive (on-demand, recon-wcd confirm step):**
```bash
curl -X PURGE https://<target>/<path> -sv 2>&1 | grep -E "< HTTP|< Age|< X-Varnish"
```
`200 OK` or `204 No Content` to PURGE without auth = **CONFIRMED** (not a LEAD). `405`/`403` = secure.

**WCD tie-in:** `X-Varnish` present + `Age: 0` on a path with `.css`/`.js` suffix appended to an authenticated route = WCD candidate. Varnish-specific path confusion to test: `/api/user/profile.css`, `/account/settings.js`.

**Age header timing signal:** `Age: 55` + TTL 60s → 5-second poison window. Tells you exactly when to race.

Source: [HackerOne #1911568](https://hackerone.com/reports/1911568), [Cache Poisoning at Scale](https://youst.in/posts/cache-poisoning-at-scale/)

---

### 3. New Low-Density Nuclei Panels (Run These Now)

These were added to nuclei-templates in the last 3 releases (v10.4.3–v10.4.5, Apr–Jun 2025) and are NOT what everyone runs:

**Low hunter-density panels (APAC/enterprise appliances):**
```bash
nuclei -t http/exposed-panels/sangfor-iam-panel.yaml \
       -t http/exposed-panels/sangfor-ngaf-panel.yaml \
       -t http/exposed-panels/hillstone-ssl-vpn-panel.yaml \
       -t http/exposed-panels/cyberoam-firewall-panel.yaml \
       -t http/exposed-panels/firemon-asset-manager-panel.yaml \
       -l <in_scope_paying_hosts>
```

**New infrastructure panels (growing deployment base):**
```bash
nuclei -t http/exposed-panels/wg-easy-panel.yaml \
       -t http/exposed-panels/headscale-panel.yaml \
       -l <in_scope_paying_hosts>
```

**ML/AI stack (fastest-moving unpatched surface in 2025):**
```bash
nuclei -t http/technologies/milvus-detect.yaml \
       -t http/misconfiguration/mlflow-unauth.yaml \
       -t http/vulnerabilities/langflow-preauth-rce.yaml \
       -l <in_scope_paying_hosts>
```
Langflow pre-auth RCE needs version-reasoning before treating as P0 (LEAD pattern).

**Auth bypass templates added this cycle:**
- `OpenWebUI LDAP empty password auth bypass`
- `DataEase JWT authentication bypass`  
- `Gitea Container Registry unauthorized private image access`
- `Nginx UI broken access control`

Source: [nuclei-templates releases](https://github.com/projectdiscovery/nuclei-templates/releases), [.new-additions](https://github.com/projectdiscovery/nuclei-templates/blob/main/.new-additions)

---

### 4. XSS FP Patterns — Suppress These at Dalfox Output Stage

These are high-volume FPs in automated XSS scanning. Add as early-exit filters before handing dalfox output to the confirm/review pipeline:

| Signal | Verdict | Reason |
|--------|---------|--------|
| Payload in `Content-Type: application/json` response | **FP** | Browser never renders as HTML |
| Payload only in error message body | **FP** | Error pages templated, not user-data sinks |
| Payload in `src=""` with proper entity escaping (`&lt;`) | **FP** | Attribute-escaped, no breakout |
| `403` response containing payload | **FP** | WAF blocked, not reflected |
| SQL error on malformed input without `'` vs `''` differential | **FP** | Input validation, not injectable |
| Reflection inside `<script>` tag but inside a string literal with `\"` escaping intact | **FP** | JS-string-context-safe, no breakout |

**Dalfox v3.1.2** (Rust rewrite, June 2026) — confirm you're on this version. The AST-backed DOM verification in v3 is the primary FP improvement: it avoids reporting reflection in non-executable contexts. `--force-headless-verification` remains the gate — reflection without Chromium-confirmed execution = discard.

Source: [chudi.dev FP post](https://chudi.dev/blog/bug-bounty-automation), [dalfox v3.1.2](https://github.com/hahwul/dalfox)

---

### 5. WCD CDN Oracle — Identify Before Probing

Add CDN identification as step 0 of recon-wcd to avoid wasting probes on CDNs that never cache dynamic routes:

| CDN | Identifying Header | Cache-Hit Indicator |
|-----|-------------------|---------------------|
| Cloudflare | `CF-Cache-Status` | `HIT` (DYNAMIC = skip) |
| Akamai | `Server-Timing: cdn-cache; desc=HIT` | `desc=HIT` |
| Fastly | `X-Fastly-Cache` | `HIT` |
| CloudFront | `X-Amz-Cf-Id` | `X-Cache: Hit from cloudfront` |
| Varnish | `X-Varnish` | Two integers (see §2) |

**FP suppression:** `CF-Cache-Status: DYNAMIC` or `Cache-Control: no-store` on the suffix-appended path = correctly NOT cached = secure, skip. Only the cacheability flip (dynamic base → cacheable variant) is a real candidate.

**Cache oracle confirm (no-shared-cache-poison rule):** Always append unique `?cb=<uuid>` to WCD probes so you test under your own cache key. Two requests with same buster = if second gets `HIT` = confirmed cached under your key = WCD candidate.

Source: [Comprehensive Cache Vulnerabilities Checklist](https://github.com/EmadYaY/Comprehensive-Cache-Vulnerabilities-Checklist)

---

### 6. Nginx Off-by-Slash Probe — Add to Param Discovery Pipeline

For in-scope hosts serving static assets at a known `location` prefix:

```bash
# Detect off-by-slash alias traversal
curl -s -o /dev/null -w "%{http_code}" "https://<host>/static../"
# If 200 (same as /static/) → traversal exists; try:
curl "https://<host>/static../.git/config"
curl "https://<host>/static../etc/passwd"
```

The vulnerability: `location /static { alias /srv/static/; }` (no trailing slash on location) allows Nginx to send `../` upstream. `merge_slashes off` (non-default) check: `GET //api//admin` — differs from `GET /api/admin` = regex bypass possible.

**Detection signal:** 200 to `/<prefix>../` where `/<prefix>/` normally 200s. Add this as an on-demand check in `recon-params crawl-host` post-crawl phase for hosts with static-path patterns.

Source: [Detectify Nginx Misconfigs](https://blog.detectify.com/industry-insights/common-nginx-misconfigurations-that-leave-your-web-server-ope-to-attack/), [off-by-slash tool](https://github.com/bayotop/off-by-slash)

---

### 7. Favicon Hash Scoping — Dup-Resistant Shodan

Stop running unscopped favicon hash queries. Scope every query to target cert:
```
ssl.cert.subject.cn:"target.com" http.favicon.hash:-1744343670
```
Validated hashes: WordPress `−1744343670`, Apache Tomcat `−692947551`, Confluence Server `−305179312`. Generate unknown hashes with:
```python
import mmh3, base64, requests
r = requests.get('https://target.com/favicon.ico')
print(mmh3.hash(base64.encodebytes(r.content)))
```
Browse pre-catalogued hashes: [faviconmap.shodan.io](https://faviconmap.shodan.io)

**High-signal dorks not everyone runs:**
```
ssl.cert.subject.cn:"target.com" http.html:"* The wp-config.php creation script"   # unfinished WP install
ssl.cert.subject.cn:"target.com" "Set-Cookie: mongo-express=" "200 OK"             # Mongo Express unauth
ssl.cert.subject.cn:"target.com" x-jenkins 200                                     # Jenkins unauth
ssl.cert.subject.cn:"target.com" "Docker Containers:" port:2375                    # Docker API unauth
```

Source: [wolfsec1337 Apr 2026](https://wolfsec1337.medium.com/finding-unique-fingerprint-keywords-for-fofa-shodan-zoomeye-censys-modat-hunter-how-5198993c1bca)

---

### 8. IDOR Confirm Primitive — Multi-Session Body Hash

Single-session automated scanners produce near-100% FP on IDOR (confirmed by BacAlarm paper, Dec 2025). The real confirm primitive:

1. Make the same request under **session A** (owner) and **session B** (non-owner, different account)
2. Hash both response bodies — if hashes match and body contains owner A's data = IDOR confirmed
3. Status code oracle: `200` for both sessions where owner A's object ID is used = candidate; `403` for B = access control working
4. Absence of timing differential between sessions = suspicious (authorized paths often faster due to auth caching)

**FP suppression in ai-hunter:** when the hunter outputs an IDOR hypothesis, the "2-account confirm" step must verify response body equality cross-session, not just HTTP 200 status. A 200 with empty body or generic schema response ≠ IDOR.

Source: [BacAlarm arxiv Dec 2025](https://arxiv.org/pdf/2512.19997), [apiiro DAST IDOR](https://apiiro.com/blog/why-dast-tools-miss-real-idor-vulnerabilities-and-how-ai-helps/)

---



## Symfony

**Passive signals:**
- Response header: `X-Debug-Token: <hash>` — Symfony web profiler is enabled
- Response header: `X-Debug-Token-Link: /_profiler/<hash>` — **direct path to profiler panel**
- Error page body contains: `Symfony\Component` in stack traces
- URL pattern: `/index.php/<route>` prefix (Symfony front controller style)

**High-value paths:**
- `/_profiler/` — stack traces, env vars, full route list, service container
- `/_wdt/` — web debug toolbar inline data
- `/_profiler/phpinfo` — full phpinfo output
- `GET /_profiler/` → redirect with token in URL → fetch that token URL = full app internals

**Confirm primitive:** if `X-Debug-Token-Link` is present in any response, fetch that URL. If it returns a Symfony profiler page = CONFIRMED high-payout info disclosure.

## CodeIgniter

- Cookie: `ci_session` — default session name
- Error page body: "A PHP Error was encountered" with CodeIgniter styling
- URL pattern: `/index.php/<controller>/<method>` (front controller)

## CakePHP

- Cookie: `CAKEPHP` — default session cookie
- Error page: "CakePHP" in title or "Missing Controller" error message

## Generic PHP signals

- Header: `X-Powered-By: PHP/7.x` or `PHP/8.x`
- `.php` extensions in crawled URLs
- Server path leaks in error pages: `/var/www/html/`, `/home/<user>/public_html/`

## Pipeline integration

1. ES query for `laravel_session` cookie or `X-Debug-Token` header → add matched hosts to ai-hunter IDOR worklist with tag `framework:laravel` or `framework:symfony`
2. For `/_ignition/execute-solution`: check `health-check` first; if `can_execute_commands:true` → CONFIRMED candidate → brief operator immediately (not a daemon-auto-confirm — needs version check + operator hands-on)
3. `/telescope` and `/horizon`: unauth access = CONFIRMED info disclosure (no exploit needed; the data IS the finding)
```



| Response | Verdict |
|----------|---------|
| `200 OK` or `204 No Content` | **CONFIRMED** unauth cache purge — reportable |
| `405 Method Not Allowed` | Secure (PURGE disabled) |
| `403 Forbidden` | Secure (IP-restricted) |

A `200` to PURGE without authentication is a confirmed security bug. Reference: HackerOne report #1911568, paid $4,850 on fanout.io.

**Confirm step (on-demand only, not daemon):** include in `recon-wcd confirm` workflow for Varnish-fingerprinted hosts.

## WCD-specific signals

- `X-Varnish` present + `Age: 0` on a path with static suffix appended to authenticated route = WCD candidate
- Path confusion variants to test: `/api/user/profile.css`, `/account/settings.js`, `/dashboard/data.png`
- **Cache-buster rule:** always append `?cb=<uuid>` to test under YOUR key; two requests with same buster: if second gets `Age: >0` = cached = WCD confirmed under your key

## Age header timing oracle

`Age: N` tells you how stale the cached object is. If TTL is 60s and `Age: 55`, you have ~5 seconds to race-poison before natural refresh. Use `Cache-Control: max-age=` from the response to determine TTL when set.

## Sources
- HackerOne report #1911568: unauthenticated Varnish PURGE
- https://youst.in/posts/cache-poisoning-at-scale/
```


`200`/`204` = CONFIRMED unauth cache purge (distinct from WCD, reportable on its own).
```





**Detection signal:** 200 response to `/<prefix>../` where `/<prefix>/` normally 200s. Static prefixes to try: `/static`, `/assets`, `/media`, `/files`, `/public`, `/uploads`.

**`merge_slashes off` bypass (non-default config):**
```bash
curl "https://<host>//api//admin"
```
If response differs from `GET /api/admin` = `merge_slashes off` is set = regex location matchers may be bypassable with double-slash prefixes.

**Nginx status page exposure:**
- Path: `/nginx_status` or `/stub_status` — exposes active connections, requests/sec. Information disclosure; blocked by default but commonly misconfigured on internal vhosts.

**Reference:** https://blog.detectify.com/industry-insights/common-nginx-misconfigurations-that-leave-your-web-server-ope-to-attack/, https://github.com/bayotop/off-by-slash
```

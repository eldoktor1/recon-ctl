# Research digest — detect-tune — 2026-08-29

# Research digest — detect-tune — 2026-08-29

## 1. Nginx 1.29.x — 6 CVEs disclosed 2026, one hits our EXACT observed version range (HIGH PRIORITY — our top-tech list shows `Nginx:1.29.7` live in-scope)
Our own top-tech data lists `Nginx:1.29.7` as an observed in-scope version. Per nginx's official advisories page, **`1.29.7` falls inside the vulnerable range of 6 CVEs disclosed this year** (all fixed in 1.30.1+/1.31.0+, i.e. anything reporting 1.29.x is unpatched by definition):

| CVE | Issue | Vulnerable range | Notes |
|---|---|---|---|
| CVE-2026-42926 | HTTP/2 request injection in `ngx_http_proxy_module` | 1.29.4–1.30.0 | **Only when config uses `proxy_http_version 2` + `proxy_set_body`** — narrow precondition, not default |
| CVE-2026-42945 | Buffer overflow, `ngx_http_rewrite_module` | ≤1.30.0 | |
| CVE-2026-42946 | Buffer overread, `ngx_http_scgi_module`/`ngx_http_uwsgi_module` | ≤1.30.0 | |
| CVE-2026-42934 | Buffer overread, `ngx_http_charset_module` | ≤1.30.0 | |
| CVE-2026-40460 | HTTP/3 address spoofing | ≤1.30.0 | |
| CVE-2026-40701 | Resolver use-after-free (OCSP) | ≤1.30.0 | |

CVE-2026-42926 detail: NGINX frames a `proxy_set_body`-substituted body as raw HTTP/2 DATA frames without escaping — attacker-controlled bytes in the body can be interpreted as forged frame headers by the upstream, letting a request smuggle a second request past the proxy. **Not blindly exploitable without knowing the backend proxy config** (needs `proxy_http_version 2`+`proxy_set_body` present) — treat as version-gated LEAD per our KEV doctrine (`kev_needs_verify`), never auto-P0. Server-header/version disclosure alone is the safe confirm primitive; actual injection would require crafting upstream-specific payloads and isn't a safe unauth probe.
- **Actionable**: feed nginx-version-reasoning into `recon_nday.sh` — any host fingerprinted `nginx/1.29.x` (or any pre-1.30.1/1.31.0) is a LEAD for this batch; CVE-2026-42926 specifically needs a `Via`/reverse-proxy config signal (e.g. visible upstream errors, `X-Accel-*` headers) before it's worth escalating past LEAD.
- Sources: [nginx.org security advisories](https://nginx.org/en/security_advisories.html), [GitHub Advisory GHSA-v43f-895r-chhh](https://github.com/advisories/GHSA-v43f-895r-chhh), [SentinelOne CVE-2026-42926](https://www.sentinelone.com/vulnerability-database/cve-2026-42926/)

## 2. Public-by-design key shapes missing from `PUBLIC_BY_DESIGN` regex — Sentry DSN, Algolia search-only key, Segment write key (feeds `class-clientside-secrets.md`)
Our `engine/impact.py` already excludes Stripe `pk_`, Firebase web config, Supabase anon, `NEXT_PUBLIC_`/`REACT_APP_PUBLIC_`/`VITE_PUBLIC_`, and OAuth `client_id`. Three more widely-shipped-to-browser key shapes are NOT in that list and would false-flag as `js_secret_hit`:
- **Sentry DSN** — `https://<public_key>@<org>.ingest.sentry.io/<project_id>` (or `o<id>.ingest.us.sentry.io`) — by design public; only allows submitting new error events, no read access. Pattern: `https://[0-9a-f]{32}@`.
- **Algolia search-only API key** — distinct from the Algolia *admin* key (which IS a real secret — HN thread cites 39 admin keys leaked via DocSearch configs in 2026, so don't blanket-exclude all Algolia keys, only ones explicitly typed `search-only`/paired with a public `appId` in `algoliasearch(appId, searchKey)` init calls).
- **Segment write key** — required client-side for `analytics.js`/`analytics-react-native` to function; shipped in page source by design (same category as GA/GTM/Mixpanel/HubSpot/Marketo write keys we likely already ignore incidentally).
- **Actionable**: extend `PUBLIC_BY_DESIGN` in `engine/impact.py` with DSN/search-only/write-key patterns — reduces the `js_secret_hit` ~53%-corpus-noise rate further. Keep Algolia *admin* keys OUT of the exclusion (still a real secret).
- Sources: [Sentry DSN explainer](https://docs.sentry.io/concepts/key-terms/dsn-explainer.md), [Algolia — can the search key be public](https://support.algolia.com/hc/en-us/articles/18966776061329-Can-the-search-API-key-be-public), [Segment write-key FAQ](https://www.twilio.com/docs/segment/connections/sources/catalog/libraries/website/javascript/faq), [39 Algolia admin keys leaked (HN)](https://news.ycombinator.com/item?id=47371064)

Nothing else surfaced this run cleared the bar (S3/Cloudflare-WAF/origin-IP searches returned only material we already have doctrine for — favicon-hash→Shodan origin discovery is standard and not new; Cloudflare Bot Management evasion research is scraping-bypass content, not applicable to our unauth-safe non-destructive doctrine).

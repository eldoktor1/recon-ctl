# class-cache-deception — Web Cache Deception (WCD) + cache poisoning  [U5 DIG, near-zero dup]

> Reusable KB. READ before working the U5 cache lane; APPEND when you learn a new delimiter,
> CDN quirk, or confirm trick. Host-specific findings → host_notes.
>
> **Why this lane (2026-06-19, Fri "learn one technique"):** WCD/poisoning is an *operator-skill*
> class (U5) — templates can't find it, so it's near-zero-dup and pays well. It's machine-
> *surfaceable* (detect the cache/origin discrepancy with OUR OWN unauth requests) but
> impact-confirmation is operator-overseen (needs a 2nd owned session — never a victim's).
> Source: PortSwigger "Gotta cache 'em all" + Web Security Academy WCD path.

## What it is
Two layers disagree on what a URL means. The **cache** (CDN/Varnish/Cloudflare/Akamai/Fastly)
decides a URL is a static cacheable asset; the **origin** serves it as a dynamic, personalized,
or auth-gated response. The cache then stores that sensitive response and serves it to anyone.
- **Deception (WCD):** trick the cache into storing an *authed/personalized* page → retrieve it
  unauth. Impact = session/PII/token theft.
- **Poisoning:** inject an unkeyed input (header/param) that the origin reflects into a cached
  response → served to all subsequent users. Impact = stored-XSS/redirect to all visitors.

## Discover (where it hides)
- Personalized/auth-gated GET routes behind a CDN: `/account`, `/settings/users/list`,
  `/api/orders/{id}`, `/profile`, `/me`, dashboard/BFF routes. Mine jsintel endpoints +
  `recon_alive` for auth-gated GET paths on hosts with a cache layer (`X-Cache`/`Age`/
  `CF-Cache-Status`/`X-Served-By`/`Via` headers, `tech:Cloudflare|Akamai|Fastly|Varnish`).
- Poisoning: any endpoint that reflects a header/param into a cacheable response.

## The path-confusion arsenal (the discrepancy primitives)
1. **Static-extension mapping:** `/api/orders/123` → `/api/orders/123/foo.js`
   (REST origin ignores `foo.js`; cache sees `.js` → caches). Try `.css .js .ico .jpg .txt`.
2. **Path delimiters** (origin truncates, cache doesn't): `/settings/users/list;aaa.js`
   - `;` = Java/Spring matrix var · `.` = Ruby-on-Rails format · also try `;` `,` `?` `#`.
   - **Test which char is a delimiter:** `/list` vs `/listaaa` vs `/list;aaa` — if `;aaa`
     response == `/list` baseline, origin treats `;` as a delimiter (truncates) → exploitable.
     (If `/listaaa` already == `/list`, that route redirects — pick another route.)
3. **Encoded delimiters** (layer decodes at different times): `/profile%23wcd.css` (encoded `#`),
   `/myaccount%3fwcd.css` (encoded `?`), `/profile%00foo.js` (null — OpenLiteSpeed),
   also `%0A` `%09`. Cache applies its rules pre-decode; origin sees decoded.
4. **Normalization / traversal via a static dir:**
   - origin decodes, cache doesn't: `/assets/..%2fprofile` (cache caches `/assets/...`,
     origin resolves `/profile`).
   - cache decodes, origin doesn't: `/profile;%2f%2e%2e%2fstatic` (origin truncates at `;` →
     `/profile`, cache normalizes → `/static`).
5. **Exact-match file rules:** `/profile%2f%2e%2e%2findex.html` — if cache normalizes to a
   known-cached filename (`index.html`/`robots.txt`/`favicon.ico`) it stores the dynamic body.

## DETECT the discrepancy (autonomous, unauth — what WE can do safely)
1. Baseline with a **cache-buster** unique query each request (Param Miner "Add dynamic
   cachebuster" automates it).
2. Send the path-confused URL **twice**; watch the cache header flip:
   `X-Cache: miss` → `hit` (also `CF-Cache-Status: MISS→HIT`, `Age: 0→N`, much faster 2nd resp).
3. A path-confused URL that the **origin serves dynamically** but the **cache stores**
   (`hit` on 2nd req) = the discrepancy is REAL → LEAD. This needs NO victim and NO auth —
   it's an unauth proof the cache mis-keys. **This is the machine/2IC-surfaceable part.**

## CONFIRM impact (operator-overseen — needs a 2nd OWNED session, never a victim)
HARD LINE: WCD impact requires caching a *logged-in* personalized page. We do this ONLY with
the operator's **own** accounts — never a third party's session/data.
1. Operator (account A, logged in) requests the path-confused URL → origin returns A's
   personalized/sensitive body.
2. Confirm it cached: re-request → `X-Cache: hit`, body == A's data.
3. Retrieve from a **clean/unauth session** (or owned account B): same URL → returns A's
   cached body unauth = CONFIRMED WCD. Use Burp/curl programmatically, **not the browser**
   (browsers redirect/clear no-session users and can hide the bug).
STOP at proof of A's-own-data-served-unauth. Never cache or fetch a stranger's page.

## REAL-vs-FP discriminators (impact-gate hard)
- **FP — cache key includes session/user:** cached response differs per user / `Vary: Cookie` /
  cached body is the attacker's own/empty page → cache is correctly keyed, NOT exploitable.
- **FP — origin sends `Cache-Control: no-store/private`** and the CDN honors it (no `hit`,
  no `Age`) = properly configured.
- **FP — "Cache Deception Armor"** (Cloudflare): CDN only caches when `Content-Type` matches the
  faked extension → a path-confused `.css` returning `text/html` is NOT cached. If you see
  `hit` only when CT matches the ext, armor is on → gap closed.
- **FP — POST/PUT/state-changing** endpoints: rarely cached, treat as safe.
- **FP — `X-Cache: hit` on the FIRST request:** suspicious (pre-cached/static), not your doing.
- **REAL only if:** same URL → **dynamic (owned-account) data** served from cache to an
  **unauth** request. Caching a *public* page = N/A (no impact). Static-asset 200 ≠ bug.

## Cache POISONING quick-confirm (the other half of U5)
- Find a request whose **unkeyed** header/param the origin reflects into a cacheable response
  (Param Miner → "Guess headers"). Inject a benign marker via the unkeyed input + cache-buster.
- REAL = the marker is served back to a request WITHOUT the injected input (poisoned for all).
  Keep the payload benign (no real XSS payload landing on real users) — prove reflection-into-
  cache with a harmless canary, then hand the operator the chain. Impact-gate: poisoning that
  only affects your own cache-buster key = N/A.

## Autonomous coverage status (honest)
NOT in the daemon confirmers today. This is operator-DIG: the machine/2IC can **surface
candidates** (auth-gated GET routes behind a CDN with cache headers) and even **prove the
unauth discrepancy** (path-confused URL caches → `X-Cache: hit`), but the impact PoC (owned-
account authed page cached + retrieved unauth) is operator-overseen. → enhancement idea:
a `recon_wcd.py` LEAD-surfacer (jsintel auth-GET routes × CDN-cache-header hosts → path-confuse
probe → flag `X-Cache: hit` on a dynamic body). Until then: card 🔬 DIG hand-off.

## Sources
- PortSwigger Research — "Gotta cache 'em all: bending the rules of web cache exploitation"
  https://portswigger.net/research/gotta-cache-em-all
- PortSwigger Web Security Academy — Web cache deception
  https://portswigger.net/web-security/web-cache-deception
- Mirheidari et al., "Cached and Confused: Web Cache Deception in the Wild" (USENIX Security '20)
  https://www.usenix.org/system/files/sec20summer_mirheidari_prepub.pdf

## Implemented in this pipeline (recon_wcd.sh + recon_wcd.py, 2026-06-20)
SAFE detect-only surfacer. Input: in-scope+paying CDN-fronted hosts (ES cdn_name/cdn_type/webserver).
Probes (GET-only, every request a UNIQUE cache-buster ?cb= so we NEVER poison the real shared cache):
WCD = path-confusion variants (`/<n>.css`, `;<n>.css`, `%23<n>.css`) of a NON-cached base → LEAD if the
variant becomes CACHED with ~same body (origin ignored the suffix); WCP = unkeyed header canary
(X-Forwarded-Host/Scheme/Host/...) reflected into a CACHED response under our cb key. LEADs only →
`briefings/wcd_candidates_<date>.md` + wcd/leads.jsonl + ES stamp + briefing; impact PoC (private data
lands in cache / poison persists) is OPERATOR + owned account. Daemon 6h loop (killswitch v2_wcd);
`recon-wcd [scan|confirm <host>|results]`. confirm = Hackmanit WCVS `-ot deception -rr 0.5` (throttled,
cache-buster cbwcvs), operator-overseen.


---
<!-- applied-proposal: 2026-06-20_vulns_class-cache-deception -->
### Applied research — vulns (2026-06-20)

## URL Delimiter Cache Attacks (PortSwigger, June 2026)

Source: https://portswigger.net/research/gotta-cache-em-all

**Technique:** URL parser discrepancies between CDN layer and origin server allow non-standard path delimiters to flip cache behavior. These are DISTINCT from the standard WCD path-confusion variant (dynamic base → cacheable suffix) — here the delimiter itself is the wedge.

### Delimiter gadgets by framework
| Delimiter | Framework | Effect |
|-----------|-----------|--------|
| `;` | Spring (Java) | Treated as path parameter separator by origin; CDN caches as static path |
| `.` | Rails | Treated as format extension by origin |
| `%00` | OpenLiteSpeed | Null byte strips suffix before routing |
| `%0a` | Nginx | Newline splits request |

### Attack variants
- **Cache deception via delimiter:** `GET /account;.css` — CDN caches as static CSS, origin serves dynamic account page.
- **Cache poisoning via delimiter:** Inject unkeyed input (header/param) into a response cached under the delimiter path.

### Detection approach (add to `recon_wcd.sh`)
After standard WCD probe pass, run a second "delimiter pass":


---
<!-- applied-proposal: 2026-06-25_vulns_class-cache-deception -->
### Applied research — vulns (2026-06-25)

## URL Delimiter Confusion Variants (2026 active research)

URL parsing discrepancies between origin and CDN can flip a `Cache-Control: private` / `no-store` response cacheable under a path-confused variant. New delimiter vectors beyond the classic `.php/.js` path-append:

**Delimiters to try (add to `recon_wcd.sh` probe set if missing):**
- `;<extension>` — semicolon before static ext: `/account/profile;.js`
- `%3B<extension>` — percent-encoded semicolon: `/account/profile%3B.css`
- `/<junk>/../<static>` — dotdot normalize: `/account/profile/.js`
- `//` double-slash prefix variations

**CDN specificity:** Cloudflare and Varnish most surface-rich for normalization discrepancies. Cloudflare Pingora normalizes differently than classic CF cache layer.

**Detection gate (pipeline doctrine — unique cache-buster is the safety primitive):**
1. Probe `GET /path<variant>?cb=<unique>` — check if response is cacheable (`CF-Cache-Status`, `Age`, `X-Cache`)
2. Second GET same URL (different session, no cookies) — if `CF-Cache-Status: HIT` while base path returns `DYNAMIC/private` = cacheability flip = LEAD
3. Impact PoC (authenticated data in cache) = operator owned-account step

**Source:** https://blogs.jsmon.sh/from-cache-poisoning-to-account-takeover-a-modern-web-security-case-study/


---
<!-- applied-proposal: 2026-06-27_vulns_class-cache-deception -->
### Applied research — vulns (2026-06-27)

## Framework-Specific Path Delimiter Attacks (PortSwigger "Gotta Cache 'Em All", 2026)

Prior WCD relied on appending `.js`/`.css` to dynamic paths. This maps framework-specific path terminators that CDNs don't recognize but origin frameworks strip:

| Framework | Delimiter | Probe |
|---|---|---|
| Spring (Java) | `;` (path param) | `/account;.js` |
| Ruby on Rails | `.` (format extension) | `/account.css` |
| OpenLiteSpeed | `%00` (null byte) | `/account%00.js` |
| Nginx | `%0a` (newline) | `/account%0a.js` |

CDN sees a static extension → caches. Origin strips the delimiter → serves the dynamic authenticated response. Cache stores it under an attacker-accessible key.

**Affected CDNs:** Cloudflare, CloudFront, Google Cloud CDN, Akamai, Fastly (all confirmed by PortSwigger research).

**Cloudflare Cache Deception Armor bypass:** `.avif` and other non-standard extensions bypassed Armor at time of research.

**Normalization WCP angle:** `%3F`/`%2F` combined with dot-segment traversal (`../`) allows poisoning path A while CDN caches it under path B.

**Add to `recon_wcd.sh` probe list:** `;.js`, `%00.js`, `.css`, `%0a.js` (in addition to existing `.js` suffix probes).

Source: https://portswigger.net/research/gotta-cache-em-all


---
<!-- applied-proposal: 2026-06-30_detect-tune_class-cache-deception -->
### Applied research — detect-tune (2026-06-30)

## CDN Identification Oracle (add before §Probing)

Identify CDN before running WCD probes. Skip if CDN never caches dynamic routes for that response pattern.

| CDN | Identifying Header | Cache-Hit Value | Skip Signal |
|-----|-------------------|-----------------|-------------|
| Cloudflare | `CF-Cache-Status` | `HIT` | `DYNAMIC` on suffix path = skip |
| Akamai | `Server-Timing: cdn-cache; desc=HIT` | `desc=HIT` | `desc=MISS` consistently = likely not caching |
| Fastly | `X-Fastly-Cache` | `HIT` | absent = not Fastly |
| CloudFront | `X-Amz-Cf-Id` | `X-Cache: Hit from cloudfront` | `X-Cache: Miss` = not cached |
| Varnish | `X-Varnish` (two integers) | two integers | single integer = miss |

**FP suppression:** `CF-Cache-Status: DYNAMIC` or `Cache-Control: no-store` on the suffix-appended path = correctly NOT cached = secure FP, skip. Only the cacheability flip (dynamic base → cacheable suffix variant) is a real candidate.

**Cache-buster rule (safety primitive):** append `?cb=<uuid>` to every WCD probe so tests run under YOUR cache key, never poisoning the shared cache. Two requests with the same buster: if second returns cache HIT = confirmed cached under your key = WCD candidate.

## Varnish-specific (see also tech-varnish.md)

Varnish-fronted hosts expose a secondary bug class: unauthenticated PURGE. Add as `recon-wcd confirm` step for Varnish-identified hosts:
```bash
curl -X PURGE https://<host>/<path> -sv | grep "< HTTP"
```


---
<!-- applied-proposal: 2026-07-11_vulns_class-cache-deception + 2026-07-17_vulns_class-cache-deception -->
### Applied research — vulns (2026-07-11 / 2026-07-17) — Varnish CVE-2026-34475 bare-`/` path-confusion variant

**CVE-2026-34475 — Varnish Cache auth-bypass / cache-poisoning via root-path `req.url`** (CVSSv3.1 5.4;
remote, unauth-reachable, high attack complexity). *(verify vs NVD/GHSA before minting — see caveat below.)*
- **Affected:** Varnish Cache < 8.0.1 / Varnish Enterprise < 6.0.16r12. **Fixed:** 8.0.1 (OSS) / 6.0.16r12 (Ent).
- **Mechanism:** improper validate-before-canonicalize (CWE-180) of a request whose URL path is exactly `/`
  under an `unchecked req.url` VCL → cache-key confusion → cache poisoning or auth-boundary bypass.
- **Why it matters for this lane:** a genuine cacheability-flip primitive (matches our WCD confirm bar, NOT
  the by-design-CDN FP pattern) — and a concrete probe variant beyond generic suffix path-confusion: test the
  **bare `/` differential** the same way `recon_wcd.sh` tests other path-confusion variants (unique per-host
  cache-buster, never touch the shared cache; check for anomalous cached auth-state leakage).
- **Detect:** confirm Varnish via `Via: 1.1 varnish` / `X-Varnish` headers (version is usually NOT
  banner-exposed → confirm the flip **behaviorally**, not by version string), then version-gate before
  treating as more than a LEAD.
- **Sources:** https://nvd.nist.gov/vuln/detail/CVE-2026-34475 · https://github.com/advisories/GHSA-m9gq-cmcj-p62x
  · https://www.sentinelone.com/vulnerability-database/cve-2026-34475/

_(Note: a 2026-07-14 proposal re-surfaced the PortSwigger "Gotta Cache 'Em All" delimiter-discrepancy
technique — Spring `;`, Rails `.`, OpenLiteSpeed `%00`, Nginx `%0a`, `#` — already covered above; not
re-merged.)_

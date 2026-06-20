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

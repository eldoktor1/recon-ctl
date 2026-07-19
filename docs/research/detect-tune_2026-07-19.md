# Research digest — detect-tune — 2026-07-19

## Detection & Verification Tuning — Digest (2026-07-19)

### 1. GraphQL introspection-disabled bypass — 3 techniques beyond Clairvoyance suggestion-mining (HIGH actionable)
Our `recon_graphql.sh` already falls back to Clairvoyance-style field-suggestion mining when standard `__schema` introspection is blocked. Three additional bypass angles surfaced, all read-only/safe and wired for our existing lane:
- **Regex-blocklist bypass**: many servers block introspection with a regex matching literal `__schema`/`__type` substrings, but GraphQL parsers ignore whitespace/commas/newlines inside the query — inserting harmless whitespace inside the field name (`__sch\nema`) or wrapping in an alias can slip past a naive regex gate while the parser still executes it.
- **Inline-fragment nesting bypass**: shallow security checks that only inspect the top-level selection set miss a nested `__type` field wrapped inside an inline fragment (`... on Query { __type(name:"X"){name fields{name}} }`) — still read-only, still just schema disclosure.
- **Alternate SDL-disclosure resolvers**: some frameworks expose schema-equivalent info via a non-`__schema` resolver (seen in a Directus-style CVE pattern, e.g. a `*_specs_graphql`/schema-introspection convenience query) even when the standard introspection query is hard-blocked.
- Real CVEs confirm the general class is still live in 2026: CVE-2026-30854 (Parse Server, inline-fragment introspection bypass) and CVE-2026-35413 (Directus GraphQL introspection bypass).

Sources: [André Baptista field-suggestion thread](https://x.com/0xacb/status/2022643073855951103), [Parse Server CVE-2026-30854](https://dailycve.com/parse-server-graphql-introspection-bypass-via-inline-fragments-cve-2026-30854-moderate/), [Directus CVE-2026-35413](https://www.sentinelone.com/vulnerability-database/cve-2026-35413/), [webonyx/graphql-php field-suggestion issue](https://github.com/webonyx/graphql-php/issues/454)



### 2. Cloudflare "Cache Deception Armor" — new FP-suppression signal for our WCD lane (MEDIUM actionable)
Cloudflare now ships a dedicated feature (Cache Deception Armor) that detects a content-type mismatch between the cache-key path and the actual response and refuses to cache it. For any Cloudflare-fronted host with this enabled, a WCD probe will consistently show `MISS`/no-cache even on a real path-confusion payload — that's the feature working, not a failed probe. This sharpens our existing "cacheability flip" primitive: worth a one-time host-level check (does *any* WCD-shaped payload ever get cached on this host, even innocuous ones?) before spending probe budget on class-mismatch payload variants against a CF host — if even benign confusable paths never cache, the host is armored and every WCD lead there is a secure-FP, not "needs more variants."

Sources: [Cloudflare Cache Deception Armor docs](https://developers.cloudflare.com/cache/cache-security/cache-deception-armor/), [CF-Cache-Status header reference](https://www.debugbear.com/docs/cf-cache-status), [Cloudflare WCD revisited](https://blog.cloudflare.com/web-cache-deception-attack-revisited/)



### 3. Cache poisoning — capitalized Host header as an additional unkeyed vector (LOW-MEDIUM, fits Varnish in our top tech)
Beyond the standard unkeyed-header set (`X-Forwarded-Host`, `X-Forwarded-Scheme`, etc.), a documented edge case: a **capitalized `Host` header** (`HOST:` vs `host:`) can poison the cache on certain Varnish VCL configs (and historically hit Cloudflare too before their fix) because the cache key normalization and the header-matching logic disagree on case. Cheap to add as one more probe variant in `recon_wcd.sh`'s WCP unkeyed-header sweep, particularly on our Varnish-fronted hosts.

Sources: [Cache Poisoning at Scale](https://youst.in/posts/cache-poisoning-at-scale/), [PortSwigger — exploiting cache design flaws](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws)



### 4. Favicon-hash fingerprinting — cheap enumeration widener for sibling infra (LOW effort, fits credit-conservative uncover lane)
Standard technique (mmh3 hash of base64 favicon bytes) not currently in our enumeration toolchain. Because many orgs reuse one favicon across main site + subdomains + staging + internal tools, a favicon hash pulled from an already-confirmed in-scope host can be turned into a **Shodan `http.favicon.hash:<hash>`** dork (or FOFA `icon_hash=`) to surface sibling infra that subfinder/CT/permutation miss — and it costs exactly one extra Shodan query per candidate hash, fitting inside our existing hard monthly budget gate. Only worth running on hosts with a non-default (non-framework-stock) favicon, since a default Nginx/Apache/CMS-stock icon hash will just return thousands of unrelated noise.

Source: [Favicon Hashing: 1000s of exposed panels](https://systemweakness.com/favicon-hashing-how-i-fingerprinted-1000s-of-exposed-panels-in-minutes-bbeb5bf47a17), [FavFreak / favicon fingerprint dict](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)



### Minor confirmations (no KB change needed — already matches our design)
- **IDOR**: current industry consensus reaffirms our ranker's stance — UUIDs reduce brute-forceability but do NOT imply an ownership check exists; several implementations use time-based/predictable UUIDv1. No change to `recon_idor_candidates.py` scoring logic needed, but worth remembering not to *downgrade* a UUID-keyed endpoint's priority purely for being a UUID.
- **S3 dangling buckets**: AWS rolled out "account regional namespaces" (Mar 2026) as a forward-looking mitigation — new buckets opted into this scheme are no longer globally squattable — but **existing buckets in the legacy global namespace are unaffected and remain exploitable**, so our current NoSuchBucket + live-host-reference detection stays valid without changes. [Google Cloud dangling-bucket best practices](https://cloud.google.com/blog/products/identity-security/best-practices-to-prevent-dangling-bucket-takeovers) note the same DNS-resolves-successfully-to-attacker's-resource trap our doctrine already treats as a hard line (never assume a resolving CNAME means "not vulnerable").

No further items met the bar this run — most 2026 "bug bounty automation" writeups surfaced were generic AI-agent-hype content with no new fingerprint/FP data beyond what's already in our KB.

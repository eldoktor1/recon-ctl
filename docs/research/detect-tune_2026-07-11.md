# Research digest — detect-tune — 2026-07-11

# Detection & Verification Tuning — Research Digest (2026-07-11)

## 1. GraphQL — engine fingerprinting + introspection-block bypass (actionable, feeds `recon_graphql.sh`)
- **graphw00f** (dolevf) fingerprints the GraphQL *engine* itself (36+ implementations: Graphene/Ariadne/Strawberry/graphql-go/gqlgen/Hasura/WPGraphQL/Apollo/etc.) by sending a mix of benign + deliberately malformed queries/directives and matching the distinct error text/behavior each engine returns — independent of whether introspection is enabled. Also cross-refs findings against the GraphQL Threat Matrix for known posture issues per engine. Worth bolting onto our schema-harvest step: engine ID lets us pick engine-specific known-mutation/known-bug lists instead of generic probing.
- **Introspection-block bypass**: many "disable introspection" deployments are just a regex grep on the request body for `__schema`/`IntrospectionQuery`. Inserting a special/whitespace character immediately after `__schema` slips past naive regex blocks while the parser still accepts it — worth trying before falling back to Clairvoyance field-suggestion recovery (cheaper, still read-only).
- Precision note: introspection-enabled-alone is still Info/dup (unchanged doctrine) — these are enumeration upgrades, not new confirm primitives.

Sources: [graphw00f](https://github.com/dolevf/graphw00f), [GraphQL Security 2026 — Beyond Introspection](https://ringsafe.in/graphql-security-beyond-introspection/), [A Story of GraphQL: Tuning Out Introspection Vulnerabilities](https://abawazeeer.medium.com/a-story-of-graphql-tuning-out-introspection-vulnerabilities-061ce14d609c)



## 2. Dalfox v3 (Rust rewrite, May 2026) — fewer FPs on our XSS/blind-XSS confirm gate
Dalfox did a full Rust rewrite (v3.0.0, 2026-05-25) with AST-backed DOM verification specifically to kill false positives from blind/inert reflections. v3.1.1 further demoted **inert `javascript:`/URL-scheme self-link reflections** (a known FP source) and fixed reflected-XSS recall regressions in raw-JS-expression/regex-literal contexts. Action: confirm our `recon_xss_confirm.sh` / `recon_blindxss.sh` pin dalfox ≥3.1.1 (Rust build) — older binaries will both under-report real reflected-JS-context XSS and over-report inert `javascript:` self-links we'd otherwise have to hand-filter.

Sources: [Dalfox v3.1.1 release notes](https://github.com/hahwul/dalfox/releases/tag/v3.1.1), [Dalfox project site](https://dalfox.hahwul.com/)



## 3. JWT — kid/jku header attack precision (feeds `class-jwt-attacks`, still human-confirm only per doctrine)
Detection sequence worth scripting as a **lead-only** probe (never auto-exploit): swap `alg` across `none`/`HS256`/`HS384`/`RS256` and observe whether the server still returns 200 with a *different* accepted alg (signal of missing algorithm allowlisting) — this is lead-grade, not confirm-grade, since accepting the header alone proves nothing without a working forged signature. Two concrete sub-vectors worth fingerprinting in already-collected JS/API data: **`jku`/`x5u`** header presence (server fetches signing keys from an attacker-controllable URL — grep JS/config for `jku`/`x5u` claims we control) and **`kid`** used unsanitized as a file path or DB lookup key (injection primitive, not just key selection). All three remain human-in-the-loop exploitation (forging a valid signature = an active PoC under our ACTIVE-PoC gates), but grepping already-crawled endpoints/JS for these claim names is a cheap ES-enrichment win.

Sources: [JWT algorithm confusion attacks](https://aquilax.ai/blog/jwt-algorithm-confusion-auth-bypass), [JWT Algorithm Confusion to Account Takeover: jku/kid](https://blogs.jsmon.sh/jwt-algorithm-confusion-to-account-takeover-rs256-hs256-jku-injection-kid-sqli/)



## 4. Varnish — unauthenticated cache-PURGE as a safe, zero-risk fingerprint
"Unauthenticated Varnish cache purge" (PURGE method reachable without auth) is a known real misconfig class. It's checkable with a **fully safe, non-mutating** primitive: send `OPTIONS` and read the `Allow:` header — if `PURGE` appears without any auth challenge, that's a lead worth a human decision (actually issuing a PURGE is a write-ish action and should stay operator-gated, consistent with our GET/HEAD/OPTIONS-only autonomous-probe rule).

Sources: [Adam Silcox — unauthenticated-varnish-cache-purge](https://www.linkedin.com/posts/adamsilcox_the-unauthenticated-varnish-cache-purge-activity-7072269488296996864-vF4x), [HTTP fingerprinting recon](https://www.yeswehack.com/learn-bug-bounty/recon-series-http-fingerprinting)



## 5. Favicon-hash fingerprinting — cheap enumeration widening for `recon_uncover.sh`
mmh3-hash the base64 of a target's favicon and Shodan/Censys/FOFA-dork on `http.favicon.hash:<value>` to surface shared-infra subdomains/hosts that DNS/CT enumeration misses (orgs commonly reuse one favicon across main site + staging + internal tools). Cheap to add to our existing scoped-dork uncover lane (same credit-budget discipline already in place) since it's just another dork template, not a new API. Caveat (their own limitation note, matches our FP discipline): a favicon match is an indicator only — trivially spoofable/collidable, so treat hits as **enumeration candidates to resolve+scope-check**, never as identity confirmation on their own.

Sources: [Favicon Hashing: Fingerprinted 1000s of Exposed Panels](https://systemweakness.com/favicon-hashing-how-i-fingerprinted-1000s-of-exposed-panels-in-minutes-bbeb5bf47a17), [Shodan favicon hash trick](https://infosecwriteups.com/how-to-find-subdomains-using-shodan-and-the-favicon-hash-trick-ac01741b0fb5)



## Low-signal / not actionable this run
- Web Cache Vulnerability Scanner (WCVS) added flags to *reduce* its own FPs (drop timing-only cache inference, `--ignorestatus` for WAF-injected 429s) — good to know if we ever adopt WCVS directly, but our `recon_wcd.sh` already uses a stricter cacheability-flip primitive, so no KB change warranted.
- `can-i-take-over-xyz/fingerprints.json` is actively maintained but nothing new surfaced beyond "keep it in sync" — worth a periodic re-pull, not a doctrine change.

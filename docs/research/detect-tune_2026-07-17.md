# Research digest — detect-tune — 2026-07-17

```
Detection & Verification Tuning — 2026-07-17
```

## 1. Dalfox v3.1.2 — complete Rust rewrite, breaking CLI + new precision flags (HIGH PRIORITY, check our confirm lane)
Dalfox went from Go (v2.x) to a **full Rust rewrite**, current release **v3.1.2 (2026-06-27)**. The CLI is
restructured into subcommands (`scan`, `server`, `payload`, `mcp`) instead of the old flat single-command
invocation `class-blind-xss.md`/`recon_xss_confirm.sh`/`recon_dast.sh` likely assume. If the box has picked up
v3 via a package update, old flag syntax may silently no-op or error — **worth a one-time check that our
confirm scripts still invoke it correctly** before trusting a "no XSS" result.
Two precision-relevant additions:
- **`--waf-min-confidence <0.0-1.0>`** — tunable WAF-fingerprint confidence threshold (default 0.3 suppresses
  weak WAF matches; 1.0 keeps only high-confidence). Useful to cut noisy "WAF detected, evasion applied" spam
  in our confirm output without losing real evasion attempts.
- **DOM/AST verification** — v3 does AST-backed DOM checks rather than pure blind-reflection matching,
  which should reduce the "reflection ≠ XSS" FP class we already guard against manually.
v2 stays maintained on the `v2` branch for security backports only — no new features land there.

Sources:
- [GitHub - hahwul/dalfox](https://github.com/hahwul/dalfox)
- [Dalfox docs](https://dalfox.hahwul.com/)



## 2. GraphQL Clairvoyance field-suggestion recovery can itself be disabled — don't read "no suggestions" as "schema safe"
Confirmed our `class-graphql.md` field-suggestion-recovery approach (typo'd field name → "did you mean X"
leaks schema even with introspection off) is the same technique researchers call **Clairvoyance / field
fuzzing**. The counter-move server operators are adopting: Apollo Server v4+ has
`hideSchemaDetailsFromClientErrors` and a `blockFieldSuggestions` option that suppresses the "did you mean"
hint specifically (separate from disabling introspection). **FP-tuning implication:** if our Clairvoyance-style
probe gets zero suggestions back, that is NOT proof the schema is genuinely undiscoverable — it may just mean
suggestions were blocked while introspection-adjacent info (error verbosity, field-type errors, `__typename`
timing) still leaks elsewhere. Don't downgrade a target to "graphql locked down, skip" on suggestion-silence
alone; check raw error verbosity/error codes as a secondary signal before writing it off.

Sources:
- [A Comprehensive Guide to GraphQL Introspection — Escape](https://escape.tech/blog/should-i-disable-introspection-in-graphql/)
- [When GraphQL field suggestions become a Security Issue — Escape](https://escape.tech/blog/graphql-verbose-error-suggestions/)
- [GraphQL Security 2026 — Beyond Introspection — RingSafe](https://ringsafe.in/graphql-security-beyond-introspection/)



## 3. S3 bucket detection: NoSuchBucket vs AccessDenied — reconfirms our existing logic, one nuance
`NoSuchBucket` in the XML error body = bucket doesn't exist (dangling-CNAME/takeover candidate if a live host
still references it). `AccessDenied` (403) on an *existing* bucket depends on whether the requester has
`s3:ListBucket` — a 403 on a specific key can appear even for buckets that are NOT publicly listable, so a lone
403 proves nothing either way (matches our existing FP doctrine). One dedupe nuance worth logging: S3 doesn't
bill the bucket owner for AccessDenied responses triggered by requests *originating outside* the owner's AWS
org — not security-relevant to us directly, but explains why some 403s come back near-instantly (no cross-account
throttling) while genuine ListBucket-permitted probes are slower — a possible weak timing signal if we ever need
one, not worth building on its own.

Sources:
- [Troubleshoot access denied (403) errors in Amazon S3 — AWS docs](https://docs.aws.amazon.com/AmazonS3/latest/userguide/troubleshoot-403-errors.html)
- [Amazon (AWS) S3 Bucket Take Over — LevelBlue](https://www.levelblue.com/blogs/spiderlabs-blog/amazon-aws-s3-bucket-take-over)

## 4. AWS Cognito — two 2026 CVEs to version-check (⚠️ UNVERIFIED, self-flagged per doctrine)
Search surfaced **CVE-2026-6911** (described as missing JWT signature verification at an API Gateway front
of Cognito — unauthenticated token forgery → cross-tenant admin access, CWE-347, critical) and
**CVE-2026-6912** (privilege escalation via a writable `custom:deployment_admin`-style attribute through
`UpdateUserAttributes`, appears scoped to a specific product "Ops Wheel" rather than Cognito itself generically).
**Neither is NVD-verified in this pass** — per our doctrine, LLM-search CVE IDs can be hallucinated. Do not
mint either as a P0/LEAD until pulled directly from `nvd.nist.gov`/`cve.org` and version-matched against an
actual in-scope Cognito-fronted host. CVE-2026-6912 in particular reads like it may be misattributed to a
specific open-source app rather than AWS Cognito core — treat with extra skepticism.
**Generically reusable pattern regardless of those two CVEs**: our `class-cognito-unauth.md` already covers
guest/unauthenticated-identity-pool credential fetch; reconfirm current best practice — the root cause pattern
across recent Cognito writeups is consistently (a) app trusting the `email` attribute instead of `sub` for
identity, combined with a writable custom attribute, and (b) identity pool `AllowUnauthenticatedIdentities`
returning usable temp AWS creds when it shouldn't. Worth grepping `endpoints.jsonl`/jsintel output for hardcoded
`userPoolId`/`identityPoolId`/`clientId` values as the enumeration fingerprint (already implied by our JS-intel
lane, no new tooling needed — just confirm the cognito scripts are pulling from that feedstock).

Sources:
- [Full Account Takeover via AWS Cognito Misconfiguration — Cobalt](https://www.cobalt.io/blog/full-account-takeover-via-aws-cognito-misconfiguration)
- [AWS Cognito pitfalls: Default settings attackers love — SECFORCE](https://www.secforce.com/blog/aws-cognito-pitfalls-default-settings-attackers-love-and-you-should-know-about/)
- [Amazon Cognito — Application Security Cheat Sheet](https://0xn3va.gitbook.io/cheat-sheets/cloud/aws/amazon-cognito)

## 5. WordPress `/wp-json/wp/v2/users` enumeration — reconfirm as Info/N/A, not a standalone finding
Reconfirms existing doctrine rather than adding new signal: WP REST user enumeration
(`/wp-json/wp/v2/users`, `?author=N` redirect probe) is intentional-by-design behavior WordPress core ships
with (supports headless/mobile integrations), restricted only to REST-exposed post-type authors since 4.7.1.
**FP-tuning note for `tech-wordpress.md`:** treat a bare username-enumeration finding as theoretical/no-impact
(same bucket as CORS/missing-headers/self-XSS per our impact-gate doctrine) unless chained with something that
makes it payable — e.g. no login rate-limiting/lockout on the same host (credential-stuffing amplifier) or an
XML-RPC `system.multicall` brute-force vector still enabled alongside it. Don't spend probe budget minting
this alone.

Sources:
- [WordPress REST API User Enumeration — Invicti](https://www.invicti.com/web-application-vulnerabilities/wordpress-rest-api-user-enumeration)
- [WordPress REST API security: hiding endpoints and preventing user enumeration — Jorijn Schrijvershof](https://jorijn.com/en/knowledge-base/wordpress/security/wordpress-rest-api-security/)



## Not actionable this run
Cloudflare bot-management bypass research (JA3/HTTP2 fingerprint evasion, Turnstile bypass) — all results were
scraper-evasion-for-scraping content, not applicable to our unauth-safe/non-destructive confirm primitives; skipped.

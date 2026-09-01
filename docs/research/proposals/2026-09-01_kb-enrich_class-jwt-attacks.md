# PROPOSAL (proposal) for docs/knowledge/class-jwt-attacks.md — kb-enrich 2026-09-01
_Review and apply manually; not auto-merged into the KB._

## 2026 update — algorithm confusion, jku injection, kid SQLi (concrete unauth-safe probes)

- **Algorithm confusion RS256→HS256**: fetch the server's RSA public key from the standard
  `/.well-known/jwks.json` (or wherever `jku`/`x5u` in a live token points), then forge a token with
  `"alg":"HS256"` signed using that PEM public key *as the raw HMAC secret string*. A vulnerable verifier
  that trusts the header's `alg` will validate it as if the symmetric secret matched. Test with
  `jwt_tool -X a` (auto-tries alg confusion) or manually via `jwt.io`/PyJWT `jwt.encode(payload, pubkey_pem,
  algorithm="HS256")`. Detect unauthenticated by simply checking whether `/.well-known/jwks.json` (or any
  `jku`/`x5u` claim in an intercepted token) is reachable and whether the app's stack (Node
  jsonwebtoken<9, Java jjwt<0.10, etc.) is a known-vulnerable version — LEAD until an actual forged token
  is accepted, which needs an owned test account per our IDOR/authed-testing doctrine (this becomes an
  auth-bypass primitive, i.e. the strongest possible finding — treat forging-and-testing as ACTIVE-PoC:
  own account only, prove once, stop).
- **`jku`/`x5u` header injection**: if the server fetches the verification key from a URL taken out of the
  token's own header (`jku`) rather than a hardcoded allowlist, point it at an attacker-controlled JWKS
  (or interactsh callback per our OOB-evidence doctrine) with our own keypair, sign the forged token with
  our own private key. **Safe unauth detection**: inject an interactsh URL into `jku`/`x5u` on a *login or
  refresh-token* request and watch for an outbound fetch callback — a callback alone (no valid session
  needed) already proves the server blindly dereferences attacker-supplied key URLs, which is a legitimate
  unauth LEAD/finding on its own (SSRF-adjacent, matches our interactsh-for-evidence lane) even before
  attempting a full forge.
- **`kid` parameter injection (SQLi / path traversal)**: when `kid` indexes a DB lookup or filesystem path
  for the verification key, inject SQLi payloads (`' UNION SELECT 'known-secret'-- -`) or path traversal
  (`../../../../dev/null`, a file with deterministic/empty content) into `kid`, then sign the forged token
  using that forced/known value as the HMAC secret. Detect the injection surface safely and unauth: single
  quote / time-based delay in `kid` is enough to prove the injection *point* exists (SQLi differential,
  same `'` vs `''` primitive as our `class-sqli` confirm) without needing to complete the full forge —　that's
  the CONFIRMED-vs-LEAD boundary: injection-point-confirmed = SQLi finding on its own merit; full-forge =
  auth-bypass finding, requires the injected value actually be leveraged into a valid signed token (do this
  minimally, once, then stop per ACTIVE-PoC doctrine).
- **Path traversal into `/dev/null`** is notable: an empty-but-existing "key" (`/dev/null` contents = empty
  string) means the HMAC secret is a known, empty value — trivially forgeable even without SQLi.

### Fingerprinting priority
`jwt_tool -M pb` (playbook mode) auto-runs all three classes read-only/detect-first. Prioritize hosts using
Node `jsonwebtoken` <9.0.0, Java `jjwt` <0.10.0, PHP `firebase/php-jwt` <6.0 — all had default-insecure
`alg`-trusting behavior at some point; version-fingerprint via response headers / error stack traces / JS
bundle deps (ties into our jsintel + n-day lanes) before spending probe budget.

Sources: [blogs.jsmon.sh — JWT Algorithm Confusion to Account Takeover](https://blogs.jsmon.sh/jwt-algorithm-confusion-to-account-takeover-rs256-hs256-jku-injection-kid-sqli/),
[dev.to — JWT Algorithm Confusion CVE-2026-22817/27804/23552 fix guide](https://dev.to/iamdevbox/jwt-algorithm-confusion-attacks-cve-2026-22817-cve-2026-27804-and-cve-2026-23552-fix-guide-4ac4) ⚠️ dev.to aggregator, NVD-verify these CVE IDs before citing in any report.

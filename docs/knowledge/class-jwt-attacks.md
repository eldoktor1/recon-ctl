# JWT Algorithm Confusion & Authentication Bypass

## Why it's dup-resistant
Requires a valid token from the app (often buried in JS/sourcemaps) + understanding the signing algorithm. Commodity scanners don't attempt it.

## Attack classes (highest payout first)

### 1. Algorithm confusion (RS256 → HS256)
If server uses RS256 (asymmetric), attacker can forge tokens signed with the PUBLIC key treated as an HMAC secret if server accepts HS256. The public key is often embedded in JS or served at `/.well-known/jwks.json`.

```bash
# jwt_tool: RS→HS confusion
python3 jwt_tool.py <token> -X k -pk public.pem
```

## Detection-only signals (2026-07-11) — human-confirm before minting anything

Fingerprint from **already-crawled JS / API responses** (no new target traffic), surface as a
LEAD, never auto-mint:

- **Header/claim flags in captured tokens:**
  - `jku` / `x5u` — server fetches the signing key(s) from a **URL inside the token**. Exploitable
    ONLY if that URL is **attacker-controllable** (e.g. host-header/open-redirect/SSRF into a JWKS
    you serve). URL present ≠ bug.
  - `kid` — key-id header. Exploitable ONLY if the value is used **unsanitized** as a file path
    (path traversal → known key file) or a DB lookup (SQL/command injection primitive). Presence
    alone is normal.
- **LEAD-grade probe — `alg` swap:** replace `alg` with `none` / `HS256` / `HS384` / `RS256`. A
  **200 with a DIFFERENT accepted alg** signals **missing algorithm allowlisting** — but this is a
  SIGNAL, not confirmation: no forged signature has been validated yet. Do **NOT** mint CONFIRMED
  off header-acceptance alone. Actually forging a working signature (RS256→HS256 with the public
  key as HMAC secret, `alg=none` with an empty signature, weak-secret crack) is an **active-PoC
  step** — own-account, ACTIVE-PoC gates, human-in-the-loop.

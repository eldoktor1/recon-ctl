# PROPOSAL (proposal) for docs/knowledge/class-jwt-attacks.md — kb-enrich 2026-07-26
_Review and apply manually; not auto-merged into the KB._

## 2026-07-26 update — concrete exploitation chains

### RS256→HS256 algorithm confusion (weaponized)
1. Fetch the server's RSA public key (`/.well-known/jwks.json`, or embedded cert).
2. Sign a forged token with **HS256**, using the raw PEM bytes of the public key as the HMAC secret (no transformation needed — `jwt.encode(payload, pub_key_bytes, algorithm="HS256")`).
3. If the server's verify path does `jwt.decode(token, key, algorithms=["RS256","HS256"])` (accepts an algorithm list instead of pinning one), it will treat the public key as a shared HMAC secret and accept the forgery.
- Root cause signature to grep for in target JS/API docs: any library config that trusts the token's own `alg` header, or passes a list of allowed algorithms including both an asymmetric and symmetric option.
- Tool: `jwt_tool <token> -X a` automates the confusion attempt.

### JKU/X5U header injection
Host a malicious JWKS at an attacker-controlled URL, set `jku` (or `x5u`) in the forged token header to that URL, sign with your own keypair. If the server blindly fetches `jku`/`x5u` to verify rather than pinning to a known key registry, it validates your self-signed token as trusted. `jwt_tool <token> -X s` automates JWKS spoofing/hosting.
- SSRF angle: even if outright forgery fails, an app that fetches `jku` unauthenticated is a **verifiable SSRF sink** — point it at an interactsh canary per our SSRF confirm primitive before trying full auth bypass.

### kid parameter injection (SQLi / path traversal)
If `kid` selects a signing key from a DB or filesystem lookup:
- SQLi: `kid = "x' UNION SELECT 'attacker_secret'-- -"` — forces the lookup to return an attacker-chosen string, then sign HS256 with that string as the secret.
- Path traversal (file-based keystores): `kid = "../../dev/null"` — forces an empty-file read, then sign HS256 with the empty string as secret.
- Both are LEAD-until-differential per our SQLi discipline (`'` vs `''` on the `kid` value first) before minting — never blind UNION-inject against a live target without the differential confirming injectability.

Sources: [jsmon.sh writeup](https://blogs.jsmon.sh/jwt-algorithm-confusion-to-account-takeover-rs256-hs256-jku-injection-kid-sqli/), [WorkOS](https://workos.com/blog/jwt-algorithm-confusion-attacks).

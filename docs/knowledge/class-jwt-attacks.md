# JWT Algorithm Confusion & Authentication Bypass

## Why it's dup-resistant
Requires a valid token from the app (often buried in JS/sourcemaps) + understanding the signing algorithm. Commodity scanners don't attempt it.

## Attack classes (highest payout first)

### 1. Algorithm confusion (RS256 → HS256)
If server uses RS256 (asymmetric), attacker can forge tokens signed with the PUBLIC key treated as an HMAC secret if server accepts HS256. The public key is often embedded in JS or served at `/.well-known/jwks.json`.

```bash
# jwt_tool: RS→HS confusion
python3 jwt_tool.py <token> -X k -pk public.pem

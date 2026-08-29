# PROPOSAL (proposal) for docs/knowledge/class-jwt-attacks.md — kb-enrich 2026-08-29
_Review and apply manually; not auto-merged into the KB._

## 2026 update: alg-confusion still shipping (cross-language CVE cluster) + concrete kid PoC payloads

**Case-variant `alg:none` bypass:** if a plain `alg=none` swap gets rejected, retry with case variants
before giving up — `nOnE`, `NoNE`, `NONE`. Naive denylists string-match only the literal lowercase `none`.

**2026 confirms this class is still actively regressing, not just legacy:**
- `CVE-2026-34950` (fast-jwt, Node) — a *second-time* RS256→HS256 confusion bypass: the original fix used
  a regex with a starting anchor to detect "this looks like an RSA public key, refuse HS256 verification
  against it"; prefixing the key with leading whitespace (space/tab/\n) defeats the anchor and re-opens
  the original bug in an already-patched library. Lesson for our own detection: don't trust "library says
  it validates alg" — check the actual regex/anchor logic version, incomplete fixes recur.
- `CVE-2026-22817` (Hono, TS/JS, CVSS 8.2) and `CVE-2026-23993` (HarbourJwt, Go) — same RS256→HS256 /
  unknown-algorithm-acceptance bug class, different languages, same year. Alg confusion is a systemic
  implementation gap, not a single-library legacy issue — always worth testing regardless of stack/tech.
- `CVE-2026-23552` (Keycloak) — accepted cross-realm tokens due to missing `iss` claim validation. For any
  multi-tenant IdP (Keycloak/Auth0/Cognito custom pools), add an explicit check: does the resource server
  validate `iss` matches the EXACT expected tenant/realm, or just "signature verifies + issuer is *an*
  IdP we trust"? A token from Tenant A accepted on Tenant B's resources is a cross-tenant IDOR via JWT.

**Concrete `kid`-injection PoC payloads (move from "presence is a signal" to an actual forge attempt —
still ACTIVE-PoC / own-account doctrine, this forges a token, treat like a credential-bypass test):**
- File-backed key lookup: set `kid` to a traversal that resolves to a predictable/empty file, e.g.
  `../../../../../../../dev/null`; set the JWK/HMAC key `k` to `AA==` (base64 for `\x00`) matching what
  an empty file would produce as the "key"; sign HS256 with that value. If the server loads the key file
  named by `kid` and treats its (empty) contents as an HMAC secret, the forged signature validates.
- DB-backed key lookup: inject SQL metacharacters into `kid` (`'`, `UNION SELECT`, time-based) to force
  the key-lookup query to return an attacker-known/empty string; sign HS256 using that same string as the
  secret. Fuzz `kid` with both SQLi and path-traversal payload sets before concluding "kid isn't
  exploitable here."
Sources: thehackerwire.com (fast-jwt CVE-2026-34950), securityonline.info (same), dev.to JWT algorithm
confusion CVE roundup, Invicti (kid path traversal / kid SQLi write-ups).

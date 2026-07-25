# PROPOSAL (proposal) for docs/knowledge/class-jwt-attacks.md — vulns 2026-07-25
_Review and apply manually; not auto-merged into the KB._

## Generalized 2026 JWT verification-library bypass patterns (added 2026-07-25)
Two disclosures this cycle show the same underlying bug class recurring in different JWT libraries —
worth probing for on ANY authed API using JWTs, not just the named products:
1. **Public-key-as-forgery-key confusion (CVE-2026-29000, pac4j-jwt):** if the app exposes its RSA
   public key (JWKS endpoint, embedded in JS, or predictable path), test whether the verifier can be
   tricked into treating that public key material as valid signing/encryption key input — a variant of
   classic RS256→HS256 algorithm confusion but via key *type* confusion rather than algorithm swap alone.
2. **Unknown-`alg` fails open to empty-string comparison (CVE-2026-23993, HarbourJwt):** some libraries'
   signature-generation path returns an empty string for an `alg` value it doesn't recognize, and the
   verification comparison doesn't treat "empty expected signature" as an error. Test: swap `alg` to an
   arbitrary/unsupported string, strip the signature — see if it validates.
Both are unauth-testable READ-ONLY checks (crafted token, observe accept/reject) — no destructive action
needed; still human-in-the-loop per our authed-testing doctrine since it targets the auth boundary itself.
Sources: https://www.codeant.ai/security-research/pac4j-jwt-authentication-bypass-public-key ,
https://pentesterlab.com/blog/cve-2026-23993-harbourjwt-unknown-alg-jwt-bypass

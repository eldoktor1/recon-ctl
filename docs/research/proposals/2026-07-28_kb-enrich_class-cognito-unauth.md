# PROPOSAL (proposal) for docs/knowledge/class-cognito-unauth.md — kb-enrich 2026-07-28
_Review and apply manually; not auto-merged into the KB._

## Self-writable privilege custom-attribute + authorizer signature-skip (added 2026-07-28, CVE-2026-6911/6912)

Real-world pattern from AWS Ops Wheel (July 2026), generalizes beyond that one app:

**Pattern 1 — privilege flag stored as a user-writable Cognito custom attribute.** If an app stores
role/tier/admin state in `custom:*` User Pool attributes and doesn't re-check it server-side, an
authenticated user can call Cognito's own `UpdateUserAttributes` (their own token, bypasses the app
entirely) to set `custom:role=admin` / `custom:is_admin=true` / `custom:tier=enterprise` etc. Look for
which custom attributes the JS SDK/Amplify config marks Mutable+self-writable; this is authed-only
(2-owned-account doctrine — human-in-the-loop) but a strong candidate on any Cognito+custom-claims app.

**Pattern 2 — API Gateway custom authorizer skips JWT signature verification.** Some Cognito-fronted
API Gateways validate claims (exp/aud/iss) but never actually verify the signature, letting an
UNAUTHENTICATED attacker forge a JWT with arbitrary claims (`alg:none`, or any signature bytes — the
authorizer never checks). Safe unauth probe: send a Cognito-shaped JWT with a mangled/garbage signature
(GET/HEAD/OPTIONS only) to an endpoint we've seen require a Cognito bearer token; a 200 instead of 401
is a strong CONFIRMED-candidate (cross-ref `class-jwt-attacks.md` for the general alg:none/sig-bypass
primitive — this is that bug specifically behind a Cognito authorizer).

Sources: AWS Security Bulletin 2026-018 (CVE-2026-6911 JWT-verification bypass, CVE-2026-6912
self-writable `custom:deployment_admin`), thehackerwire.com, Tenable.

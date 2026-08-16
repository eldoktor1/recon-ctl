# PROPOSAL (proposal) for docs/knowledge/class-cognito-unauth.md — kb-enrich 2026-08-15
_Review and apply manually; not auto-merged into the KB._

## Cognito USER POOL AuthFlow + attribute misconfig — a separate surface from Identity Pool (added 2026-08-15)
Everything above this section covers **Identity Pool** unauth credential issuance. This is a
distinct Cognito surface — **User Pool** authentication — worth checking whenever Amplify config
harvest (`aws-exports.js`/`amplifyconfiguration.json`, same sources as above) reveals a User Pool
Client ID, even if the Identity Pool unauth-issuance test comes back clean/FP.

### AuthFlow downgrade → plaintext credential stuffing/brute-force
User Pool app clients enable one or more auth flows (`USER_SRP_AUTH`, `USER_PASSWORD_AUTH`,
`ADMIN_NO_SRP_AUTH`, `CUSTOM_AUTH`). The SPA/mobile client is expected to use the SRP flow
(password never leaves the device in plaintext), but if the app client ALSO has
`USER_PASSWORD_AUTH` enabled (common — devs enable it for testing and never disable it) an
attacker can call `InitiateAuth` directly with `AuthFlow: USER_PASSWORD_AUTH` and a plaintext
`PASSWORD` param, bypassing whatever client-side SRP logic exists, and use it for credential
stuffing / password spraying against enumerated usernames.
- **Check (unauth, safe):** `aws cognito-idp initiate-auth --client-id <id> --auth-flow
  USER_PASSWORD_AUTH --auth-parameters USERNAME=<test>,PASSWORD=<test> --region <region>
  --no-sign-request` — a `NotAuthorizedException`/`UserNotFoundException` (vs
  `InvalidParameterException: ... USER_PASSWORD_AUTH is not enabled`) confirms the flow is live
  and safe to note as a LEAD (enumeration/brute-force surface); do NOT brute-force real credentials
  autonomously — same human-in-the-loop line as any authed testing.
- **CUSTOM_AUTH risk (LEAD only, needs source access to confirm):** a Lambda-backed custom
  challenge that accepts an empty/arbitrary response as "solved," or where `ChallengeName` is
  client-controlled and can be swapped to skip a step, is an auth-bypass — cannot confirm without
  seeing the Lambda logic; treat published `CUSTOM_AUTH` support as a note-worthy fingerprint only.

### Writable custom attribute → cross-tenant privilege escalation (own-account PoC, active-PoC doctrine)
Disclosed pattern: apps store tenant/merchant/role identity in a Cognito **custom attribute**
(`custom:m_id`, `custom:org_id`, `custom:role`, `custom:deployment_admin`) and trust it for
backend authorization, but never restrict who can WRITE it via `UpdateUserAttributes`.
**Test (own account only):**
1. `aws cognito-idp get-user --access-token <own-access-token>` — list your own attribute set.
2. `aws cognito-idp update-user-attributes --access-token <own-access-token> --user-attributes
   Name=custom:<attr>,Value=<own-2nd-account's-value>` — swap to a value from YOUR OWN second
   account, never a guessed/third-party tenant ID (same hard line as IDOR 2-account testing).
3. Re-authenticate; if the backend now treats you as the other tenant/role, the attribute is
   trusted without server-side revalidation → privilege-escalation finding.
- **Root cause to cite in the report:** no pre-token-generation Lambda trigger (or equivalent
  server-side check) re-derives the authoritative tenant/role from a source the user can't write —
  the app relies on the Cognito attribute as if it were server-controlled.
- Only escalate beyond your own two accounts if `update-user-attributes` on the field succeeds
  AND the target value is your own second account — same discipline as every other IDOR test here.

⚠️ CVE-2026-6911/6912 (Cognito attribute privesc / JWT-signature-skip) appear only in a
third-party-product context ("AWS Ops Wheel"), not an AWS-service CVE — NVD/vendor-verify before
citing in any report, standard KB caveat for LLM-surfaced CVE IDs.

Sources: https://medium.com/@melodicbook/exploiting-security-misconfigurations-in-aws-cognito-authflow-types-bc693260b8b8 , https://www.securitum.com/aws_cognito_misconfiguration_to_full_account_takeover.html

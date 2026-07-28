# PROPOSAL (proposal) for docs/knowledge/class-cognito-unauth.md — kb-enrich 2026-07-28
_Review and apply manually; not auto-merged into the KB._

## Authenticated attribute-rewrite → account/org takeover (2026-07-28)

Distinct from the unauth-creds-harvest lane (bucket/JS→sourcemap→Amplify→pool→unauth
creds). This is an AUTHED technique for when we have an owned low-priv account on a
Cognito-backed target:

- Root cause pattern: app uses the Cognito `email` attribute (or a custom writable
  attribute like `custom:userId`) as the authoritative identity/authz claim instead of
  the immutable `sub`, AND the attribute is writable via
  `update-user-attributes`/`AdminUpdateUserAttributes` without forcing re-verification
  before the new value becomes authoritative.
- Test (own account only): `aws cognito-idp update-user-attributes --access-token <own
  token> --user-attributes Name=email,Value=<any address, e.g. an org domain you're
  probing>` — if the platform grants access/portal scoping off the new unverified email
  immediately, that's account/org takeover.
- Related variant: `ForceAliasCreation=true` + registering a new user with the SAME
  `custom:userId` as an existing user can silently reassign that ID to the new
  registrant, displacing the original owner's identity binding.
- Still gated by our doctrine: requires an OWNED test account, no third-party ID
  guessing, minimal PoC (verify the attribute write succeeds and observe the authz
  effect, don't pivot further).

Source: https://medium.com/@a-shams/how-an-aws-cognito-misconfiguration-led-to-full-organization-account-compromise-5c9f6983e1a4

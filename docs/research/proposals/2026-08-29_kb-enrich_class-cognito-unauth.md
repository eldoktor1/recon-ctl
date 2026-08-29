# PROPOSAL (proposal) for docs/knowledge/class-cognito-unauth.md — kb-enrich 2026-08-29
_Review and apply manually; not auto-merged into the KB._

## Adjacent attack surface: authenticated Cognito USER POOL bugs (not Identity Pool creds)

The primitives above are unauth Identity Pool credential issuance. Two more Cognito bugs live in the
same config/JS surface we already mine, but require an OWNED account (ACTIVE-PoC doctrine — own account
only, minimal, prove-then-stop):

### Custom-attribute mass-assignment / privesc
Cognito **custom attributes** (`custom:role`, `custom:tier`, `custom:org_id`, `custom:permissions`, …)
default to **write-enabled** for the owning user unless the developer explicitly restricts them to
read-only in the App Client's "Attribute read and write permissions". If the app trusts a custom
attribute for authz decisions (role/tier/org gating) server-side, this is a direct privesc:
1. `GetUser` / decode your own ID token to see which custom attrs exist and their current value.
2. `aws cognito-idp update-user-attributes --access-token <YOUR-OWN-TOKEN> --user-attributes Name="custom:role",Value="admin"`
   (or whatever attribute drives authz — `custom:tier=enterprise`, `custom:org_id=<privileged-org>`).
3. Re-auth / re-fetch a token that reflects the new claim (some apps re-issue on next login; others
   trust the live `GetUser` call) and observe whether backend authz actually changed.
Own-account only; never write another user's attributes. FP check: many apps validate custom attrs
server-side against a separate authoritative table (Cognito is just profile storage) — the client-side
write succeeding is NOT the finding, a privilege change the BACKEND honors is. Confirm impact, don't
stop at the write. Source: secforce.com "AWS Cognito pitfalls: Default settings attackers love".

### Account-enumeration protection gap: SignUp bypasses `prevent_user_existence_errors`
`prevent_user_existence_errors` (the standard Cognito hardening flag) normalizes error responses on
`InitiateAuth`/login flows only. It does **not** cover `SignUp` — registering with an already-registered
email still returns a distinguishing `UsernameExistsException` even on a "hardened" pool. Safe, unauth,
single unauthenticated `SignUp` call against a known-format email is enough to confirm/deny account
existence — useful for credential-stuffing target lists or confirming an org's user roster is enumerable
even when the login flow looks locked down. LEAD-grade (info-disclosure-class, low severity alone) —
pair with a concrete downstream impact (e.g. feeds a targeted password-spray) before minting. Source:
hackingthe.cloud "Bypass Cognito Account Enumeration Controls".

### AdminInitiateAuth flow note
`ADMIN_NO_SRP_AUTH` is deprecated in favor of `ADMIN_USER_PASSWORD_AUTH` (same risk profile — password
sent in the clear over TLS to Cognito, no SRP). Compromised-credential checking (`AdvancedSecurityMode`)
only applies to `ADMIN_USER_PASSWORD_AUTH`/`USER_PASSWORD_AUTH` flows — a pool still on `USER_SRP_AUTH`
only gets that protection if the client library implements it. Not independently exploitable; a hardening
signal to note when scoping an authed Cognito engagement. Source: AWS docs (AdminInitiateAuth API ref,
compromised-credentials detection guide).

# PROPOSAL (proposal) for docs/knowledge/class-cognito-unauth.md — kb-enrich 2026-07-28
_Review and apply manually; not auto-merged into the KB._

## Beyond the guest role — authenticated-path escalation (added 2026-07-28)

The existing SAFE test only covers the **unauthenticated guest role**. When a User Pool has open self-signup, a second, often more permissive path exists: register your own account (authorized own-account setup, active-PoC doctrine), obtain an authenticated identity-pool role, and enumerate what it reaches.

**Recon/test sequence (own account only):**

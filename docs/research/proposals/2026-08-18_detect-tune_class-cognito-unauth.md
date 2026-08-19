# PROPOSAL (proposal) for docs/knowledge/class-cognito-unauth.md — detect-tune 2026-08-18
_Review and apply manually; not auto-merged into the KB._

## Second unauth-credential pattern: AWS Amplify dangling trust-policy Condition (added 2026-08-18)
Distinct from the legacy-MobileHub win already documented: when an Amplify project's
Authentication category is REMOVED, the generated IAM role's trust policy can retain
`"Effect":"Allow"` for `sts:AssumeRoleWithWebIdentity` while losing the `Condition` block that
scoped it to the specific Cognito identity pool `aud`. Result: the role is assumable by ANY
caller presenting a web-identity token from ANY provider, not just the original pool — a second,
independent route to unauthenticated AWS credential issuance beyond the classic
allow-unauth-identities misconfig.
**Detect:** on a Cognito-fronted host, after pulling the identity pool ID (per the existing
bucket/JS→sourcemap→Amplify→pool chain), check whether the linked IAM role's trust policy has
`Allow`+`AssumeRoleWithWebIdentity` with NO matching `Condition`/`StringEquals` on `aud` — this is
visible via the same unauth `GetId`/`GetCredentialsForIdentity` calls already in our chain: if
credentials come back for a role that doesn't restrict to our pool alone, note the wider blast
radius in the report.
Sources: https://www.mallory.ai/stories/019e59ea-36a4-79e9-9431-fa3fc572a19d, https://securitylabs.datadoghq.com/articles/amplified-exposure-how-aws-flaws-made-amplify-iam-roles-vulnerable-to-takeover/

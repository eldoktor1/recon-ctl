# PROPOSAL (proposal) for docs/knowledge/class-cognito-unauth.md — kb-enrich 2026-08-29
_Review and apply manually; not auto-merged into the KB._

## Sub-lane: Amplify legacy trust-policy takeover (added 2026-08-29, CVE-2024-28056 — verify before citing)

A DIFFERENT bug from the "unauth guest role over-permissioned" primitive above: pre-fix Amplify CLI
(projects scaffolded **July 2018–Aug 2019**) generated `authRole`/`unauthRole` IAM trust policies
**missing the Cognito identity-pool audience (`cognito-identity.amazonaws.com:aud`) condition**. Without
that condition, `AssumeRoleWithWebIdentity` via Cognito Basic authflow + STS assumes the role without
being scoped to the specific identity pool that issued the token — and the over-permissioned role often
survives as a dormant credential path even after the project later REMOVED its Cognito auth entirely
(the trust policy is orphaned but still assumable).

**Why this matters for us:** it's a distinct provenance signal from "is guest access enabled" — check
it on any Cognito pool we already have from JS/sourcemap harvesting, especially ones whose build
metadata / JS bundle looks old (2018-2019 vintage Amplify config, or an app where auth-related UI has
since been removed but the pool ID/config still ships in the bundle).

**Detection (passive, safe):**
1. From the harvested pool config, extract the linked `authRole`/`unauthRole` ARNs (visible via
   `aws cognito-identity describe-identity-pool` unauth, or in `aws-exports.js`/`amplifyconfiguration.json`).
2. Check the trust policy is even readable unauth (usually isn't) — otherwise the tell is behavioral:
   run our existing unauth flow (`get-id` → `get-credentials-for-identity`, no `--logins`) and if it
   issues creds for a role whose naming/vintage matches this pattern, note it as a candidate for the
   missing-audience-condition variant vs. the standard over-permissioned-guest-role variant.
3. **AWS patched the tooling Jan–Apr 2024 for NEW deployments only** — this does not retroactively fix
   already-scaffolded dormant roles. A hit is only actionable on legacy-looking targets.

Same REAL-vs-FP + severity + program-scope-carve-out rules as the rest of this doc apply unchanged
(Amazon-parent-AWS dead-zone caveat especially — this is still "found creds, pivoted via AWS," the
exact Amazon VRP invalid-example pattern).

Source: mallory.ai/stories/019e59ea-36a4-79e9-9431-fa3fc572a19d (references CVE-2024-28056 — NVD-verify
before citing in any report; this is a 2024-vintage issue relevant only to legacy/dormant configs, not
a fresh finding class).

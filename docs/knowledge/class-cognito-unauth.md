# class: unauthenticated AWS Cognito Identity Pool credential issuance

**The money primitive (H1 #3800848, Logitech, Critical):** an AWS Cognito **Identity Pool** configured
to allow unauthenticated ("guest") access hands **valid temporary AWS credentials** to anyone who knows
the pool ID. Pool IDs are public by necessity (hardcoded in web/mobile clients) — *the pool ID leaking is
NOT the bug*; the **unauth role having real permissions** is the bug (same logic as Firebase rules).

## Where pool IDs live (harvest sources)
- **Open S3 build/asset buckets** → mobile-app **source maps** (`.jsbundle.map`, `index.android.bundle.map`)
  or `aws-exports.js` / `amplifyconfiguration.json` embedding the Amplify config. (Logitech: `builds.myharmony.com`
  → open bucket `dhg-app-builds` → iOS source map → 9 pool IDs.)
- **In-scope host's own JS** (no bucket needed) — Amplify config in the SPA bundle / `sourceMappingURL`
  reconstructed with sourcemapper. (Dropbox: `learn-stage.dropbox.com` JS → pool.)
- **Predictable config paths:** `/aws-exports.js`, `/amplifyconfiguration.json` (+ `/assets/`, `/static/`, `/config/`).
- **Mobile apps (APK/IPA)** — where legacy AWS **MobileHub** pools live (the permissive ones). Extract with
  apktool/jadx/unzip + grep for `[a-z]{2}-[a-z]+-\d:UUID`.

## The SAFE test (reference: hackingthe.cloud, Yassine Aboukir NahamCon)
Unauth path = the two calls WITHOUT `--logins`, unsigned (we hold no creds):
```
aws cognito-identity get-id --identity-pool-id <region:uuid> --region <region> --no-sign-request
aws cognito-identity get-credentials-for-identity --identity-id <id> --region <region> --no-sign-request
aws sts get-caller-identity            # with the returned ASIA... creds → the assumed-role ARN
```
`ASIA...` creds returned = **CONFIRMED issuance**. These calls hit AWS, not the target → not target
traffic (but keep VPN-gated, fail-closed). Tooling: `engine/recon_cognito_test.py` (boto3 UNSIGNED),
`scripts/recon_cognito.sh`. Blast-radius = safe `list_/describe_` enumeration ONLY (no object/item DATA
reads, no writes); Pacu `cognito__attack` / enumerate-iam for the operator-authorized deeper pass.

## THE REAL-vs-FP RULE (most pools are FP — do not overclaim)
Issuance alone is NOT a finding. **Only `issued` + the unauth role actually REACHES a resource**
(list_buckets/list_tables/list_functions/appsync/etc succeeds) = reportable. Severity scales with what
the role can do (Logitech prod pools → Critical). FP classes (score N/A, note + move on):
- **CloudWatch RUM** roles `cw-rum-unauthenticated-role` / `RUM-Monitor-*-Unauth` — by-design public,
  scoped to `rum:PutRumEvents` only. **The #1 FP** (any site using CW RUM). Never a finding.
- **`issued` but 0 permissions** = deliberately locked-down public guest role (e.g. Dropbox
  `Cognito_warning_public_browsersUnauth_Role`). Not a finding.
- **`denied` / `InvalidIdentityPoolConfiguration`** = secure (unauth disabled / no role). Not a finding.
- **Dead backend** — creds issue but the AppSync/API the role targets is deleted (NXDOMAIN) → no impact.
- **Modern Amplify pools scope the unauth role tightly.** Logitech's win was a **legacy 2017 AWS MobileHub**
  artifact (`*_unauth_MOBILEHUB_*` roles granted broad S3/DynamoDB/Lambda by default). Hunt old apps.

## Severity / reporting
Honest framing: "unauthenticated AWS credential issuance" is the primitive; state the assumed-role ARN +
account, and what the role reaches (proven by safe list/describe). Do NOT read/harvest third-party data
(hard line) or enumerate blast radius beyond list/describe. Logitech reported Medium (issuance only) and it
triaged Critical once the reviewer checked the prod-role policies. Only test pools whose provenance host is
in-scope + PAYING (per-asset). Never test a pool found on a third-party/non-scope host.

## PROGRAM-SCOPE CAVEAT — check the program BEFORE testing/reporting (Amazon = dead zone, 2026-07-12)
A REAL, confirmed unauth issuance can still be **unreportable/unpayable** because of the *program's* rules,
not the finding's merit. **Amazon proved this** — a genuine `com.amazon.relay` finding (pool
`us-east-1:56106a99-...`, role `RelayMobile_Unauth_Users_prod_NA`, `sqs:ListQueues` reachable) is a dead
zone on BOTH venues:
- **Amazon VRP** (the app is in scope) explicitly carves out "AWS and AWS customer assets" as *always out
  of scope* — "Discovering and testing against AWS and AWS customer assets is strictly out of scope for VRP
  and against the AWS AUP." And their Rules of Engagement list our exact chain as an **Invalid Example:
  "Finding disclosed credentials and using them to pivot."** Also: "do not attempt to reproduce the finding
  again unless requested" (so you can't even re-run for screenshots).
- **AWS VDP** only covers vulnerabilities in AWS *services*, NOT customer misconfigurations ("Non-default
  configuration ... using valid credentials that were correctly authorized" is excluded) — a customer's
  unauth-enabled pool is a config choice, not an AWS service flaw. Plus "you may only interact with accounts
  you own," and there's **no bounty**.
- Net: the impact (the AWS pivot) is exactly what Amazon forbids, and the config is exactly what AWS VDP
  excludes → no valid venue. The Logitech win transferred because Logitech OWNED its config and had no AWS
  carve-out; Amazon (AWS's parent) routes this class into a gap.
**Rule going forward:** before minting/reporting a Cognito finding, confirm the *program* accepts AWS-backed
findings. If the pool's AWS account is the program-owner's own AWS customer account AND the program has an
AWS/customer-asset carve-out (Amazon does), it's unreportable — note + drop, do not run the pivot. Sources:
hackerone.com/amazonvrp policy (Rules of Engagement); aws.amazon.com/security/vulnerability-reporting/.

Sources: hackingthe.cloud/aws/exploitation/cognito_identity_pool_excessive_privileges; Yassine Aboukir
"Hunting for AWS Cognito Security Misconfigurations" (NahamCon EU 2022); HackTricks Cloud cognito-identity-pools.
Lane memory: project_cognito_unauth_lane.

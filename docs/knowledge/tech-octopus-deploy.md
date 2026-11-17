# tech: Octopus Deploy (Octopus Server + Tentacle, self-hosted) — zero-day hunting notes

Program: Bugcrowd `octopus-deploy` — "standalone on premise products: Octopus Server & Octopus Tentacle".
$200–$6,000 per vuln (Bugcrowd VRT; P1 $6k). Full safe harbor. **Disclosure not allowed.** Scope rating 1/4,
running since 2021-03. Shares code with Octopus Cloud ⇒ a bug in shared code is a dup of itself across the
two programs (file once). Sibling program `octopus-og` = *.octopus.com web assets (needs @bugcrowdninja.com).
Written 2026-10-22 (discovery research; no testing yet).

## Why it is a zero-day target
- Closed-source .NET, but **every DLL decompiles cleanly** (ILSpy / dnSpy / dotPeek). `/Octopus/Octopus.Server.dll`
  and siblings inside the container ⇒ effectively full source. The crowd that runs scanners never does this.
- **Every advisory gets a CVE** (advisories.octopus.com, SA-YYYY-NN). 73 Octopus Server advisories to date.
- **All 13 advisories of 2026 were found by Octopus's own security engineer (Nathan Willoughby) in internal
  testing** — no external researcher has published a 2026 find. External reporters were active in 2022 (15 CVEs,
  pentest-shaped). ⇒ The program is paying and the surface is live, but the external crowd is thin.
- Free license: with `OCTOPUS_SERVER_BASE64_LICENSE` empty the server self-issues a **free tier license
  (no time limit; 10 projects / 10 tenants / 10 machines / 10 users)**. 30-day Enterprise trial also exists.

## Self-host (Linux container, Docker Desktop on Windows → Linux containers)
Official compose (docs: installation/octopus-server-linux-container/docker-compose-linux): `db` = SQL Server
image (`mcr.microsoft.com/mssql/server:2022-latest`, `SA_PASSWORD`, `ACCEPT_EULA=Y`, port 1401:1433, volume
`/var/opt/mssql`) + `octopus-server` = `octopusdeploy/octopusdeploy:<tag>` with env `ACCEPT_EULA=Y`,
`DB_CONNECTION_STRING="Server=db,1433;Database=OctopusDeploy;User=sa;Password=<SA_PASSWORD>"`,
`ADMIN_USERNAME/ADMIN_PASSWORD/ADMIN_EMAIL`, `MASTER_KEY=$(openssl rand 16 | base64)`, optional
`ADMIN_API_KEY`, `DISABLE_DIND=Y`, `TASK_CAP=5`; ports 8080 (API+portal), 10943 (polling tentacles), 8443 (gRPC);
volumes `/repository /artifacts /taskLogs /cache /import /eventExports`. `docker compose --project-name octopus up -d`
→ http://localhost:8080. Pin the tag to the **latest public release** (2026.3.158xx at time of writing) — the
bounty needs latest; diff against the next release before filing (shared-code dups).
Built-in worker on the server is self-hosted-only (Script Console can target the server itself).

## Architecture map (from docs + public repos)
- **REST API** = everything the portal does. Space-scoped routes `/api/{spaceId}/...` (projects, releases,
  deployments, runbooks, runbookRuns, packages/raw, variables, feeds, machines, workers, workerpools, tasks,
  tenants, certificates, accounts, artifacts, channels, lifecycles, projectgroups, steptemplates, tagsets,
  users, teams, userroles, scopedUserRoles, spaces, events, reports, bulk operations). System routes `/api/...`.
  Swagger: `/swaggerui/`. **`/llms.txt` = unauthenticated Markdown API summary** (great offline oracle;
  older `/api/experimental/llms.txt` redirects). Auth: `X-Octopus-ApiKey: API-...` header, bearer (OIDC,
  short-lived), or the portal session cookie (`OctopusIdentificationToken`, CSRF cookie `Octopus-Csrf-Token`).
- **Public repos** (github.com/OctopusDeploy): Halibut (C#, JSON-RPC over TLS, server↔tentacle transport;
  had a deser RCE pre-4.4.7), OctopusTentacle (C# agent), Calamari (C#, the deployment tooling run ON targets
  — step execution, package extraction, variable substitution), Octostache (variable `#{...}` substitution
  DSL), Octodiff (delta packages), OctopusClients (.NET client = full resource model, every DTO shape),
  api-client.ts, go-octopusdeploy, cli (Go), step-packages, mcp-server, Library (community step templates).
  **Octopus.Server itself is NOT open** → decompile.
- **Permission model** (two levels): *system* (AdministerSystem, UserInvite, TeamEdit, User*, Space*…) and
  *space* (ProjectView/Edit, DeploymentCreate, EnvironmentEdit, TaskCreate/Cancel, VariableEdit, FeedEdit,
  MachineEdit, TenantView/Edit, Script?…). Roles are assigned to teams; a role assignment can be **scoped to
  projects / environments (/ tenants / project groups)**. 22 built-in roles (Project Viewer/Contributor/Lead/
  Deployer/Initiator, Deployment Creator, Release Creator, Environment Manager/Viewer, Runbook Consumer/
  Producer, Package Publisher, Build Server, Certificate Manager, Tenant Manager, Feature Toggle Editor,
  Insights Report Manager, Space Manager/Viewer, System Administrator/Manager, Read Only).
  **Multiple scoped assignments are COMBINED by the server — this evaluation is exactly where SA2026-12
  (CVE-2026-102488, 8.7), SA2026-13 (7.1), SA2026-08 (7.2), 2020-12286 and 2024-2975 lived.**
  `Configuration → Test Permissions` shows the effective matrix (use it as the ORACLE for 2-account tests).
- **Spaces** = tenancy boundary inside one server (2022-2508 verbose errors leaked cross-space resources;
  2024-4811 failed imports readable across spaces; 2022-1881 project export IDOR).
- **Script Console** (Tasks): runs ad-hoc scripts on targets/workers/the server; needs AdministerSystem or
  TaskCreate (+MachineEdit for targets). 2022-2013: feature flag handed it to new users. Every "run a script"
  surface (runbooks, script steps, step templates, console, health-check scripts, Kubernetes agent) is a
  **privilege-boundary** ⇒ the 2026-08/13 class.
- **Feeds**: built-in repo + external (NuGet, Docker, Maven, NPM, Python, S3, GCS, Helm, ECR, OCI, GitHub).
  Server downloads/extracts packages (`/repository`, `/cache`). **SA2026-09: path traversal via a non-built-in
  feed → arbitrary file overwrite → RCE** (FeedEdit privilege). Package names/versions/paths from a feed the
  user controls = server-side file I/O driven by attacker data. Also "offline package creation" command
  injection (2022-4009), zip-bomb (2022-4008).
- **Variables & secrets**: sensitive variables AES-encrypted with the master key, "never retrievable" via
  API/UI, masked in logs (>3 chars only, substring masking fails: 2022-2720). Repeated leak surfaces:
  **deployment variable snapshot JSON (SA2026-07, 7.1)**, task logs (2024-6972, 2024-12226), variable
  preview (2023-2247), audit log API key (2024-02), OIDC secret logged (2023-1904). Snapshot/preview/export/
  audit endpoints are where secrets escape the "never retrievable" promise.
- **Deserialization**: project/environment objects carry JSON blobs; **SA2026-10 (CVE-2026-101169, 8.7): a
  user who can edit an Environment or Project sets crafted JSON → arbitrary code in the server process.**
  2018-18850 was YAML in process edits. Look for `TypeNameHandling`, polymorphic JSON converters, `$type`.
- **Unicode equivalence** (SA2026-11, 8.7): role management compared names/ids with Unicode-equivalent forms
  → weaken built-in roles / add self to privileged team. Any string that gates a *protected* object (built-in
  role names, team names, "Everyone", system space, reserved usernames) is a normalization target.
- **Auth/identity**: AD/LDAP/OIDC/GitHub/Azure AD providers (2020-10678 AD privesc, 2025-0589 AD data readable
  unauth via API, 2022-3614 AD sign-in redirect), API keys outliving disabled external users (2022-2572,
  9.8), access token → long-lived API key (SA2026-02), session cookie reuse as CSRF token (2022-2783),
  sessions never expiring (2022-2782), invitation codes over-usable (2022-1670).
- **SQLi still happens**: 2024-9194 SQLi in the REST API (8.7), 2021-31818 Events API. Hunt the filter/sort/
  search query params of list endpoints (`/api/events`, `/api/{space}/tasks?...`, `partialName`, `orderBy`).
- **SSRF**: 2025-0539 (Windows auth material leaked via coerced server requests), 2022-2416 blind SSRF, Git
  connectivity test → SMB/NTLM relay (2022-2780). Every "test connection" (feeds, git repos, accounts,
  webhooks/subscriptions, Slack/Teams/Jira/ServiceNow integrations) is SSRF surface.
- **Config-as-Code**: project process/runbooks/settings/non-sensitive variables stored as OCL (HCL-like) in
  a Git repo the server clones and parses; branches user-chosen; templates from repo content. Untrusted repo
  content parsed server-side = a fresh surface (newer feature, fewer eyes).
- **Stored XSS** still pays Medium: artifacts (SA2026-05), audit page (2024-4456), help sidebar (2022-29890).

## Hunt thesis (chains the program has proven it pays for)
1. **Scoped-permission evaluation** (the 2026 money class): build teams with overlapping scoped roles
   (env A only + project B only, tenant-scoped, Runbook Producer vs Deployer) and prove an action lands in an
   environment/project the union should not allow. Oracle = Test Permissions page; proof = the task executes.
2. **Edit-permission → server code exec**: everything a Project Contributor can write that the server later
   deserializes/parses/extracts: project/environment JSON, OCL on a branch, step-template bodies, feed
   package paths, Octostache expressions, health-check scripts, Kubernetes manifests, import bundles.
3. **"Never retrievable" secrets**: snapshot/preview/export/audit/event/report endpoints with a Project
   Viewer that can read a sensitive variable value or an API key.
4. **Cross-space**: any `/api/{spaceId}/` resource reachable with the OTHER space's id/permissions; IDOR on
   exports, imports, tasks, artifacts, events, reports.
5. **Identity**: external-provider users disabled/removed but keys/sessions/invites alive; Unicode/case
   normalization on usernames/teams/roles.
6. **Tentacle/Halibut**: certificate-trust pinning, polling-tentacle registration, websocket trust (2020),
   deser (Halibut <4.4.7). Needs a Tentacle VM.

## Sources
advisories.octopus.com (pages 1-4; SA2026-09/10/11/12/13 detail pages), NVD keyword "Octopus Server",
octopus.com/docs (api, api/authentication, installation/octopus-server-linux-container{,/docker-compose-linux},
security/users-and-teams/{default-permissions,user-roles,system-and-space-permissions},
administration/managing-infrastructure/script-console, projects/variables/sensitive-variables,
projects/version-control, packaging-applications/package-repositories), github.com/OctopusDeploy,
bugcrowd.com/octopus-deploy (public card: $200–$6,000, no disclosure), cybersecuritynews/gbhackers on
CVE-2026-101169.


## Advisory wave SA2026-15..24 (published 2026-10-27..11-12; recorded 2026-11-14)
All internal finds (Willoughby, Rossow); all fixed in 2026.3 builds <= 15936 and 2026.2 <= 13526. Latest at time of writing 2026.3.16138.
| SA | CVE | class | fixed (2026.3) |
|---|---|---|---|
| 15 | CVE-2026-116870 | OIDC issuer confusion: illegitimate issuer accepted for a service-account OIDC identity | 15816 |
| 16 | CVE-2026-117341 | invitation code written to audit event log (space users could read + redeem) | 15829 |
| 17 | CVE-2026-117466 | System Manager -> System Administrator | 15863 |
| 18 | CVE-2026-118426 | LDAP user/group search callable by any authenticated user | 15909 |
| 19 | CVE-2026-96414 | auth cookie integrity + user/audit view permission flaw -> admin (Critical with guest) | 15875 |
| 20 | CVE-2026-93487 | project-trigger create permission validation -> run runbooks/deploys | 15863 |
| 21 | CVE-2026-105948 | self-service LDAP login editing -> team membership via LDAP groups -> admin | 15909 |
| 22 | CVE-2026-116835 | custom OIDC claims on OIDC accounts -> signed tokens impersonating another project | 15894 |
| 23 | CVE-2026-124627 | LDAP identity injection during invitation redemption | 15926 |
| 24 | CVE-2026-124628 | disabled LDAP self-service identity editing bypassed | 15936 |
Reading: identity/RBAC (users, teams, invitations, OIDC, LDAP) is the active internal hunting ground. Mechanics learned from source
(2026.3.15996): `IsSelfServiceIdentityEditingEnabled` defaults TRUE (`AuthenticationConfiguration`, setting `selfServiceLoginEditingEnabled`,
Issues #4306, 2018); `CannotModifyOwnIdentitiesIfSelfServiceIsDisabled` only vetoes an identity edit that escalates team membership NOW;
`UserStore.GetByIdentity` PARTIAL-matches any claim value under the same provider name and falls back to `[ExternalId]=@x OR [Username]=@x`;
OIDC `UserService.GetOrCreateUser` throws on >1 match; external groups are fetched from the STORED identity claim by LDAP (`Claims["uan"]`)
and Active Directory (`Claims["sam"]`) `GroupRetriever`s (`UserGroupCollator`, scheduled SynchronizeExternalSecurityGroups task).
Open variant: the same planting against OIDC-family providers (Azure AD/Okta/GoogleApps/GenericOidc) is not named in any advisory.

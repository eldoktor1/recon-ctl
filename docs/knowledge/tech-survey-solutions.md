# tech: World Bank Survey Solutions (Headquarters / HQ)

Open-source (github.com/surveysolutions/surveysolutions) .NET Core survey data-collection
platform by the World Bank. Server = **Headquarters (HQ)** web app (Kestrel/ASP.NET). Fielded
by universities/statistics offices for CAPI (Interviewer app) + CAWI (WebInterview) data collection.
**Because it's open-source + fully documented + ships an exposed Swagger, it's a research-driven
BFLA/IDOR target — read the source/spec, don't guess.** First seen: UGent `srvdenbalo.ugent.be` (2026-07-03).

## Fingerprints (how to detect in ES / on a host)
- `Server: Kestrel`, `X-Powered-By: ASP.NET`, login at `/Account/LogOn?ReturnUrl=`.
- JS refs: `/api/v1/questionnaires/`, `/WebInterview/`, `/WebInterviewSetup/`, `/Download/Supervisor`,
  `support.mysurvey.solutions`, `/ApiTokens`, `/UsersManagement`, Vue + recaptcha, `/locale/hq/<lang>.<hash>.js`.
- **Version leak (unauth): `GET /.version`** → e.g. `26.04 (build 39432)`.
- **Swagger exposed (unauth): `/apidocs/index.html` + spec `/swagger/v1/swagger.json`** (~55 ops).
- Multi-tenant **workspaces**: default `/primary/`; `/Error/401?...reason=WorkspaceDisabledReason`; reserved
  workspace names include `graphql`, `api`, `apidocs`. `GET /api/v1/workspaces/status/{name}` probes existence.

## Auth model (READ THIS before testing)
- REST API auth = **HTTP Basic OR Bearer** (`securitySchemes: basic, bearer`). API calls need an **"API user"** role.
- Roles: **Administrator** (all workspaces, all funcs) > **Headquarters** > **Supervisor** (owns interviewers) >
  **Interviewer** (single workspace) ; plus **API user** and **Observer** (read-only). HQ/Observer may be multi-workspace;
  Interviewer/Supervisor are **single-workspace**.
- Accounts are **admin-provisioned** (no public self-register on HQ). CAWI **WebInterview** respondents are UNAUTH via
  assignment/invitation links (`/WebInterview/{invitationId}/Start`, `/Resume/{interviewId}`, `/Link/{id}/{interviewId}`).

## Money surface (qualifying classes: IDOR/BOLA, BFLA, H/V privesc, business logic, data export)
The whole platform is object-ref heavy → BOLA/BFLA is THE lane. Test with 2 owned accounts / owned IDs only.
- **Cross-workspace isolation** — the #1 concern. A Supervisor/Interviewer/API-user scoped to workspace A trying
  to read/mutate workspace B's objects (interview/{id}, export, assignment). `/api/v1/workspaces/{name}` GET/PATCH/DELETE
  + `/disable`/`/enable` + `POST /workspaces` = **workspace-mgmt BFLA** (should be Admin-only — test lower roles).
- **`GET /api/v2/export/{id}/file`** (+ POST /api/v2/export, GET /api/v2/export/{id}) → **bulk survey-data export
  download by id** = highest-impact respondent-PII IDOR if id guessable or cross-workspace.
- **`GET/DELETE /api/v1/interviews/{id}`** (+ `/approve` `/hqapprove` `/hqreject` `/reject` `/assign` `/assignsupervisor`
  `/comment/{questionId}` `/pdf` `/stats` `/history`) → respondent-data IDOR + workflow BFLA (can a non-HQ role hqapprove?).
- **`GET /api/v1/users/{id}`, `POST /api/v1/users`, `PATCH /users/{id}/archive|unarchive`** → user-mgmt BFLA / privesc
  (low-priv creating/archiving users). HQ UI equivalents: `/ChangePassword/{userId}`, `/ResetAuthenticator/{userId}`,
  `/ResetRecoveryCodes/{userId}` → account-takeover BFLA if authz missing on {userId}.
- **`/api/v1/assignments/{id}`** (+ `/assign` `/changeQuantity` `/close` `/changeTargetArea` `/recordAudio`) → assignment BFLA.
- **`/api/v1/supervisors/{id}`, `/supervisors/{supervisorId}/interviewers`** → org-structure IDOR.
- **WebInterview invitation IDOR (UNAUTH)** — check `invitationId` entropy: short/sequential code ⇒ enumerate = access
  strangers' interviews (HARD LINE: prove the access-control gap with YOUR OWN 2 invitations, never harvest third-party data).
- GraphQL: exists (reserved name; used for maps/advanced). Not at `/graphql` root on 26.04 (404) — probe per-workspace/POST.
  NOTE: on programs where "GraphQL introspection enabled" is explicitly NON-qualifying (e.g. UGent), only a real
  IDOR/mutation/authz bug via GraphQL pays — introspection alone is worthless.

## Testing notes / anti-FP
- Version leak + exposed Swagger ALONE = info-disclosure = usually NON-qualifying (need real authz PoC).
- v-current (patches fast: 26.04 = Apr 2026) → n-day CVE unlikely; focus LOGIC/authz, not version CVEs.
- Basic-auth API → brute/cred-stuffing is out (rate-limit non-qualifying + not our game). Need legit account.
- Data-handling: on export/interview IDOR, demonstrate the authz gap minimally, REDACT PII, do not copy datasets.

## Sources
- github.com/surveysolutions/surveysolutions (source — read authz attributes on controllers)
- docs.mysurvey.solutions/headquarters/ (API + accounts/workspaces) ; demo.mysurvey.solutions (study the app safely, NOT a target)
- Live spec (target): `<host>/swagger/v1/swagger.json`, `<host>/.version`

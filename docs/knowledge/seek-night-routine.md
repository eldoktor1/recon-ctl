# SEEK — NIGHT ROUTINE (standing, operator-locked 2026-08-19)

**Commitment: work SEEK every night for 1–2 months.** This is a long campaign, not a session.
Nothing here is optional and nothing here is a "quick check" — see the NO SURFACE CHECKS and
DEPTH DOCTRINE sections of `process-stride-wstg.md`.

Workspace key: `seek`. Artifact: regenerate with `python3 tools/walk_report.py seek <out.html>`.
Credentials + object ids: `~/recon/state/private_programs/seek/creds.md` (local only, chmod 600).

---

## EVERY NIGHT, IN THIS ORDER

### 1. Orient (5 min, no traffic)
```bash
python3 tools/coverage_audit.py seek        # numbers first, always
```
Read `~/recon/state/hunt_cursor.md` and the workspace notes for `NEXT:`. Report coverage numbers
before anything else. If WSTG resolved has not moved in two consecutive nights, say so plainly and
change approach.

### 2. Preconditions
- Burp Pro up (`:8080` proxy + `:9876` MCP), dedicated SEEK project.
- Dev Brave on `:9222` via `scripts/launch_brave_debug.ps1`, proxied through Burp.
- Mullvad up, no `state/vpn_down`.
- **The daemon must never scan SEEK** — `scope/scan_deny.txt` contains `SEEK`; verify with
  `python3 tools/coverage_audit.py seek` and spot-check that `triage_scan_deny` is still true.

### 3. Walk the next WSTG category IN ORDER
Categories: INFO → CONF → IDNT → ATHN → ATHZ → SESS → INPV → ERRH → CRYP → BUSL → CLNT → APIT.
Per test: read the KB doc → pin the exact in-scope surface → execute → record a step card →
mark `done | finding | na | manual`. A clean pass is worked-knowledge; record WHY it was cleared
and WHAT it does not rule out.

**Do not chase leads mid-walk.** Record them as follow-ups and keep walking.

### 4. Record, then regenerate
Every outcome goes into the workspace as a note. Then regenerate the artifact and publish it to the
SAME URL. Never hand-write counts.

### 5. Ping Discord ONLY for something real
`discord_post "$(cat ~/recon/state/discord/review)" '<json>'` — a CONFIRMED, in-scope, non-excluded
finding with a reproducible primitive. Nothing else. No progress pings, no "interesting" leads.

---

## STANDING CONSTRAINTS (violating any of these invalidates the work)
- **NO automated tooling against SEEK assets.** The brief bans it outright. Manual/browser only.
  No nuclei, dalfox, sqlmap, kiterunner, ffuf, arjun, S3Scanner, DAST, blind-XSS planting.
- **Cloudflare-fronted hosts (`au.seek.com`, `au.employer.seek.com`): NEVER issue back-to-back
  fetch() calls for page HTML.** Tripped TWICE on 2026-08-19 (bundle mining, then pricing recon).
  Use ONE real browser navigation, read what it returns, wait, then navigate again. Reserve
  programmatic fetch for same-page API calls the app itself would make, under ~1/sec.
  `app.seekpass.co` (CloudFront/S3) is tolerant and can absorb bulk asset fetching.
- **Burp cannot reach `*.seek.com`** — drive through the browser.
- **Excluded classes — do not spend a minute on them:** DoS/volumetric, rate-limit bypass, verbose
  errors/stack traces, admin/monitoring LOGIN PAGES with no data, non-sensitive API keys, config-only
  (headers/cookie flags/TLS/password policy), **pre-auth account takeover**, unpatched software,
  mobile-root issues, Accessibility Service abuse.
- **Reports must not be AI-generated.** Claude verifies and assembles evidence; the OPERATOR writes.
- **Hard lines:** our own ids only; never enumerate the advertiser id space (short + near-sequential
  = tempting AND forbidden); never revoke/destroy anything we do not own; never touch a third party's
  ABN, submission id or credential; no money movement — stop at any payment screen and ask.

---

## THE BOARD — where the campaign stands (update every night)

### CLEARED (do not re-walk; each has its limits recorded in the workspace)
- Token-layer hirer tenancy: `advertiser:<id>` entitlement is enforced, no existence oracle.
- S3 identity-document bucket: anonymous LIST + ACL denied. *Object-level still untested.*
- `au.seek.com/graphql`: introspection AND field suggestions both off.
- `au.employer.seek.com/graphql`: introspection off, generic `Invalid request`, no field-name leak.
- Job-ad authoring: ProseMirror strips `<img>`/`javascript:`; summary stored+escaped. *Ad RENDER untested.*
- `candidatePartnerAddExternalDataPublicFetch`: unauth by design but returns METADATA ONLY.
- **Cross-API audience separation**: the hirer token (`api/talent`) is rejected by BOTH the partner API
  and the candidate API with `Unknown 'aud'`. No audience confusion.
- **`graphql.seek.com` unauth per-resolver sweep** (2026-08-19): a real differential exists —
  `candidateProfile`/`candidate`/`positionOpening`/`positionProfile` return plain `null` with NO auth
  error while `hiringOrganization`/`advertisementBranding`/`applicationQuestionnaire`/`self` raise
  `UNAUTHENTICATED`. **NOT a bypass**: `extensions.requestLatency` is 5-6ms for all of them, identical
  to the static `version` floor ⇒ no lookup happens, the null is unconditional. Unresolvable without a
  real partner-scheme object id; we do not enumerate. *Re-run it the instant partner credentials exist —
  those four are the first place a missing relationship check would show.*

### LIVE LEADS (ranked)
1. **Cross-tenant CV read** — `applicationAttachmentsV2(input:{jobId, applicationCorrelationId})` and
   `application(input:)`. Needs a real application to exist: org A publishes a job → candidate +a/+b
   applies → read ids from A → request them from B. **Blocked on whether posting costs money.**
2. **Intra-tenant BFLA** — add a second, low-privilege user to org A via `/account/team`, then attempt
   `canExportApplications`, `canPayInvoices`, `canManageUsers`, `canManageBrand`. Self-contained,
   no second org needed, no cost. **This is the best unblocked lane — do it next.**
3. **SSRF** — SEEK Pass `document` URL field (domain-allowlisted) and webhook registration;
   candidate-side `validateMyEqualsUrl`, `updateHkAcvpUrlDocumentSubmission`. OOB canary only.
   Matches SEEK focus area #3 (internal network).
4. **ABN business impersonation** — auto-verification may check ABN existence, not ownership.
   NOT testable without a real third party's ABN → ask Bugcrowd Support first.
5. **Partner API** (blocked on credentials): `/add/batch` scope-OR escalation into `digital_identity`;
   v1 read endpoints declare an EMPTY OAuth scope; `PUT /webhooks/{id}/secret` rotation BOLA; **plus the
   re-run of the graphql.seek.com resolver sweep with a token** (cross-hirer BOLA on the id-taking queries —
   full ranked plan in `workspaces/seek_assets/graphql_seek_com_schema.md`).
6. **`/oauth/transition` + transition_token** — cross-product identity binding, both products.
7. Legacy IdP `auth.seekpass.co` still trusted in the production CSP.

### UNTOUCHED SURFACE (the breadth debt)
jobstreet.com (54 hosts / 900 endpoints), jobsdb.com (41 / 452), `*.outfra.xyz` (383 hosts, incl.
the Auth0 tenant `seekanz.onlineauth.prod.outfra.xyz`), `*.skinfra.xyz` (36), `*.jobapi.net` (24),
`*.sol-data.com`, `*.myseek.xyz`, `*.aips-internal.com`, 4 mobile apps, `graphql.seek.com` +
dev/test/staging siblings, and 6 of 8 `au.seek.com` micro-frontends.

### FRESH-CODE WATCH
SEEK Pass release notes said new `revoked`/`unshared` statuses + webhook events land **on or after
4 Sept 2026**. Re-read `developer.seekpass.co/en-au/docs/guide/release-notes/` after that date —
new code on an identity API is the best freshness/weakness intersection available.

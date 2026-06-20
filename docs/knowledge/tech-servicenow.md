# tech-servicenow — ServiceNow unauth data exposure (Simple List widget + ACL misconfig)

Fingerprint: `webserver: snow_adc` (ServiceNow App Delivery Controller) in recon_alive, or host
`*.service-now.com` / `service-now.*` / `servicenow.*`. Root usually **302 → login** (SSO/SAML) — a
login redirect at `/` does NOT mean the data API is gated; the public widget API is a SEPARATE surface.

## The class (Aaron Costello / AppOmni, Oct 2023 — still widely unpatched)
ServiceNow Service Portal ships public widgets ("Simple List", "Unordered List", others) that, when an
ACL is configured with **no role + no condition + no script** (the default on many tables / over-provisioned
guest), let an **UNAUTHENTICATED** user read arbitrary tables+fields. AppOmni found ~70% of instances
vulnerable in 2022; >90% of public instances leaking *something*. PII (names/emails), incident details,
internal KB articles, even `oauth_entity` (client secrets) have been pulled. = High/Critical data exposure.

## The SAFE confirm primitive (unauth, READ-ONLY GET — non-destructive)
Canonical scanner: https://github.com/bsysop/servicenow (replace `t=` with any table).

1. (optional token) `GET https://<host>/login.do` → scrape `g_ck` token from body; send as `X-UserToken`
   + reuse the cookie jar. Many instances return data **without** any token (contributor D. Müller note).
2. Request the widget. **Method matters by version:**
   - Older: `GET .../api/now/sp/widget/widget-simple-list?t=<table>`.
   - Newer (returns `405 "GET method not supported for API"`): use **POST** to the SAME URL — the table
     still goes in the `?t=<table>` query string (`$sp.getParameter('t')`), body is empty `{}`, headers
     `X-UserToken: <g_ck>` + `Content-Type: application/json`. Optional `f=<field>` query, `filterText` in body.
   - **VULNERABLE** = `result.data.count > 0` with a populated `result.data.list` (record rows).
   - **NOT vuln** = `result.data.count: 0` / empty list / `isValid:false` / redirect to login / 401/403 /
     `"User Not Authenticated"`. (405 just means wrong HTTP method — retry as POST, not a verdict.)

Canary tables (escalate only enough to prove impact, NEVER mass-dump):
- `kb_knowledge` — fast-check canary (internal KB articles; often the first to leak)
- `incident` — incident records (descriptions, internal notes = sensitive)
- `sys_user` — PII (name/email/phone) = clean high-sev PoC
- `sys_user_group`, `cmdb_ci`, `sc_request`, `oauth_entity` (secrets), `sys_user_has_role`
Related newer vector (2024+): `POST /api/now/related_list_edit/create` reachable unauth = related-list
record creation/disclosure. **State-changing — do NOT fire autonomously** (write); read path only.

## HARD LINE (recon-vs-attack)
Confirm the widget returns >0 records for ONE canary table = CONFIRMED exposure → STOP. Do NOT iterate all
tables, do NOT page through records, do NOT harvest PII. The PoC is "unauth widget returns record N" with a
single redacted row. Read-only GET only; never the `related_list_edit/create` write path.

## Impact gate / FP notes
- 302→login at `/` alone = NOT a finding (expected). Need the WIDGET to return data.
- Empty list / `[]` = ACLs enforced = NOT vuln (note it, move on).
- Heroku/`mockservicenow`/marketing pages that merely mention ServiceNow ≠ a real instance.
- Severity by table: `sys_user`/`incident`/`oauth_entity` data = High/Critical; only `kb_knowledge`
  public-by-design marketing KB = Low/Info (check the article content before claiming).

## In-scope+paying instances seen in ES (2026-06-19, 54 total `snow_adc`)
Elite/high-value: employee.crowdstrike.com, now/now-uat/now-devtoggle.wf.com (Wells Fargo),
help.playstation.net (+dev/sit), {ecm,techspot,xpe}.comcast.com, ehc.lululemon.com,
test-escalations.vintedgo.com (Vinted explicitly scopes it), service-now.dropboxer.net,
SBB cluster (apps/capps/dapps/iapps/tapps/yapps/{d,i,t}service.sbb.ch …), EPAM support cluster,
Playtika/Slotomania/Redecor, knowledge/support/status.here.com.

Sources: Aaron Costello "Data Exposure and ServiceNow" (enumerated.io, 2023-10-14); AppOmni AO Labs
technical analysis; bsysop/servicenow scanner.

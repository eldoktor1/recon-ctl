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

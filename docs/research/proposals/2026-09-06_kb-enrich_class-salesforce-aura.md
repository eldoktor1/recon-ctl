# PROPOSAL (proposal) for docs/knowledge/class-salesforce-aura.md — kb-enrich 2026-09-06
_Review and apply manually; not auto-merged into the KB._

## Guest-user Aura/Lightning BOLA — unauth confirm primitive (added 2026-09-06)

**Class:** broken access control via over-provisioned Salesforce Experience Cloud/Community guest
profile, exposed through the Aura framework's internal RPC endpoint. Customer-misconfiguration class
(not a Salesforce platform CVE) — actively exploited by ShinyHunters since Sept 2025, ~300-400 orgs,
disclosed March 2026. Every misconfigured in-scope org is an independent, non-dup finding.

**Fingerprint (from JS-intel / jsintel endpoint mining):** any in-scope host serving
`/aura`, `/sfsites/aura`, or `/s/sfsites/aura`, or whose bundled JS references
`force-community`/Aura framework markup (`fwuid`, `auraConfig`).

**Safe unauth confirm (read-only, non-destructive — one request per step):**
1. `GET` the community/site root → extract `fwuid` (`"fwuid":"([^"]+)"`) and `app`
   (`"app":"([^"]+)"`) from inline page markup — public framework build IDs.
2. Build `aura.context` = JSON `{mode:"PROD", fwuid, app, loaded:{...}}` (base64/urlencode per the
   framework's transport format).
3. `POST {endpoint}` with form body `message` / `aura.context` / `aura.token=undefined`.
4. Cheap capability probe: `message` descriptor
   `serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData`
   — confirms the endpoint answers unauthenticated at all.
5. **The actual BOLA probe** — swap descriptor to:
   - `serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems`
     with `params:{entityNameOrId:"User", ...}` (or another guessed sObject) — lists records if the
     guest profile has read FLS on that object.
   - `serviceComponent://ui.force.components.controllers.detail.DetailController/ACTION$getRecord`
     — fetch one specific record by an ID surfaced from the list call.
   Response containing real PII fields (`Email`, `Phone`, `Name`, internal `Id`) for a
   non-public object = CONFIRMED. **Stop at one confirmed record** — do not mass-harvest (minimal
   PoC doctrine); severity scales with *what object* is exposed (User/Contact/Case = high; public
   marketing content = by-design/low).
6. Known severity-scaling factor (not for us to exploit, just to note in the report): Salesforce
   caps Aura list responses at 2,000 records by default; researchers found the `sortBy` param can
   bypass that cap — relevant to describing blast radius honestly, not to actually pull 2000+ records.

**Tooling:** AuraInspector (Mandiant, OSS auditor — the same tool the ShinyHunters campaign
weaponized against real orgs) · SALSA (`github.com/cosad3s/salsa`, Aura misconfig scanner) ·
Misconfig Mapper (bulk `/aura` path discovery across a host list — run ahead of jsintel on any
Experience Cloud host).

**FP note:** guest access to genuinely public objects (marketing content, public knowledge articles
by design) is not a finding — confirm the exposed object/fields are not intended to be public before
minting (same discipline as our bucket public-read lane).

Sources: intigriti "Hacking Salesforce Lightning" (2026), unixtz "Exposing BAC in Salesforce Aura",
moniik/poc_salesforce_lightning, cosad3s/salsa, BleepingComputer ShinyHunters Aura campaign report.

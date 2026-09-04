# PROPOSAL (proposal) for docs/knowledge/class-salesforce-aura.md — kb-enrich 2026-09-03
_Review and apply manually; not auto-merged into the KB._

## AuraInspector-style guest-profile misconfiguration — live mass-campaign, safe detection — added 2026-09-03

**Context (why this matters now):** ShinyHunters ran a campaign (active since Sept 2025,
publicly disclosed March 2026) against an estimated 300–400 Salesforce orgs by weaponizing
**AuraInspector**, a tool Mandiant open-sourced in Jan 2026 as a defensive, READ-ONLY
Experience-Cloud misconfiguration checker. Any Salesforce Experience Cloud host currently in
our scope is presently in the blast radius of active real-world scanning — high-signal,
time-sensitive, and the underlying detection technique is exactly our style of unauth-safe
confirm primitive (no data harvest required to prove the bug).

**Target surface:** Aura endpoints on Experience Cloud sites — `/s/sfsites/aura` (primary),
also `/aura`, `/sfsites/aura`. The bug is a **guest user profile misconfiguration**
(over-permissioned Object/Field-level access for unauthenticated visitors), not a Salesforce
platform code vuln.

**Safe, read-only detection flow (this is literally what AuraInspector's public/defensive
build does — data-extraction capability was deliberately excluded from the OSS release):**
1. Load the target Experience Cloud site once normally; capture the `aura.context` JSON blob
   from any legitimate request (contains `mode`, framework UID, app reference, loaded-component
   hashes) — needed to construct a valid-looking Aura request.
2. POST to `/s/sfsites/aura` with `Content-Type: application/x-www-form-urlencoded` and a
   `message` param invoking:
   `serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData`
   — this enumerates every Object/Component the current (guest) user can see, unauthenticated.
3. If the response lists sensitive objects (`Account`, `Contact`, `Lead`, internal
   user/support/case records) reachable by the guest profile, that alone is the confirmed
   misconfiguration — **do not go further and pull actual records** (matches our
   confirm-the-primitive-never-harvest doctrine and the tool's own designed stopping point).

**Separately documented, concrete impacts (not theoretical):**
- Full names + sometimes email/phone of OTHER USERS visible to unauthenticated guests via
  Aura context (Intigriti).
- Historical unauthenticated file-upload via guest support-ticket flows (no ACL check on
  attachment upload).
- XSS via the `aura.tag` parameter reflecting into the response on some configurations.

**Recon fit:** fingerprint candidates among in-scope hosts via Salesforce-specific markers
(`force.com`/`.lightning.force.com`/`sfsites` in JS/CDN refs, or a live `/s/sfsites/aura`
response) before running the read-only `getConfigData` probe — same shape as our GraphQL
introspection lane (schema/config enumeration first, human decides what's worth an authed
follow-up).

Sources: en.wikipedia.org/wiki/Aura_data_breach, thehackernews.com/2026/03/threat-actors-mass-scan-salesforce.html, rhisac.org/threat-intelligence/shinyhunters-sf-aura, intigriti.com/researchers/blog/hacking-tools/hacking-salesforce-lightning-guide-for-bug-hunters, gbhackers.com/salesforce-aura

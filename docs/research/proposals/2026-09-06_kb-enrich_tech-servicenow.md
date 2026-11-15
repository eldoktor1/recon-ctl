# PROPOSAL (proposal) for docs/knowledge/tech-servicenow.md — kb-enrich 2026-09-06
_Review and apply manually; not auto-merged into the KB._

## Unauthenticated scripted REST API exposure — generalized pattern (added 2026-09-06)

June 2026 incident: ServiceNow's own `/api/now/related_list_edit/create` endpoint was left with
`requires_authentication=false` on `sys_ws_operation`, letting unauthenticated requests pull ticket/
HR/vendor-contract data across multiple customer instances (patched by ServiceNow hosted-side
2026-06-05; on-prem/customer-managed instances are NOT automatically covered). This is a config
error class, not a single CVE — it reproduces independently on any instance where a custom Scripted
REST API resource has auth left off.

**Detection (unauth, safe, GET/HEAD/OPTIONS only):**
1. Enumerate ServiceNow custom API paths for the target host via jsintel/JS mining
   (`/api/now/table/*`, `/api/now/related_list_edit/*`, `/api/<scope>/*` custom scripted resources)
   and via `sys_ws_operation.list`-style path guessing if a dev/staging instance leaks its API
   catalog.
2. `GET` each candidate path with NO session cookie/Authorization header.
3. A `401`/redirect-to-login = secure (expected default). A `200` returning real record JSON
   (ticket numbers, names, emails, vendor/contract fields) = CONFIRMED unauth data exposure — the
   response itself, redacted, is the evidence; do not iterate to harvest more records than needed
   to prove the class of data returned.

**Companion angle already known to be prevalent (Costello/AppOmni research, ~70% of tested
instances leaking PII):** the *widget* variant — role-less ACLs + overprovisioned guest-user
widgets (e.g. "Simple List") let an unauthenticated visitor iterate known table/field name
combinations through the widget and get data back. Same confirm primitive: unauth GET/POST to the
widget endpoint with a guessed table/field, real data back = confirmed. Both variants share root
cause (ACL/auth config left open on a customer-managed instance) — check both when a ServiceNow
in-scope host doesn't 401 on API discovery.

**Severity framing:** honest per data type returned (PII/HR = high; public knowledge-base content
by design = not a finding). Don't mass-enumerate tables — one confirmed table/record type is the
proof.

Sources: Obsidian Security "ServiceNow Unauthenticated API Access Vulnerability" (June 2026),
TheHackerNews "ServiceNow Flaw Exploited" (June 2026), AppOmni AO Labs ServiceNow ACL misconfiguration
research (Aaron Costello).

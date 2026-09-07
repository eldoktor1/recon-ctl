# PROPOSAL (proposal) for docs/knowledge/tech-argocd.md — kb-enrich 2026-09-06
_Review and apply manually; not auto-merged into the KB._

### Applied research — kb-enrich (2026-09-06)

## New 2026 CVEs (add below the CVE-2025-55190 entry)

- **CVE-2026-82456 (CVSS 10.0, argocd-mcp 0.8.0, UNAUTHENTICATED):** the `argocd-mcp` MCP-server
  sidecar (separate from argocd-server) binds its HTTP transport to ALL interfaces and accepts MCP
  sessions with NO credential check when the operator has set `ARGOCD_API_TOKEN`. Any network-reachable
  unauth attacker inherits the full privileges of that stored token — create Applications, force syncs,
  mutate resources. If an MCP-server port is discoverable alongside an Argo CD instance, this is a
  genuine unauth-confirmable primitive (not just a version match) — probe read-only MCP session
  init/list-tools only, never invoke a mutating tool. Fixed in argocd-mcp releases after 0.8.0 — check
  for a patched version banner before treating a match as live.
  Source: https://www.thehackerwire.com/argocd-mcp-critical-auth-bypass-resource-control/

- **CVE-2026-42880 / CVE-2026-43824 (CVSS 9.6, likely duplicate/renumbered pair for the SAME bug —
  reconcile before citing one over the other):** the `ServerSideDiff` endpoint is the ONE place Argo CD
  forgets to call `hideSecretData()`. A **read-only** account with only default `applications get` RBAC
  (every authenticated user has this by default) can retrieve cleartext Kubernetes `Secret` data via the
  ServerSideDiff dry-run path, on any Application annotated
  `argocd.argoproj.io/compare-options: IncludeMutationWebhook=true` (equivalently
  `include-mutation-webhook: true`). Affected: `>=3.2.0 <3.2.11`, `>=3.3.0 <3.3.9`; fixed 3.2.11 / 3.3.9.
  Disclosers withheld the exact endpoint path/request shape (responsible disclosure) — no public PoC
  request found as of this digest. TRIAGE: version-in-range ⇒ authed-LEAD (needs an operator-held
  low-priv token to exploit, same authed-exploitation caveat as CVE-2025-55190) — never headline the
  version match alone as a finding.
  Sources: https://cybersecuritynews.com/argo-cds-serversidediff-vulnerability/ ,
  https://bugzilla.redhat.com/show_bug.cgi?id=2464613 ,
  https://www.endorlabs.com/vulnerability/cve-2026-42880

- **Legacy freebie (GHSA-87p9-x75h-p4j2, CVE-2024-37152, moderate):** unauth `GET /api/v1/settings`
  disclosed config data (all fields except `passwordPattern`) on `>=2.9.3 <2.9.17 / <2.10.12 / <2.11.3`.
  Almost certainly patched on any 2026-era instance, but a zero-cost single-request check to fold into
  the existing `/api/version` fingerprint pass — if it ever returns non-trivial JSON, the instance is
  years out of date and worth a full version-floor re-check across every CVE in this doc.
  Source: https://github.com/argoproj/argo-cd/security/advisories/GHSA-87p9-x75h-p4j2

## Updated triage rule
`/api/version` in-range for ANY of the above ⇒ LEAD only, per-CVE authed/unauth status as noted above.
CONFIRMED still requires either: the argocd-mcp unauth session-init succeeding (CVE-2026-82456), an
unauth `/api/v1/applications` app-list leak, an unauth `/api/v1/settings` non-trivial response
(legacy), or an operator-held token demonstrating the ServerSideDiff/repo-credential leak. Version
match alone never P0.

# PROPOSAL (proposal) for docs/knowledge/tech-argocd.md — detect-tune 2026-09-17
_Review and apply manually; not auto-merged into the KB._

## Unauth CVE cluster (Aug 2026) — CVE-2026-82277, CVE-2026-15416, CVE-2026-82456

- **CVE-2026-82277** (CVSS 9.8, CWE-306): Argo Rollouts dashboard ≤1.10.0, all interfaces, no auth/CSRF on
  mutating ops (`PromoteRollout`/`AbortRollout`/`RestartRollout`/`SetRolloutImage`/`UndoRollout`/`RetryRollout`).
  Default port commonly **:3100**. SAFE confirm primitive: single unauth `GET /api/v1/rollouts/<namespace>`
  (or dashboard root JSON) — a real rollout-object response is CHAIN-TO-IMPACT (deployment/image state
  disclosure), no mutation needed to prove exposure. NEVER invoke the mutating ops (state-changing, cluster
  blast radius) — those are the exploit, not the recon. No dedicated fix yet as of 2026-08-28; mitigation is
  network isolation, so any confirmed-reachable instance in-scope is real.
- **CVE-2026-15416** (CVSS 8.9, CWE-306): ArgoCD repo-server `GenerateManifest` gRPC endpoint, unauth network
  access → cached-manifest manipulation → potential cluster compromise. Fixed argo-helm ≥10.0.0. gRPC, not
  plain HTTP — our probe tooling can't safely confirm this; version-gate only (match repo-server version via
  exposed `/api/version` or Helm labels), treat as LEAD, do not attempt exploitation.
- **CVE-2026-82456** (CVSS 10.0): `argocd-mcp` 0.8.0 binds HTTP transport on all interfaces, no session auth
  required when `ARGOCD_API_TOKEN` is configured — full ArgoCD tool surface (create apps, sync, modify
  resources) reachable unauth. Niche (MCP server) but same missing-auth pattern; fingerprint if seen.

Sources: synacktiv.com/en/publications/caught-in-the-octopus-trap-unauthenticated-rce-in-argo-cd-with-codeql,
nflo.tech/knowledge-base/2026-08-28-cve-2026-82277-en, thehackerwire.com/argocd-mcp-critical-auth-bypass-resource-control

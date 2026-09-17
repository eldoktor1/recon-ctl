# Research digest — detect-tune — 2026-09-17

# Research digest — detect-tune — 2026-09-17 (pass 3)

## 1. Argo CD / Argo Rollouts unauthenticated-RCE CVE cluster (Aug 2026) — new confirm primitives for `tech-argocd.md` (HIGH PRIORITY)

Two distinct unauth vulns, both CVSS ≥8.9, both fit our existing ArgoCD lane:

- **CVE-2026-82277** (CVSS 9.8) — Argo Rollouts dashboard ≤1.10.0 binds all interfaces, exposes **mutating** rollout operations (`PromoteRollout`/`AbortRollout`/`SetRolloutImage`/etc.) with zero auth/CSRF. Dashboard commonly on **:3100**, path prefix `/rollouts` or `/api/v1/rollouts/<ns>`. Per our doctrine, the mutating ops themselves are off-limits (state-changing, third-party blast radius) — but the **read-only list endpoint** (`GET /api/v1/rollouts/<ns>` or the root dashboard JSON) on an unauth-reachable instance is itself a CHAIN-TO-IMPACT primitive: it discloses live deployment/image state without touching anything. Safe confirm = single GET, check for rollout object JSON in the response; mint on **data returned**, not on "port open."
- **CVE-2026-15416** (CVSS 8.9) — ArgoCD repo-server `GenerateManifest` gRPC endpoint, reachable unauth via network access, lets an attacker manipulate cached manifest data toward cluster compromise. This is gRPC (not plain HTTP), fixed in argo-helm ≥10.0.0. Given our tooling is HTTP-probe based, treat as **version-gate LEAD only** (match repo-server version <10.0.0 via exposed `/api/version` or Helm chart labels) — don't build an active gRPC exploit primitive; flag for operator if a target is confirmed in-range.
- **Also new**: CVE-2026-82456 (argocd-mcp, CVSS 10.0) — MCP HTTP transport with no session auth when `ARGOCD_API_TOKEN` is set; niche (MCP server exposure) but same pattern — worth a fingerprint entry if we ever see `argocd-mcp` in JS-intel/banner data.

Actionable: extend `recon_nday.sh` version-reasoning to include these three CVE IDs against any ArgoCD/Argo-Rollouts fingerprint; add the read-only rollout-list GET as a chain-to-impact confirm step (analogous to the actuator/bucket pattern) when a Rollouts dashboard is unauth-reachable.

Sources: [Synacktiv — Caught in the Octopus Trap](https://www.synacktiv.com/en/publications/caught-in-the-octopus-trap-unauthenticated-rce-in-argo-cd-with-codeql), [nFlo — CVE-2026-82277](https://nflo.tech/knowledge-base/2026-08-28-cve-2026-82277-en/), [hol.org — CVE-2026-15416](https://hol.org/guard/security/cves/CVE-2026-15416-argo-cd-argo-cd-unauthenticated-remote-code), [TheHackerWire — argocd-mcp](https://www.thehackerwire.com/argocd-mcp-critical-auth-bypass-resource-control/)

## 2. Bucket lane is S3-only — Azure Blob / GCS provenance extension is a genuine, still-open gap (MEDIUM)

Our `recon_bucket_scanner.sh` (S3Scanner backend) only handles AWS S3. The same provenance-seeded doctrine (mine bucket refs from the target's own JS/params surface, never blind-permute) applies cleanly to `*.blob.core.windows.net` (Azure) and `*.storage.googleapis.com` (GCS) — both are commonly referenced in JS bundles of orgs using multi-cloud, and public-read misconfig is structurally identical (container-level "Full public read" for Azure = a single unauth `?restype=container&comp=list` GET; GCS = unauth `GET /storage/v1/b/<bucket>/o` via JSON API or XML `?list-type=2`). No new CVE here — just an existing detection gap worth closing since it's zero extra recon (same JS-intel provenance feed already extracts these URLs, just not currently routed to a scanner).

Actionable: add a lightweight Azure/GCS branch to the bucket pipeline — same gates (provenance-required, in-scope+pays, public-write→verify/public-read→lead) as S3.

Sources: [Goblob (Azure blob enum reference)](https://github.com/Macmod/goblob), [Microsoft Security Blog — Azure Blob Storage attack chain](https://www.microsoft.com/en-us/security/blog/2025/10/20/inside-the-attack-chain-threat-activity-targeting-azure-blob-storage/)

---

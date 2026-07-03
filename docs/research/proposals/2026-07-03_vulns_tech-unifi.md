# PROPOSAL (proposal) for docs/knowledge/tech-unifi.md — vulns 2026-07-03
_Review and apply manually; not auto-merged into the KB._

## N-Day CVEs — 2026

### CVE-2026-34908 / 34909 / 34910 — UniFi OS Triple RCE Chain (KEV Jun 23, CRITICAL)
- **Affected:** All UniFi OS firmware before June 2026 patch (Cloud Gateways, Network Controllers, Protect NVRs, Access Hubs, Talk appliances).
- **Class:** Auth bypass (34908) + path traversal arbitrary file read/write (34909) + OS command injection (34910) → unauthenticated root RCE.
- **Fingerprint/detect:** Bishop Fox `BishopFox/CVE-2026-34908-check` — single GET probe to nginx-routed path returns vulnerable / patched / inconclusive. Safe/read-only.
- **Pipeline:** We have 4,600+ UniFi consoles in ES. THIS IS NOT the fanout-suppressed IDOR lane — it is device-level RCE. Run against in-scope+paying hosts via `recon-nday`.
- **Hard line:** Shared-tenant hosted consoles (`<uuid>.unifi-hosting.ui.com`) still require the shared-tenant hard-line check; skip these. Only directly-accessible or operator-owned consoles.
- **Sources:** https://bishopfox.com/blog/popping-root-on-unifi-os-server-unauthenticated-rce-chain-detection-analysis · https://github.com/BishopFox/CVE-2026-34908-check · https://threat-modeling.com/cve-2026-34908-34909-34910-ubiquiti-unifi-os-triple-kev/

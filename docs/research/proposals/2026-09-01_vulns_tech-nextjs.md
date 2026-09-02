# PROPOSAL (proposal) for docs/knowledge/tech-nextjs.md — vulns 2026-09-01
_Review and apply manually; not auto-merged into the KB._

## 2026-09-01 — Aug 2026 security release: 2 unauth Critical RCEs

**AVIF Image Optimization RCE (GHSA-2xp9-vwfh-vxw4, upstream libheif GHSA-g89c-p67h-r497, CVSS 9.5)**
- Affected: Next.js 10.0.0–15.5.23, 16.0.0–16.3.2 (self-hosted only — Vercel-hosted apps were pre-patched platform-side).
- Root cause: `sharp`'s bundled `libheif` heap overflow decoding attacker-supplied AVIF, triggered via the built-in Image Optimization API (`/_next/image?url=...`), which decodes AVIF automatically based on the requester's `Accept` header — no special config needed.
- Detect: confirm host is Next.js + version < 15.5.24/16.3.3 (build-id/x-powered-by/jsintel bundle), AND `/_next/image?url=...&w=...&q=...` responds live (proves Image Optimization is enabled, not disabled).
- Do NOT fire a real malicious-AVIF PoC autonomously — exploitation, not a safe unauth primitive. Version-match + live endpoint = LEAD → operator confirm-then-stop.
- This endpoint (`/_next/image?url=`) is the SAME path our WCD doctrine (class-cache-deception.md) already flags as a product-class dup-magnet for cache-deception fuzzing — now dual-purpose: also check RCE version range before dismissing it as "just WCD noise."

**Windows-hosted path traversal RCE (CVE-2026-75604, GHSA-p293-qw3h-jr36, CVSS 9.0)**
- Affected: Next.js 13.4.0–15.5.23, 16.0.0–16.3.2, apps using BOTH Pages Router + App Router WITHOUT Cache Components, Windows-hosted servers ONLY. Public PoC: github.com/rafabd1/CVE-2026-75604-poc.
- Low hit-rate on our corpus (skews Linux/container-hosted) but check if a target is confirmed Windows-hosted (IIS front, response headers).
- Both fixed in Next.js 15.5.24 (Maintenance LTS) / 16.3.3 (Active LTS), released 2026-08-25.
- Source: https://nextjs.org/blog/august-2026-security-release

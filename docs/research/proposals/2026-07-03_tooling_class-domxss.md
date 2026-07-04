# PROPOSAL (proposal) for docs/knowledge/class-domxss.md — tooling 2026-07-03
_Review and apply manually; not auto-merged into the KB._

## Prototype Pollution → DOM-XSS (addition)

### Tool: pphack
- **GitHub:** https://github.com/edoardottt/pphack
- **What it does:** Headless-Chromium scanner that injects client-side prototype pollution payloads and detects DOM-level impact dynamically. Finds PP sinks dalfox and static miners are blind to.
- **Our use pattern:** Detection-only (`-e` flag OFF for autonomous). A pphack hit is a **LEAD**; feed to `dalfox --deep-domxss --force-headless-verification` for EXECUTION confirmation (the CONFIRMED primitive).
- **Pipeline fit:** Pre-pass in `recon-domxss` before the source→sink miner. Unauthed GET-only, non-destructive.
- **Dup resistance:** The crowd does not run automated PP detection. PP + gadget = XSS PoC without direct injection = low dup risk even on saturated programs.
- **Last verified:** 2026-07-03 · v0.1.4 May 2026, actively maintained (572 commits).

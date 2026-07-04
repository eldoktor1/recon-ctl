# class-ssrf — Server-Side Request Forgery (SSRF) hunting

Research compiled 2026-07-03. Sources: PortSwigger Web Security Academy, Craft CMS CVE-2026-27129, HackerOne #1369312, herish.me five-bounties-one-ssrf writeup.

**Pipeline role:** SSRF is a CONFIRMED finding only via an OOB callback to a canary we control (interactsh). Reflection of the URL or a non-200 response is NOT confirmation. No `file://`, no internal-data exfiltration — one OOB ping is the PoC.

---

## The confirm primitive (pipeline-safe)

Point every tested SSRF sink at an **interactsh** collaborator URL:

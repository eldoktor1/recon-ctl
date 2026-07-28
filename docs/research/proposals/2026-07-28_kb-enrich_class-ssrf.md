# PROPOSAL (proposal) for docs/knowledge/class-ssrf.md — kb-enrich 2026-07-28
_Review and apply manually; not auto-merged into the KB._

## Second disclosed DNS-rebinding/TOCTOU instance (added 2026-07-28)

Reinforces the DNS-rebinding/TOCTOU section already in this doc (2026-07-14, Craft CMS instance). A
second, independently-disclosed 2026 case: **MCP Atlassian, CVE-2026-27826 (GHSA-489g-7rxv-6c8q)** — the
SSRF guard resolved the hostname once, validated the IP was public, then discarded the resolved IP
("returns a string verdict, not a pinned IP") and let the actual HTTP client re-resolve the raw hostname
at connect time. An attacker-controlled DNS-rebinding domain answers with a public IP on the validation
lookup and `169.254.169.254` on the connection lookup — identical root cause to the Craft CMS case, now
confirmed in an unrelated stack. Strengthens confidence this is a **systemic pattern class** (validate
hostname → discard result → reconnect via raw hostname) worth checking on ANY target whose SSRF guard is
implemented as "resolve + check" middleware in front of a generic HTTP client, not a one-off bug.

Source: https://github.com/advisories/GHSA-489g-7rxv-6c8q

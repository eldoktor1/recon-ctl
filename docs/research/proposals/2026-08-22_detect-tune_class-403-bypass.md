# PROPOSAL (proposal) for docs/knowledge/class-403-bypass.md — detect-tune 2026-08-22
_Review and apply manually; not auto-merged into the KB._

## Cloudflare cf-mitigated header — deterministic edge-block signal (2026-08-22)
Cloudflare's own docs confirm: any Challenge Page response (managed/interactive/JS challenge, any status
code) sets `cf-mitigated: challenge` on the response. This is the only value the header takes and it is
present for ALL challenge-page types — use it as a first-class, zero-ambiguity classifier for "the CDN
edge blocked this, the origin app never saw the request," ahead of body-branding/fingerprint heuristics.
Complements the block_source: edge vs app classification in safe_probe_worker.py (2026-08-20) — a response
carrying this header should classify as `edge` unconditionally (short cooldown, does not count toward the
circuit-breaker), independent of status code. Absence of the header on a 429/403 leans toward a genuine
app/origin-level block instead. Source: developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/

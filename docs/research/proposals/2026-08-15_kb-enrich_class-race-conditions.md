# PROPOSAL (proposal) for docs/knowledge/class-race-conditions.md — kb-enrich 2026-08-15
_Review and apply manually; not auto-merged into the KB._

## Multi-endpoint alignment tricks (added 2026-08-15, source: PortSwigger race-conditions methodology)
When a straight single-packet batch against a target shows partial or zero success (jitter too high,
or the flow spans multiple endpoints):
- **Connection warming** — fire a few throwaway requests down the same connection before the real gated
  batch, to absorb setup jitter and tighten the timing window.
- **Induced rate-limit delay** — deliberately trip a rate/resource limit with junk requests first; the
  resulting backpressure widens the TOCTOU window for the real batch. Try this on `/limit`/`/quota`
  targets before concluding "not racy."
- **Session-based locking bypass** — if single-packet racing shows no effect within one session, some
  frameworks serialize per-session-token. Retry the same batch spread across N session tokens.

## Partial-construction race (added 2026-08-15)
Distinct from balance/coupon/one-time-code races: racing a multi-step object-creation flow itself,
injecting `param[]=` (empty array) or null into a role/permission/state field mid-construction to catch
an uninitialized-default window. Add to the endpoint-signal list: any `/register`, `/create`, `/signup`,
or resource-creation endpoint with a role/permission/tier field is a candidate, not just referral-bonus
signup races.

Source: portswigger.net/web-security/race-conditions (Web Security Academy, PortSwigger — primary/authoritative).

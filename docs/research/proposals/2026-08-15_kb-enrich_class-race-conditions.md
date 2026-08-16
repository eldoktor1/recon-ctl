# PROPOSAL (proposal) for docs/knowledge/class-race-conditions.md — kb-enrich 2026-08-15
_Review and apply manually; not auto-merged into the KB._

## First Sequence Sync — breaking the single-packet byte limit (added 2026-08-15)
The standard single-packet attack is capped at ~1,500 bytes (Ethernet MTU) ≈ 20-30 simultaneous
requests — fine for limit-overrun (coupon/balance races) but too small to exhaustively race an
OTP/PIN keyspace (e.g. all 10,000 4-digit codes) in one shot.

**First Sequence Sync** (GMO Flatt Security, 2025) breaks this ceiling:
1. Build ONE oversized TCP payload (up to 65,535 bytes) containing many pipelined HTTP requests.
2. Let IP fragmentation split it across multiple Ethernet frames (unavoidable above MTU).
3. Send all fragments EXCEPT the one carrying the initial TCP sequence number first — the
   server-side TCP stack buffers out-of-order segments and does not begin processing.
4. Send the final fragment (seq #1) last — the stack now has a contiguous stream and releases
   all buffered requests for processing essentially simultaneously.

Demonstrated: 10,000 requests delivered in ~166ms. Real ceiling in practice is the target's
HTTP/2 `SETTINGS_MAX_CONCURRENT_STREAMS`, not the packet-count limit anymore.

**Relevance to our lane:** raises the practical severity ceiling on `/verify`, `/confirm`,
`/activate` one-time-code endpoints in `race_candidate` — a code space too large for the classic
20-30-request single-packet attack (e.g. a full 4-6 digit OTP) is now a plausible TOCTOU/limit-
overrun target, not just a small discount-stacking race. Still operator-confirmed via Burp/Turbo
Intruder (not autonomous); note it when ranking `race_candidate` endpoints with a numeric OTP/PIN
of ≤6 digits as HIGHER priority than before.

PoC code: `first-sequence-sync` GitHub repo (benchmark + PIN-bypass demo folders).
Source: https://flatt.tech/research/posts/beyond-the-limit-expanding-single-packet-race-condition-with-first-sequence-sync/

## Multi-endpoint hidden-substate races (added 2026-08-15)
Beyond single-endpoint limit-overrun: some vulnerable windows only exist BETWEEN two different
endpoints hitting the same underlying resource, not from repeating one request. Two disclosed
patterns to add to our endpoint-signal triage:
- **Auth/MFA gap:** race a login request (`POST /login`) against a request to a privileged/MFA-gated
  endpoint. If the session is marked "authenticated" before MFA enforcement is applied, the second
  request can land in the sub-state where the session is valid but MFA hasn't been checked yet.
- **Checkout validate/complete gap:** race the "validate balance/stock" step against the "complete
  order" step of a multi-step purchase flow (cart→checkout→confirm) — same account-overconsumption
  outcome as classic limit-overrun, but requires PAIRING two distinct endpoints in the same request
  group rather than repeating one.

**Triage implication:** when scanning `endpoints.jsonl` for race candidates, also look for
adjacent PAIRS on the same host that touch the same object/flow (login+dashboard, cart+checkout,
verify+confirm) — flag as `race_candidate_multiendpoint` and note both URLs in the briefing so the
operator sends them as ONE Turbo Intruder request group, not separately.

Source: https://portswigger.net/research/smashing-the-state-machine , https://portswigger.net/blog/new-techniques-and-tools-for-web-race-conditions

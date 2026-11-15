# Race Condition / TOCTOU Testing

## Why it's dup-resistant
Requires HTTP/2 single-packet synchronization + state reasoning. Commodity scanners don't attempt it; most hunters test it manually only when they already know the flow. Finding it via endpoint-signal triage is rare.

## The primitive (Kettle 2023, mainstream 2025-2026)
HTTP/2 multiplexes multiple requests in a single TCP packet, collapsing network jitter to ~1ms. The server processes them truly simultaneously, exposing TOCTOU (time-of-check to time-of-use) windows invisible to sequential testing.

## Endpoint signals to target (from jsintel / ES)
- `/coupon`, `/promo`, `/redeem`, `/voucher` — coupon replay
- `/transfer`, `/withdraw`, `/pay`, `/checkout` — balance overconsumption
- `/limit`, `/quota`, `/rate` — rate-limit bypass
- `/verify`, `/confirm`, `/activate` — one-time-code reuse
- `/register`, `/signup` with referral bonuses

## Safe automated triage (unauth-safe lane)
1. Pull endpoints with above path patterns from `endpoints.jsonl` + ES
2. Confirm in-scope + paying
3. Flag as `race_candidate` in briefing — operator tests

## Operator confirm with Turbo Intruder (Burp Pro)
```python
# Turbo Intruder script: send N identical requests single-packet HTTP/2
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1,
                           requestsPerConnection=20, pipeline=True)
    for i in range(20):
        engine.queue(target.req)

def handleResponse(req, interesting):
    if '200' in req.response or 'success' in req.response:
        table.add(req)

---

## Idempotency-gap mapping: a targeted double-spend worklist (Chime, 2026-09)

Rather than racing money endpoints at random, diff the schema for which ones carry an idempotency
key and which do not. The protected ones are a **built-in positive control**: if a shop uses
`idempotency_key` on six money mutations, its absence on a seventh is an anomaly rather than a house
style, and that is the one to race.

Method (offline, from an introspection dump):
1. Collect every mutation whose name or arguments look like money movement.
2. Flatten each argument's input object (recursively) into a flat field list.
3. Flag fields matching `idempot|request_id|client_reference|dedup|nonce|correlation|..._session_id`.
4. Flag fields matching `amount|amount_cents|total|..._amount|..._cents`.
5. The worklist is: **takes an amount, carries no idempotency key**.

On the target this produced 14 protected vs 17 unprotected-with-an-amount out of 100 money
mutations, and the sharpest pair sat side by side — one transfer path with `idempotency_key` and
another with none taking `amount` + `source_id` + `destination_id`.

**Report the LEDGER DELTA, not the response.** N concurrent identical requests returning `200`
proves nothing; the finding is a measured balance discrepancy against the expected single debit.

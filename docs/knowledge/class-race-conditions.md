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

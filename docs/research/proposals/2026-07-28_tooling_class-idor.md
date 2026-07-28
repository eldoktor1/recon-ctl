# PROPOSAL (proposal) for docs/knowledge/class-idor.md — tooling 2026-07-28
_Review and apply manually; not auto-merged into the KB._

## UUID-version-aware ID-type scoring (2026-07-28)
Not all UUID-shaped object-ref IDs are equal for IDOR ranking:
- **v1 UUID** (13th hex group starts with `1`) encodes a millisecond timestamp + the generating
  host's MAC/node-id in the low bits. This makes it **structurally predictable** — an attacker who
  observes one v1 UUID from a system can forge nearby-in-time UUIDs without any prior leak
  (technique + reference tool: intruder-io/guidtool, https://github.com/intruder-io/guidtool).
  Treat v1-UUID object-ref params as a HIGHER-priority IDOR candidate than a generic "uuid" bucket.
- **v4 UUID** (13th hex group starts with `4`) is cryptographically random — it is only harvestable
  if disclosed elsewhere (another endpoint, a list response, a leaked JS blob), never guessable cold.
  Keep at the existing "harvestable-if-leaked" tier.
- Practical check: version nibble = the first hex char of the 3rd group (`xxxxxxxx-xxxx-Vxxx-...`).
  `V==1` → predictable-tier; `V==4` → leak-dependent tier; other versions (3/5/nil) → rare, treat as v4-tier.
- Actual enumeration/guessing of another user's v1-predicted ID is still real testing against a live
  target — stays human-in-the-loop with 2 owned accounts per the IDOR hard line; this only changes
  RANKING/prioritization, not the confirm gate.

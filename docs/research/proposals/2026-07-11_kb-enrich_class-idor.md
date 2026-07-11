# PROPOSAL (proposal) for docs/knowledge/class-idor.md — kb-enrich 2026-07-11
_Review and apply manually; not auto-merged into the KB._

## UUIDv7 timestamp-prefix — a distinct enumerability tier from UUIDv4 (added 2026-07-11)
RFC 9562 UUIDv7 (increasingly the default over sequential ints / UUIDv4 in newer ORMs — Rails 7.2+,
Postgres 17 `uuidv7()`, many Node/Prisma stacks) embeds a **48-bit millisecond Unix timestamp** as the
leading bits; only the remaining ~74 bits are random. This means "ID type: uuid" is no longer one
bucket for enumerability scoring:
- **UUIDv4** — no leak vector = practically unguessable (current KB position, correct, keep as-is).
- **UUIDv7** — if an attacker can bound the target's creation time (a listing endpoint shows relative
  age, a signup-confirmation email timestamp, "created today" copy, sequential adjacent records in a
  feed), the search space collapses to one narrow millisecond window of pure randomness per guess —
  MUCH cheaper to brute than full UUIDv4, and the timestamp itself is a **PII/recon leak** on its own
  (exact account-creation or record-creation time, even without ever guessing the full ID).
- **Detection:** decode any UUID field with a `version` nibble of `7` (the `M` position in
  `xxxxxxxx-xxxx-7xxx-yxxx-xxxxxxxxxxxx`) — instantly recover the embedded creation timestamp
  (ms-precision) without any exploitation, useful even just to prove recon/PII leak impact.
- **Scoring implication for `recon_idor_candidates.py`:** split the current `uuid=harvestable` bucket
  into `uuidv4` (needs an external leak vector, keep low-priority) vs `uuidv7` (medium-priority even
  standalone — decode-only PII leak; escalate if a plausible timestamp-narrowing leak vector exists
  nearby, e.g. a public listing/feed on the same host).
Sources: https://medium.com/@dimpchubb/exploiting-uuids-in-account-takeover-a-penetration-testers-guide-to-bypassing-insecure-token-96de9cc520a3 ,
https://kkm-mako.com/en/blog/articles/uuid-v4-v7-bigint-primary-key-design/

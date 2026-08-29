# PROPOSAL (proposal) for docs/knowledge/class-jwt-attacks.md — kb-enrich 2026-08-29
_Review and apply manually; not auto-merged into the KB._

## Concrete jku/kid exploitation payloads (added 2026-08-29) — LEAD fingerprint unchanged, adds the forge step detail

### kid → SQL injection (key-lookup bypass, not algorithm bypass)
When `kid` is used to look up the signing key in a DB, inject to make the lookup return an
attacker-known value, then sign the forged token with THAT value as the HMAC secret:

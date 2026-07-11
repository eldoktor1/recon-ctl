# PROPOSAL (proposal) for docs/knowledge/class-jwt-attacks.md — detect-tune 2026-07-11
_Review and apply manually; not auto-merged into the KB._

## Detection-only signal, 2026-07-11 (still human-confirm before minting anything)
- Fingerprint candidates from already-crawled JS/API responses: any JWT header/claim containing
  `jku`, `x5u`, or `kid` is a lead worth flagging — `jku`/`x5u` (server fetches signing keys from
  a URL in the token) is only exploitable if that URL is attacker-controllable; `kid` is only
  exploitable if the value is used unsanitized as a file path / DB lookup (injection primitive).
- LEAD-grade probe: swap `alg` to `none`/`HS256`/`HS384`/`RS256`; a 200 with a DIFFERENT accepted
  alg is a signal of missing algorithm allowlisting, NOT confirmation — no forged signature yet
  validated. Do not mint CONFIRMED off header-acceptance alone; forging a working signature is an
  active PoC step (own-account, ACTIVE-PoC gates, human-in-the-loop).

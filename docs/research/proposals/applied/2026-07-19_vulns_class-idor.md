# PROPOSAL (proposal) for docs/knowledge/class-idor.md — vulns 2026-07-19
_Review and apply manually; not auto-merged into the KB._

## GUID IDOR amplification via a leaking list endpoint (writeup pattern, added 2026-07-19)
- Recurring 2026 pattern: a UUID/GUID-keyed object reference looks low-severity ("must guess a
  UUID") until a SEPARATE query/endpoint is found that lists or otherwise leaks valid GUIDs
  (search, autocomplete, activity feed, GraphQL list query) — turns it into a fully harvestable
  IDOR chain and materially raises severity/payout.
- Confirms our `recon_idor_candidates.py` scoring (uuid=harvestable) — when ranking, also flag
  pairs: an IDOR-candidate endpoint + any other endpoint on the same host that returns a list of
  IDs of the same shape, since that pairing is the actual high-severity chain.
- Source: https://escape.tech/blog/idor-in-graphql/ , https://infosecwriteups.com/graphql-security-how-i-found-and-exploited-critical-idor-and-authorization-bypass-in-a-42ab78e13642

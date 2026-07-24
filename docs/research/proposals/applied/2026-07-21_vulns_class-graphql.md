# PROPOSAL (proposal) for docs/knowledge/class-graphql.md — vulns 2026-07-21
_Review and apply manually; not auto-merged into the KB._

## Relay global-ID decode/increment/re-encode — dominant GraphQL BOLA pattern (2026-07-21)
Empirical study of 107 classified HackerOne/GitLab/Shopify BOLA disclosures (arXiv 2605.25865)
found the single most common GraphQL object-ref BOLA pattern is: a base64-encoded Relay "global
ID" argument (spec convention `base64("TypeName:12345")`, e.g. `VXNlcjox`) that (1) decodes
cleanly to `Type:<digits>`, (2) the digit component is incrementable, (3) re-encoded and replayed
against another query/mutation. Ranking upgrade for our schema-worklist (`recon_graphql.sh` /
`recon_idor_candidates.py`): when an arg value looks base64 and decodes to `^\w+:\d+$`, score it
ABOVE opaque-UUID object-ref args — it's a near-certain enumerable ref, not just a generic
object-ref signal. Still human-test-only (2 owned accounts), same hard line as before.
Source: https://arxiv.org/html/2605.25865

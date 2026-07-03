# PROPOSAL (proposal) for docs/knowledge/class-graphql.md — tooling 2026-06-20
_Review and apply manually; not auto-merged into the KB._

## Hadrian — systematic BOLA/BFLA role-matrix testing (human-in-the-loop)

When our native schema recovery + `idor_candidates` ranking surfaces a GraphQL IDOR lead and 2 owned accounts are available, **Hadrian** (https://github.com/praetorian-inc/hadrian) can run the full role-pair BOLA matrix instead of hand-crafting curl chains.

**Setup:**
1. Define a YAML role config: role A (account 1 JWT), role B (account 2 JWT), object IDs owned by each.
2. Run against **staging** (never live prod — it sends mutations).
3. Hadrian's 13 GraphQL templates probe cross-role read/write/delete on every object-ref operation in the schema.

**Doctrine constraints:**
- NEVER autonomous: requires auth config + sends mutations = human-in-the-loop only
- Staging preferred; if live: confirm in-scope+pays, only own-account object IDs, confirm-then-stop
- Output is a cross-role violation matrix → operator confirms → report

**When to use:** schema recovered via `recon_graphql.sh` (introspection or clairvoyance-style field recovery) → sensitive object-ref mutation identified in `graphql_candidates_<date>.md` → 2 accounts available → operator runs Hadrian on staging.

**Not for autonomous pipeline.** Add to the 2IC's GraphQL IDOR SOP as the structured proof step.

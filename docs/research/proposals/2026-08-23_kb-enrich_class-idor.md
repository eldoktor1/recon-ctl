# PROPOSAL (proposal) for docs/knowledge/class-idor.md — kb-enrich 2026-08-23
_Review and apply manually; not auto-merged into the KB._

## Disclosed-report technique patterns (added 2026-08-23, from a 250-report dataset)

Complements the existing BOLA taxonomy — these are specific exploitation shapes with exact
payloads, useful for both hunting and honest-severity report framing.

### GraphQL node substitution (8.4% of dataset; 140% growth 2020-22 → 2023-25)
Mutation accepts an object-ref array/id with auth-token check but no ownership check.
Example — Snapchat #1819832 ($15K):
```graphql
mutation DeleteStorySnaps {
  deleteStorySnaps(ids: ["VICTIM_SNAP_ID"], storyType: SPOTLIGHT_STORY)
}

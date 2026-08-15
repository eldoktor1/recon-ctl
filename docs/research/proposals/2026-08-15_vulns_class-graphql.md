# PROPOSAL (proposal) for docs/knowledge/class-graphql.md — vulns 2026-08-15
_Review and apply manually; not auto-merged into the KB._

## GraphQL global-ID (Relay) IDOR pattern — decode/increment/re-encode (added 2026-08-15)
Source: arXiv empirical taxonomy of 100+ disclosed BOLA reports (https://arxiv.org/html/2605.25865),
cross-referenced against H1/GitLab/Shopify disclosures.

Relay-style "global IDs" (base64 blobs like `VXNlcjoxMjM=` decoding to `User:123`) are frequently
mistaken for opaque/unguessable identifiers by developers, who then skip server-side ownership
checks on the assumption that an attacker can't derive a valid ID for another object. In practice:
1. Base64-decode the ID → reveals `TypeName:numericID` (or similar delimited pair).
2. Increment/decrement the numeric component.
3. Re-encode to base64, submit as the `id` arg to a query/mutation that returns/mutates that object.

When our schema-reasoning worklist (`recon_graphql.sh`) sees a `node(id: ID!)` resolver, or any
field/mutation arg typed `ID` whose sample values look like base64, flag it explicitly as an
IDOR-candidate for this decode/increment/re-encode test — human 2-owned-account confirm only,
never auto-probed (same hard line as REST IDOR).

Also worth noting: **GraphQL batching** (multiple queries/mutations in a single POST body) is a
recurring vector for bypassing naive per-request rate limits — relevant to both brute-force and
IDOR-enumeration testing on GraphQL endpoints; test manually, never automate mass enumeration of
third-party IDs.

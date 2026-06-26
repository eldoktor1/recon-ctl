# PROPOSAL (proposal) for docs/knowledge/class-graphql.md — vulns 2026-06-25
_Review and apply manually; not auto-merged into the KB._

## IDOR via Object-Type Argument Confusion ($12,500 payout, 2026)

Pattern validated in fresh disclosed report. The crowd stops at "introspection enabled" (Info dup). The edge:

1. Fetch introspection schema (unauth GET to `/graphql` or `/api/graphql`)
2. Identify mutations/queries with **ID-typed scalar args** on sensitive object types: `userId: ID!`, `accountId: ID!`, `orderId: ID!`, `documentId: ID!`
3. Reason: does the auth check gate on the session's identity or on the inner object's ownership? If the latter is absent → cross-account object access via ID swap
4. Surface as 2-account IDOR LEAD in briefing; confirm = human 2-owned-account swap (never guessed/enumerated third-party IDs)

**ES/jsintel signals:** `/graphql` or `/api/graphql` in endpoints.jsonl with POST method; `Content-Type: application/json` + `{"data":` in response fingerprint.

**Source:** https://infosecwriteups.com/graphql-security-how-i-found-and-exploited-critical-idor-and-authorization-bypass-in-a-42ab78e13642

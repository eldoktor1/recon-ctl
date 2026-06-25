# PROPOSAL (proposal) for docs/knowledge/class-idor.md — kb-enrich 2026-06-24
_Review and apply manually; not auto-merged into the KB._

## New techniques (2024–2025)

### HTTP parameter pollution IDOR bypass
Duplicate the object-ref parameter with two different values in the same request. Application logic
processes the FIRST (victim's id) while the authorization check looks at the SECOND (attacker's id),
resulting in a bypass. Test both query-string (`?userId=VICTIM&userId=ATTACKER`) and JSON body
(`{"userId":"VICTIM","userId":"ATTACKER"}`). Also test URL-encoded body vs JSON body disagreement.

Source: https://0xgaurang.medium.com/case-study-bypassing-idor-via-parameter-pollution-78f7b3f9f59d

### UI / API authorization divergence
A systematic gap: the UI correctly blocks a privileged action (e.g. edit another user's metadata) but
the underlying API endpoint has no server-side authorization check. Pattern from CVE-2024-22278 (Harbor
container registry): `PUT/POST/DELETE /projects/{id}/metadatas/{meta_name}` allowed a Maintainer role
to execute ProjectAdmin-only operations because UI gating was the ONLY layer.

**Hunting approach:** find every UI-blocked action → capture the underlying raw API request → replay it
with a lower-priv session. Any 2xx = authorization delegated to the UI only = IDOR/BAC.

Source: https://unit42.paloaltonetworks.com/bola-vulnerability-impacts-container-registry-harbor/

### WebSocket IDOR
Object-ref IDs in WebSocket / real-time message payloads are almost never tested. Auth checks on the
HTTP upgrade path ≠ auth checks inside WS message handlers. Test: swap the `id` / `resource` fields
in WS frames with another account's known object ID. If the handler processes it without re-checking
the caller's ownership, it is IDOR. Signal to look for: any WS message payload containing an `id`,
`roomId`, `channelId`, `userId`, `orderId`, etc.

### Multi-step purchase-flow IDOR
Purchase → confirmation → receipt flows return an object ID at step N that is consumed at N+1 without
re-validation. Intercept the confirmation/download step and substitute another account's
order/invoice ID. High-severity because it typically exposes financial PII. Also applies to:
subscription renewals, invoice downloads, shipping labels, return authorizations.

### JWT `sub` claim IDOR
Unsubscribe, email-preference, and "my account" endpoints sometimes decode the token's `sub` claim to
derive the target user but do NOT re-check that the claim matches the caller. If the `sub` is a user
ID that the server uses for the action (not just auth), replacing it with another account's ID = IDOR.
Note: this requires a JWT with a manipulable claim (unsigned/algorithm-confusion) OR an endpoint that
takes the user-id separately from auth (e.g. a link-token that embeds the ID but is not signature-bound
to a caller session).

Source: https://ajakcybersecurity.medium.com/exploiting-jwt-token-leads-to-idor-ec48cb8888bb

### Tooling addition
- **BurpAPISecuritySuite** (https://github.com/Teycir/BurpAPISecuritySuite) — 15 attack types including
  BOLA/IDOR detection, 108+ payloads. Complements Autorize for API-focused surfaces.

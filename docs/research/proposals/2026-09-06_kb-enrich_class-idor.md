# PROPOSAL (proposal) for docs/knowledge/class-idor.md — kb-enrich 2026-09-06
_Review and apply manually; not auto-merged into the KB._

## Mass assignment (sibling class — right object ID, wrong writable fields)

Distinct from classic IDOR: the object reference is correctly YOUR OWN, but the server accepts
extra/unexpected fields in the write body it shouldn't. Two testable patterns:

- **Blind-action targets are the highest yield:** endpoints that don't echo the object back
  (password reset, invite-user, notification-settings, webhook config) are where devs most often
  skip strict field whitelisting, since there's no dev-time "surprise field in the response" signal.
  Add candidate privileged fields to the body (`role`, `is_admin`, `is_verified`, `tier`, `credits`,
  `provider`, `type`, or an `id`/`user_id` pointing at your OWN second account/object) even though
  the response won't confirm it — verify via a follow-up authenticated read.
- **Discover the real writable-field set before guessing:** GraphQL introspection on the mutation's
  input type lists every accepted field (including ones the UI hides) — pairs directly with our
  `recon-graphql` lane. OpenAPI/Swagger request schemas do the same for REST. JS-bundle mining
  (`recon-jsintel`) often shows the client constructing a wider object than the form UI exposes.
  Validation-error messages sometimes leak accepted field names for free.
- Own-account-only per our ACTIVE-PoC doctrine — this is authed testing, human-in-the-loop.

Source: [DeepStrike — mass assignment techniques](https://deepstrike.io/blog/mass-assignment-techniques)

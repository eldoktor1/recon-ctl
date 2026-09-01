# PROPOSAL (proposal) for docs/knowledge/class-graphql.md — vulns 2026-08-31
_Review and apply manually; not auto-merged into the KB._

## Bypass note (added 2026-08-31 research digest)

**HTTP introspection-lockdown gap: WebSocket subscription transport.** Disabling introspection over
the HTTP GraphQL endpoint is common hardening, but the GraphQL-over-WebSocket subscription endpoint
(`wss://`/`ws://`, discoverable from JS/jsintel) can sit outside the same middleware stack and still
answer introspection queries — observed pattern via CVE-2026-32594 (Parse Server). If HTTP
introspection is 403/disabled on an in-scope GraphQL host, also try a bare `{__schema{types{name}}}`
over the subscription WS transport if one is discoverable — same read-only primitive as our existing
introspection probe, just a second transport to check before concluding "introspection off."

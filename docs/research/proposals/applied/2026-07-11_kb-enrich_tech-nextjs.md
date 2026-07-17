# PROPOSAL (proposal) for docs/knowledge/tech-nextjs.md — kb-enrich 2026-07-11
_Review and apply manually; not auto-merged into the KB._

## 9. CVE-2026-44578 — WebSocket-upgrade SSRF (unauthenticated, self-hosted only) — added 2026-07-11

Self-hosted Next.js (`next start`, NOT Vercel-hosted) 13.4.13–15.5.15 and 16.0.0–16.2.4 has an
asymmetric safety check in the WS-upgrade proxy path (`router-server.ts`): it validates
`parsedUrl.protocol` but skips the `finished`/`statusCode` routing-approval flags the normal HTTP
path enforces.

**Trigger (unauthenticated, one request):** send an absolute-form request-target with a WS upgrade:

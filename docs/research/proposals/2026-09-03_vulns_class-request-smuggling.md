# PROPOSAL (proposal) for docs/knowledge/class-request-smuggling.md — vulns 2026-09-03
_Review and apply manually; not auto-merged into the KB._

## CVE-2026-48710 "BadHost" — Starlette/FastAPI Host-header path-confusion auth bypass (added 2026-09-03, CISA KEV)
Not classic HTTP request smuggling (no desync between front-end/back-end parsers) — a **single-hop** Host-header
path-confusion bug that behaves like a smuggling-class primitive: the framework re-derives `request.url` by
concatenating the raw `Host` header with the path and re-parsing it without RFC 9112/3986 grammar validation.
Injecting `/`, `?`, or `#` into `Host` shifts what `request.url.path` reports vs. the path actually routed —
so path-based auth middleware checks a forged path while the real (unforged) route executes underneath.

- Affected: Starlette 0.8.3–1.0.0 (FastAPI, vLLM, LiteLLM, MCP servers all ride on Starlette). Fixed 1.0.1.
- Fingerprint: `Server: uvicorn`/`gunicorn` + `/openapi.json`/`/docs` (FastAPI default), or any ASGI app.
- SAFE unauth confirm: find a path that 401/403s normally, resend with a crafted `Host` header embedding
  `/`,`?`,`#` (path-injection into the Host value per the advisory), diff whether protected content is served.
  GET-only, no state change — fits `recon_safe_probe.sh`'s repertoire directly, not just a version-match LEAD.
- Source: https://ostif.org/disclosing-the-badhost-vulnerability-in-starlette/

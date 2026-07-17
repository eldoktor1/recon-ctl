# PROPOSAL (proposal) for docs/knowledge/class-ssrf.md — kb-enrich 2026-07-11
_Review and apply manually; not auto-merged into the KB._

## Absolute-form request-target SSRF — reverse-proxy-into-forward-proxy pattern (added 2026-07-11)

Beyond query-param sinks (`?url=`, `?callback=`, webhook fields), a distinct SSRF class hides in how a
reverse proxy (Nginx/ALB/anything) hands the RAW request-target through to a Node/Express backend. If
the backend does `new URL(req.url)` (or equivalent) without checking for a leading `/`, an
**absolute-form** request line:

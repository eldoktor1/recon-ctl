# PROPOSAL (proposal) for docs/knowledge/class-ssrf.md — kb-enrich 2026-08-15
_Review and apply manually; not auto-merged into the KB._

## Protocol-scheme control as a severity signal, not an exploit path (added 2026-08-15)
If a sink's URL parser accepts non-`http(s)` schemes (`gopher://`, `dict://`, `ftp://`), that's a
blast-radius indicator for severity write-up — a gopher-capable fetcher can drive raw TCP protocols
(Redis command injection, Memcached stats leak, SMTP relay) against internal services, not just fetch
a URL. **Still never execute this** — our confirm primitive stays the `http(s)` OOB canary ping only;
noting scheme-acceptance is for honest severity framing in the report, same discipline as the IMDSv2
reasoning above.

## GCP metadata header-gate caveat (added 2026-08-15)
Don't assume GCP metadata is always `Metadata-Flavor: Google`-gated — some instances still serve the
legacy `v1beta1` path (`http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token`)
without the header check. When severity-reasoning a confirmed SSRF against a GCP target, diff `v1` vs
`v1beta1` before concluding the header-gate blocks credential access.

## DNS-rebinding tooling for TOCTOU severity confirmation (added 2026-08-15)
For the validate-then-fetch TOCTOU pattern already noted above, concrete tools exist rather than a
custom rebinder: **1u.ms** (public rebinding service, `http://make-<target-ip-dashed>-rebind-127.0.0.1-rr.1u.ms/`)
and NCC Group's **Singularity** (self-hosted). Same OOB-confirm discipline — use for severity
demonstration only after the canary-ping confirm, never as the confirm step itself.

⚠️ Unverified-CVE caution: recent SSRF-writeup searches keep surfacing very specific CVE IDs
(Craft CMS, Next.js, Pandoc) that don't match what's already sourced in this doc and weren't
independently NVD-confirmed. Don't cite a new CVE number here without an NVD lookup.

Sources: vulnsy.com/cheat-sheets/ssrf (secondary aggregator, CVE IDs unverified — treat technique
descriptions as directional, not citation-grade).

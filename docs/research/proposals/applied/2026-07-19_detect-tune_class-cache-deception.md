# PROPOSAL (proposal) for docs/knowledge/class-cache-deception.md — detect-tune 2026-07-19
_Review and apply manually; not auto-merged into the KB._

## Capitalized-Host unkeyed-header poisoning vector (2026-07-19)
Add capitalized `Host` header (`HOST: evil.example`) to the unkeyed-header WCP probe set
alongside `X-Forwarded-Host`/`X-Forwarded-Scheme`/`X-Original-URL`. Root cause: some Varnish
VCL cache-key logic and the header-match logic disagree on header-name case, so a capitalized
variant reaches the origin unkeyed while bypassing a case-sensitive allowlist check. Same
under-our-own-cache-buster safety rule applies — never verify against the shared cache key,
always a unique buster.

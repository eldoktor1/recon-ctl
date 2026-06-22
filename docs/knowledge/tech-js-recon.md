# tech-js-recon — mining JavaScript for the hidden API + secret surface

Reusable tooling/usage for the JS-intelligence vertical (`recon_jsintel.sh`) and on-demand JS mining.
The crowd greps JS for token-shaped strings → ~53% FP noise. AST + source-map reconstruction is how
you pull the surface they miss.

## jsluice (AST extractor) — the core
Tree-sitter AST, not regex → it understands `fetch()/XHR/string-literal` URL context and key shapes.
- **URLs/paths:** `jsluice urls [-R https://host/] file...` → JSONL `{url, method, type, queryParams, bodyParams, filename}`.
  - `type` = `fetch` | `xhr` | `stringLiteral` etc.; `method` present for fetch/XHR (IDOR-ranking signal).
  - `-R <base>` resolves relative paths to absolute (host-associates the endpoint).
  - PROVEN (Bokun bundle, 2026-06-21): jsluice cleanly extracted a full GraphQL/extranet/payouts route
    set that regex grep missed entirely. Always prefer jsluice over regex for JS endpoints.
- **Secrets:** `jsluice secrets file...` → JSONL `{kind, data:{key}, severity, filename, context}`.
  - AST-context catches custom/internal key shapes trufflehog has no detector for.
  - These are **candidate LEADs, UNVERIFIED** → review store `~/recon/js_recon/secret_leads.jsonl`, capped,
    NEVER auto-confirmed (don't reopen the 53%-FP token-noise trap). trufflehog stays the CONFIRMED path.
- Other modes: `tree` (AST dump), `query` (tree-sitter query), `format` (beautify). `-c N` concurrency.

## sourcemapper (source-map reconstruction) — the surface multiplier
A leaked `.map` is the ORIGINAL un-minified source (full var names, comments, dev-only routes/keys) —
a far richer surface the crowd never un-maps.
- `sourcemapper -jsurl https://host/app.js -output <dir>` → auto-discovers `sourceMappingURL`, fetches the
  map, writes the reconstructed source tree. (`-url <map-url>` if you already have the map URL; `-output` REQUIRED.)
- In the pipeline: only fired when the bundle advertises an **EXTERNAL** `sourceMappingURL` (skip inline
  `data:` maps); reconstructed files are folded into the jsluice urls/secrets + trufflehog passes.
- PROVEN: an endpoint (`/v1/superuser`) present ONLY in the reconstructed tree, absent from the shipped
  bundle. Source maps routinely leak admin/internal routes + dev keys.
- Fingerprint a live `.map`: `curl -s https://host/app.js | grep -aoiE 'sourcemappingurl=[^ ]+'` then fetch
  that path (often `.js.map`, sometimes a separate dir). `.map` 200 = un-mappable.

## trufflehog (LIVE verification) — the CONFIRMED secret path
`trufflehog filesystem <dir> --only-verified --json --no-update` — authenticates the leaked key against the
provider; a `verified:true` hit IS the PoC (never a data harvest). Scan the WHOLE workdir so reconstructed
source-map output is covered, not just raw bundles. Verified secret → SQLite → Claude verify → #review.

## noseyparker — EVALUATED, not wired into jsintel
Fast Rust bulk secret scanner (`noseyparker scan --datastore <ds> <paths>` → `report -d <ds> --format json`).
Verdict: for jsintel, jsluice-secrets (AST candidates) + trufflehog (verified) already cover it — adding a
third overlapping scanner = bloat. noseyparker's edge is **bulk corpora + Git history**, so it belongs in the
`recon_ghleaks` lane (large repo/history sweeps), not per-host JS. Left available, not wired here.

## xnLinkFinder — available fallback
Endpoint/param extractor (xnl-h4ck3r). jsluice covers JS URL extraction better (AST); keep xnLinkFinder as a
fallback for non-JS / burp-history / waymore-corpus link extraction if a gap shows up.

## Doctrine
Target-facing (fetches public JS) → runs as d0k, VPN-gated, scope+pays-gated, bounded (JS_PER_HOST,
JS_MAXBYTES), freshest-first. Source-map fetch is same-host (scope already gated). Endpoints feed the
IDOR/logic worklist (`recon_idor_candidates.py`); secrets split CONFIRMED (trufflehog) vs LEAD (jsluice).

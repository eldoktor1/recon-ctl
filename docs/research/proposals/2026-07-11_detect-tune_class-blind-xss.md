# PROPOSAL (proposal) for docs/knowledge/class-blind-xss.md — detect-tune 2026-07-11
_Review and apply manually; not auto-merged into the KB._

## Dalfox v3 (Rust rewrite) — precision update, 2026-07-11
v3.0.0 (2026-05-25) is a full Rust rewrite with AST-backed DOM verification (fewer FPs from
blind reflections, our EXECUTION-only confirm gate benefits directly). v3.1.1 demoted inert
`javascript:`/URL-scheme self-link reflections (a known FP class) and restored recall for
reflected XSS inside raw-JS-expression / regex-literal contexts. Action: verify the confirm
harness runs dalfox >=3.1.1; older versions both miss some real raw-JS-context reflections and
mis-flag inert javascript: self-links as hits.

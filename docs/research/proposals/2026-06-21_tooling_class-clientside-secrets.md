# PROPOSAL (proposal) for docs/knowledge/class-clientside-secrets.md — tooling 2026-06-21
_Review and apply manually; not auto-merged into the KB._

## Tool note: jsluice (BishopFox) — AST-aware JS endpoint + secret extractor

**Repo:** https://github.com/BishopFox/jsluice  
**Added:** 2026-06-21  

### What it adds over regex-based extraction
- Parses JavaScript AST rather than running regex over raw text
- Extracts URLs/paths embedded in: template literals, nested object keys, computed property names, minified variable chains
- Outputs structured JSON; designed for pipeline integration (`jsluice urls <file.js>`)
- Also has a `secrets` subcommand that finds hardcoded secrets — complementary to trufflehog (different detection strategy, not a replacement)

### Integration pattern
Run as a *second pass* after existing regex extractor in `recon_jsintel.sh`. Deduplicate by URL path template before feeding `endpoints.jsonl`. Expected gain: deeper endpoint yield from complex/minified JS that regex misses.

### Safety
Static analysis only — reads already-fetched JS files, zero new target traffic.

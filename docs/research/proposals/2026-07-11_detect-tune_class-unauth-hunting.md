# PROPOSAL (proposal) for docs/knowledge/class-unauth-hunting.md — detect-tune 2026-07-11
_Review and apply manually; not auto-merged into the KB._

## Favicon-hash dork as a cheap uncover-lane addition, 2026-07-11
Add `http.favicon.hash:<mmh3(base64(favicon))>` as another scoped dork template in the
`recon_uncover.sh` Shodan/Censys pass (same in-scope-cert/root scoping + credit-budget
discipline as existing dorks) — surfaces shared-favicon infra (staging/internal/forgotten hosts)
that CT/subfinder enumeration misses. Treat a hash match as an ENUMERATION CANDIDATE only
(resolve → in-scope check → normal validator queue), never as standalone identity confirmation —
favicons are trivially swapped/collide.

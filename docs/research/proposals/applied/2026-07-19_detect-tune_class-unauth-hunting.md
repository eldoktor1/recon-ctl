# PROPOSAL (proposal) for docs/knowledge/class-unauth-hunting.md — detect-tune 2026-07-19
_Review and apply manually; not auto-merged into the KB._

## Favicon-hash Shodan dork — sibling-infra widener (2026-07-19)
For a confirmed in-scope host with a CUSTOM (non-stock-framework) favicon: compute mmh3(base64(
favicon bytes)) and run ONE Shodan query `http.favicon.hash:<hash>` (counts against the existing
hard monthly budget in [[reference_api_credit_budget]]) to surface sibling hosts sharing the
same branded favicon — catches staging/internal/forgotten infra CT/permutation miss. SKIP when
the favicon is a stock CMS/framework default (WordPress, generic Nginx welcome, etc.) — the hash
will match thousands of unrelated sites and just burns budget for noise. Every resulting host
still goes through the normal resolve → scope+pays gate before touching the validator queue.

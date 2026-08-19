# PROPOSAL (proposal) for docs/knowledge/class-graphql.md — detect-tune 2026-08-18
_Review and apply manually; not auto-merged into the KB._

## Introspection-block bypasses to try BEFORE the Clairvoyance suggestion fallback (added 2026-08-18)
When a target returns "introspection disabled", try these two cheap read-only bypasses first —
both are still introspection, not exploitation, and fit the existing safe-probe gate:
1. **Newline-in-token regex evasion**: many blockers regex-match the literal `__schema`/`__type`
   string in the raw body; GraphQL's lexer ignores whitespace/newlines/commas between tokens, so
   `__sch\nema` (or a comma) parses identically but slips the filter. Try one variant before
   falling back to the slow Clairvoyance near-miss harvest.
2. **Inline-fragment nesting (CVE-2026-30854 pattern, seen in Parse Server)**: a `__type` query
   nested inside an inline fragment (`... on Query { __type(name:"X"){name fields{name}} }`) has
   bypassed `disableIntrospection` even when correctly configured on some GraphQL server
   implementations — worth a single-shot try per host.
Both remain LEAD-tier reconnaissance (schema disclosure), not a finding on their own — same
"introspection enabled ≠ payable" rule already in the KB.
Sources: https://x.com/0xacb/status/2022643073855951103, https://advisories.gitlab.com/pkg/npm/parse-server/CVE-2026-30854

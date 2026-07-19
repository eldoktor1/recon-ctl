# PROPOSAL (proposal) for docs/knowledge/class-graphql.md — detect-tune 2026-07-19
_Review and apply manually; not auto-merged into the KB._

## Introspection-disabled bypass ladder (2026-07-19)
When the standard `{__schema{...}}` query is blocked, try these BEFORE falling back to full
Clairvoyance suggestion-mining (all still read-only, no mutations, safe):
1. **Whitespace-mangled query**: insert a harmless newline/comma inside the field name
   (`__sch\nema`, `__typ,e`) — GraphQL parsers ignore this, naive regex blocklists on the raw
   query string don't. If it parses and returns schema data, the "introspection disabled" is
   actually just a string-match gate, not real enforcement.
2. **Inline-fragment nesting**: wrap `__type`/`__schema` inside an inline fragment
   (`{ __typename ... on Query { __type(name:"User"){name fields{name type{name}}} } }`).
   Shallow top-level-only introspection blockers miss fields nested this way.
   Reference: CVE-2026-30854 (Parse Server), CVE-2026-35413 (Directus) — both real-world
   instances of exactly this bypass pattern, still being found in 2026.
3. **Alternate schema-exposing resolvers**: some frameworks ship a secondary endpoint/query
   that returns SDL-equivalent info even with standard introspection off (naming pattern seen:
   `*specs*graphql`, `*schema*`, admin/system namespace queries). Worth a quick probe of any
   non-standard query names surfaced by field-suggestion mining.
4. Only THEN fall back to full suggestion-mining (near-miss field-name harvesting) — it's the
   most request-heavy option, use it last.
All three are still schema-DISCLOSURE, not exploitation — same LEAD tier as standard
introspection-enabled; do not upgrade severity, just widens what we can enumerate before
handing a human the ranked mutation/IDOR worklist.

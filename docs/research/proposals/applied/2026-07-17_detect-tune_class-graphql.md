# PROPOSAL (proposal) for docs/knowledge/class-graphql.md — detect-tune 2026-07-17
_Review and apply manually; not auto-merged into the KB._

## Suggestion-blocking is not the same as introspection-off, 2026-07-17
Apollo Server v4+ ships `hideSchemaDetailsFromClientErrors` / `blockFieldSuggestions`, which suppresses the
"did you mean 'field'?" hint our Clairvoyance-style recovery relies on — independently of whether
introspection itself is disabled. **FP guard:** a target returning zero field suggestions to typo'd-field
probes is NOT confirmed-locked-down; it may only mean suggestions are blocked while other schema leakage
(verbose error codes/types, timing on valid vs invalid field names) persists. Before marking a GraphQL host
"schema recovery failed / skip", also check raw error-message verbosity on a deliberately malformed query —
a still-verbose error page on an otherwise suggestion-silent endpoint means the hardening is partial, not
complete, and is itself worth a note.

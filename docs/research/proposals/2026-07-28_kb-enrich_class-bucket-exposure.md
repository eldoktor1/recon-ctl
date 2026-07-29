# PROPOSAL (proposal) for docs/knowledge/class-bucket-exposure.md — kb-enrich 2026-07-28
_Review and apply manually; not auto-merged into the KB._

## Azure — anonymous container listing is possible, level-dependent (correction, 2026-07-28)

Correction to the "Azure can't enumerate containers anonymously" line above: that's only true at the
**Blob** public-access level (anonymous read of a blob you already know the name of, but no listing).
At the **Container** public-access level, anonymous clients CAN enumerate the full object list. Manual
check for any `*.blob.core.windows.net` host mined via Lane A:

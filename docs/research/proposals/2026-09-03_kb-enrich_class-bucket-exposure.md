# PROPOSAL (proposal) for docs/knowledge/class-bucket-exposure.md — kb-enrich 2026-09-03
_Review and apply manually; not auto-merged into the KB._

### GCS-specific enumeration + confirm primitives (added 2026-09-03)

S3Scanner (our current backend) does not test GCS anonymous permissions correctly — its GCS provider
only checks bucket existence, not `allUsers` grants. Until/unless we add a GCS-native scanner path, use
these primitives manually on any `storage.googleapis.com` / `.storage.googleapis.com` ref surfaced by
Lane A (target-reference mining):

**Unauthenticated permission-test (preferred — answers exactly what's granted, no trial-and-error):**

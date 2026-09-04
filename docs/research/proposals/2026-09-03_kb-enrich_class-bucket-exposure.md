# PROPOSAL (proposal) for docs/knowledge/class-bucket-exposure.md — kb-enrich 2026-09-03
_Review and apply manually; not auto-merged into the KB._

---
### Applied research — Azure Blob manual lane + GCS legacy-ACL gap (2026-09-03)

## Azure Blob Storage — manual anonymous-read lane (S3Scanner has NO Azure support)
Our doc previously noted Azure as "manual, no S3Scanner support" with no concrete test. It's a plain
unauthenticated REST call — add it to Lane A whenever a target JS/HTML references
`*.blob.core.windows.net`:

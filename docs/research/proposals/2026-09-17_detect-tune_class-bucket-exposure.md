# PROPOSAL (proposal) for docs/knowledge/class-bucket-exposure.md — detect-tune 2026-09-17
_Review and apply manually; not auto-merged into the KB._

## Multi-cloud extension gap — Azure Blob + GCS (open, not yet built)

Current lane is S3Scanner-only (AWS). The provenance doctrine (mine bucket/container refs from the
target's own JS-intel/params surface, never blind-permute, in-scope+pays gate before probing) generalizes
directly to the other two major object-storage providers, and the JS-intel feed already captures these URLs
in-band — just not currently routed anywhere:
- **Azure Blob**: `*.blob.core.windows.net/<container>` — unauth `GET <url>?restype=container&comp=list`
  succeeds (200 + XML blob listing) only on "Full public read" (container-level) access; "Blob" level access
  allows direct object GET by known name but not listing. Distinguish the two the same way we distinguish
  S3 public-read vs 403: a successful `comp=list` = public-READ (LEAD pending content sensitivity, same as
  S3); a 404/`PublicAccessNotPermitted` on `comp=list` but a 200 on a provenance-known object path = blob-level
  read only (weaker signal, still worth noting).
- **GCS**: `*.storage.googleapis.com/<bucket>` or `storage.googleapis.com/storage/v1/b/<bucket>/o` — unauth
  `GET` on the JSON API listing endpoint or XML `?list-type=2` reveals public-read the same way.
- Same mint gates apply: public-WRITE/ACL-write → CONFIRMED → verify → #review; public-READ → LEAD pending
  content-sensitivity triage; provenance REQUIRED to mint (global namespace, name match ≠ ownership).

Sources: github.com/Macmod/goblob, microsoft.com/en-us/security/blog/2025/10/20/inside-the-attack-chain-threat-activity-targeting-azure-blob-storage

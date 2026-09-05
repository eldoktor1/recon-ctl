# PROPOSAL (proposal) for docs/knowledge/class-bucket-exposure.md — detect-tune 2026-09-04
_Review and apply manually; not auto-merged into the KB._

## GCS backend (2026 addition — we were S3-only despite GCP being a top in-scope tech)

Same provenance-seeded doctrine as S3: mine bucket refs from the target's OWN surface
(jsintel endpoints, JS strings, params catalog referencing `storage.googleapis.com`,
`storage.cloud.google.com`, or `<bucket>.storage.googleapis.com`) — never blind-permute
GCS bucket names (the namespace is global, same third-party-data risk as S3).

**Unauthenticated read/list checks (anonymous GET, no service account):**
- `GET https://www.googleapis.com/storage/v1/b/<BUCKET>/o` → 200 + object listing =
  public-read confirmed (an `allUsers` IAM binding or legacy ACL grants it). 403
  `PERMISSION_DENIED` = secure/normal state — same discipline as S3's 403≠finding.
- `GET https://storage.googleapis.com/<BUCKET>/<object>` → legacy XML-API anonymous
  object fetch, mirrors our existing S3 anonymous-GET primitive.
- Severity distinction: `allUsers` (internet-public) vs `allAuthenticatedUsers`
  (any Google-account holder, not internet-anonymous) — label/score these differently,
  same as we already separate S3 public-read from public-write.
- Reference-only tool (technique validation, not a source of candidates):
  GCPBucketBrute (RhinoSecurityLabs) — enumerates anonymous-first, matching our own order.

Object-triage after a confirmed public-read follows the SAME `recon_bucket_loot.py`
pipeline as S3 (`.env`/tfstate/private-keys/source-maps → credentials via `engine/impact.py`)
— no new triage logic needed, just a new discovery backend feeding the same pipeline.
Source: RhinoSecurityLabs GCPBucketBrute docs, 2026-09.

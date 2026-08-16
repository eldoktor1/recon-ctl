# PROPOSAL (proposal) for docs/knowledge/class-idor.md — kb-enrich 2026-08-15
_Review and apply manually; not auto-merged into the KB._

## Presigned-URL generation endpoint as an object-ref IDOR surface (added 2026-08-15)

Distinct from the "where the id hides" swap-the-session-object pattern already in this doc: the
**endpoint that MINTS a presigned S3/GCS URL** is itself an authz-critical resolver, and it's rarely
tested as one — the crowd tests the resulting signed URL's expiry, not whether the server should have
signed THAT key for THIS caller at all.

### The test
1. Find any endpoint returning a presigned URL (`getObject`/`get-pre-signed-url`/`generate-upload-url`/
   `s3_key`/`document`/`filePath` params — grep jsintel endpoints for `presign`/`s3`/`signed-url`).
2. As account A, capture the request; note the object-key parameter (often sequential/predictable:
   `pdfs/<userId>/receipt.pdf`, `uploads/<accountId>/...`).
3. Swap the key to account B's (owned) path — e.g. `pdfs/124/receipt.pdf` — while authenticated as A.
   **If the server signs a URL for B's object without checking A owns that key = IDOR.** (Real case:
   $20k payout, S3 bucket misconfig of presigned URLs leaking all users' attachments.)
4. Root-path / empty-parameter probes (safe, read-only, worth trying before the swap):
   - `key=/` or `filePath=/` → some implementations return a signed URL to the BUCKET ROOT →
     `ListBucketResult` (full object enumeration) instead of one file.
   - `bucketName=` / `objectKey=` (empty) → some signing wrappers fall back to listing all buckets
     (`ListAllMyBucketsResult`) or a default/wrong bucket.
   - Path traversal in a custom (non-AWS-SDK) signing wrapper: `?key=../../../` — malformed input to a
     regex-based key extractor can normalize to the bucket root and sign a listing URL. Also try URL-
     confusing input like `{"url":"https://.x./example-bucket"}` against custom URL-parsing signers.
   These are provenance-confirmed the moment they return bucket-listing content instead of a 403/404 —
   no swap needed, straight LEAD→CONFIRMED on read-only probe.

### POST-policy condition fuzzing (upload direction — presigned POST, not GET)
When the app hands back a presigned **POST** (browser-direct-upload pattern: `url` + `fields` incl.
`policy`/`signature`), the policy document's conditions are client-visible (base64 in the `policy`
field) and worth decoding + testing for bypass, independent of the IDOR angle above:
- `["starts-with","$key",""]` (empty prefix) → key is fully attacker-controlled → can overwrite ANY
  object in the bucket the policy is scoped to, not just upload to your own prefix.
- `["starts-with","$key","acc_123"]` **without a trailing path separator** → attacker can still write
  to `acc_123evil.html` etc. at the bucket root (sibling-prefix collision), not truly scoped to a subdir.
- `["starts-with","$Content-Type","image/jpeg"]` bypass: send
  `Content-Type: image/jpegz;text/html` — starts-with matches the substring, but browsers/CDNs serving
  the object may render it as HTML → stored XSS on the bucket's origin if the bucket serves uploads
  with `Content-Disposition: inline`.
- `["starts-with","$Content-Type",""]` (unrestricted) → upload raw HTML, same stored-XSS chain if the
  object is public-read + inline.
- Vendor implementation bugs also happen at the framework level, not just app misconfig: CVE-2026-27607
  (RustFS) shipped a presigned-POST implementation that didn't validate policy conditions AT ALL server-
  side — `content-length-range`/`starts-with`/`Content-Type` were client-side-only, so ANY key/size/type
  was accepted regardless of the stated policy. Worth a version check on any self-hosted S3-compatible
  object-storage backend (MinIO, RustFS, SeaweedFS, Garage) fingerprinted in-scope.

### Scoring / FP notes
- A presigned GET/PUT scoped to the caller's own account-prefix with a real server-side ownership check
  before signing = clean (mirrors the existing "tenant-isolation enforced" FP entry in this doc).
- Short expiry (`X-Amz-Expires=60`) is NOT a mitigating factor for the IDOR angle — the swap works the
  instant the URL is minted, expiry only bounds a *stolen* URL's replay window.
- Confirm PoC = one redacted object read via the swapped presigned URL, or a decoded-policy screenshot
  showing the unrestricted condition + one benign own-account upload proving it — never bulk-enumerate
  or overwrite a third party's object (same discipline as every other IDOR primitive in this doc).

Sources:
- https://research.ivision.com/signed-sealed-delivered-secure.html (object-key IDOR, root-path listing, empty-param enumeration — concrete payloads)
- https://labs.detectify.com/writeups/bypassing-and-exploiting-bucket-upload-policies-and-signed-urls/ (POST-policy condition bypasses, Content-Type substring trick, path-traversal/URL-confusion signing-wrapper bugs)
- https://www.bugbountyexplained.com/my-20000-s3-bug-that-leaked-everyones-attachments-s3-bucket-misconfig-of-pre-signed-urls/ ($20k real-world payout, sequential-key IDOR)
- https://osv.dev/vulnerability/CVE-2026-27607 (RustFS presigned-POST policy-validation bypass — verify current patch status before citing in a report)

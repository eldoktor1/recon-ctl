# PROPOSAL (proposal) for docs/knowledge/class-takeover.md — detect-tune 2026-08-29
_Review and apply manually; not auto-merged into the KB._

## S3 claimability primitive — account-regional-namespace exclusion (added 2026-08-29)
The S3 `NoSuchBucket` claimability primitive (this doc's "AWS S3" provider row) now has an
exception: since 2026-03-12 AWS supports account-regional-namespace buckets, named
`{{prefix}}-{{12-digit-account-id}}-{{region}}-an`. These are reserved to the creating account
PERMANENTLY — deletion does not free the name for anyone else. A `NoSuchBucket` response for a
name matching `-\d{12}-[a-z-]+-an$` is therefore NOT claimable and must not be scored as
`confirmed` (add to GATE B/C-style exclusion alongside the existing Azure `checkNameAvailability`
reserved-name check). Suffix-less bucket names are unaffected — the original primitive still holds.
Source: https://docs.aws.amazon.com/AmazonS3/latest/userguide/gpbucketnamespaces.html

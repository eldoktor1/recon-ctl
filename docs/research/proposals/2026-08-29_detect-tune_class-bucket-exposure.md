# PROPOSAL (proposal) for docs/knowledge/class-bucket-exposure.md — detect-tune 2026-08-29
_Review and apply manually; not auto-merged into the KB._

## S3 account-regional-namespace buckets (added 2026-08-29) — NoSuchBucket claimability caveat
AWS GA'd account-regional namespaces for general-purpose buckets 2026-03-12. A bucket name ending
in `-<12-digit-account-id>-<region-code>-an` (e.g. `mybucket-012345678910-us-west-1-an`) lives in
the CREATING ACCOUNT's reserved namespace: even after deletion, **no other account can ever
re-create that exact name** — `NoSuchBucket` on such a name is NOT a claimability signal, unlike
the classic global namespace where `NoSuchBucket`/`BucketAlreadyExists`-cleared = free-for-anyone.
**Rule:** before treating a `NoSuchBucket` hit as a takeover/squat candidate, regex-check the
bucket name for the `-\d{12}-[a-z-]+-an$` suffix — if it matches, drop (permanently unclaimable
by us); only suffix-less (classic global-namespace) names remain valid takeover candidates.
Source: https://docs.aws.amazon.com/AmazonS3/latest/userguide/gpbucketnamespaces.html

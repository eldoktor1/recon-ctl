# Research digest — detect-tune — 2026-08-29

# Research digest — detect-tune — 2026-08-29 (pass 3)

## 1. AWS S3 account-regional-namespace buckets (GA March 2026) — new suffix pattern makes `NoSuchBucket` **NON-claimable** for a large and growing class of names (HIGH PRIORITY — directly tunes `recon_bucket_scanner.sh` + the takeover lane's S3 primitive)

**What changed:** AWS rolled out account-regional namespaces for general-purpose S3 buckets on 2026-03-12. A bucket created in this namespace is reserved to the creating AWS account **forever** — "deleted account regional names can't be claimed by another account and remain reserved for your use." This is the *opposite* of the classic global-namespace behavior our `NoSuchBucket` claimability primitive relies on (`class-bucket-exposure.md` / `class-takeover.md`: "NoSuchBucket = name free = claimable").

**The fingerprint (definitive, regex-matchable):** account-regional bucket names have a mandatory, structurally fixed suffix:
```
{{prefix}}-{{12-digit-AWS-account-id}}-{{aws-region-code}}-an
```
e.g. `amzn-s3-demo-bucket-012345678910-us-west-1-an`, `mybucket-987654321012-eu-north-1-an`. Regex: `-\d{12}-[a-z]{2}(-gov)?-[a-z]+-\d-an$` (region code like `us-west-2`, `ap-southeast-1`, `eu-north-1`).

**Actionable:** when `recon_bucket_scanner.sh` / `recon_bucket_loot.py` observes a `NoSuchBucket` response for a bucket name matching this suffix pattern, it is **NOT claimable** — the name is permanently reserved to that AWS account even after deletion. Do NOT surface it as a takeover/squat candidate; drop silently (this is a pure precision gain, prevents a wasted claim attempt or a false LEAD). Names *without* this suffix keep the existing global-namespace behavior (`NoSuchBucket` = genuinely free = still the valid claimability primitive). This also matters for provenance-seeded bucket mining (`--provenance` requirement in our doctrine): a JS/CDX reference to an `-an`-suffixed bucket name is now itself a strong signal the bucket belongs to a specific, identifiable AWS account (the account ID is literally embedded in the name) — useful context but does not change the public-read/public-write triage.
- Source: [AWS docs — Namespaces for general purpose buckets](https://docs.aws.amazon.com/AmazonS3/latest/userguide/gpbucketnamespaces.html), [AWS What's New, 2026-03](https://aws.amazon.com/about-aws/whats-new/2026/03/amazon-s3-account-regional-namespaces)





## 2. CloudFront-to-S3 dangling-origin fingerprint is dead since late 2023 — our KB is already correctly hardened, confirming no drift needed
Checked this against our current `class-takeover.md`: the historical CloudFront→S3 takeover fingerprint (CloudFront returning a `NoSuchBucket` XML body that discloses the deleted bucket name, letting an attacker recreate it under their own account) was killed by AWS in late 2023 — CloudFront now returns a generic `NotFound` with no bucket name disclosed. Our KB already lists `aws_cloudfront` in `TKO_NOTVULN`/"impossible" — **no change needed, this confirms our existing gating is current, not stale.** Noting so this doesn't get re-investigated as a gap. (No kb-proposal — verifying existing doctrine, not new content.)
- Source: [hackingthe.cloud — Orphaned CloudFront/DNS takeover via S3](https://hackingthe.cloud/aws/exploitation/orphaned_cloudfront_or_dns_takeover_via_s3/)

## Skipped as not actionable this run
- Apache HTTP Server: no 2026 CVEs surfaced in-range (search only returned 2022-2024 CVEs already patched long ago on any live host worth targeting).
- Cloudflare Bot Management bypass techniques: all sources are scraping-evasion guides aimed at defeating anti-bot for scraping, not a detection/confirm-primitive improvement — and per `feedback_403bypasser_waf_ban`, WAF-bypass tooling is a banned lane (trips exit-IP bans). Not applied.
- IDOR/BOLA automated false-positive tuning research (2026): confirms the structural limitation we already design around (request-level scanning can't know ownership) — validates our reasoning-only ranking + human-2-account-confirm approach, but no new concrete fingerprint/technique to add.

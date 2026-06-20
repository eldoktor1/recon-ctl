# class-bucket-exposure — open / misconfigured cloud storage (S3, GCS, DO Spaces, …)

Reusable knowledge for the cloud-bucket lane (`recon_bucket_scanner.sh`, backend = S3Scanner
sa7mon v3). Built 2026-06-20 from source-grounded research (S3Scanner source + top-hunter
writeups). READ before hunting buckets; APPEND when you learn something reusable.

## The one rule everything reduces to
**The open state is NOT the bug.** Severity = **(permission level) × (content sensitivity /
demonstrated impact)**, gated by **in-scope + pays + not-by-design + provenance-confirmed**.
This maps onto CONFIRMED-vs-LEAD: a *permission grant* is a LEAD; the *primitive firing on
provenance-confirmed, sensitive, in-scope content* (or any public WRITE) is CONFIRMED.

## Severity ladder (what's payable vs N/A noise)
| Rung | Primitive (S3 ACL / IAM) | Severity | Payable only if… |
|------|--------------------------|----------|------------------|
| Public-read **static/CDN/marketing** bucket | AllUsers READ (`s3:ListBucket`) | **N/A–Low / Informative** | content is sensitive — else **by-design, close N/A** |
| Public-read **sensitive** content | READ + PII/creds/source/backups | **Medium→Critical** (P1 if secrets) | content sensitivity proven, target-owned |
| **Public/Auth WRITE** | `s3:PutObject` | **High** | demonstrate ONE benign upload; never destroy |
| READ_ACP (ACL world-readable) | `s3:GetBucketAcl` | **Medium-High** | recon/chain step; also leaks the full grant list |
| **WRITE_ACP / FULL_CONTROL** | `s3:PutBucketAcl` | **Critical** | confirmed ACL-write = bucket takeover |
| NoSuchBucket but referenced by live target JS | (re)register the name | **Medium→High** | confirm `NoSuchBucket` + claimable → route to takeover lane |

Two dangerous grant groups (flaws.cloud lesson): `AllUsers` = anyone on earth; **`AuthenticatedUsers`
= ANY AWS account holder** (operators mistake this for "my org's users" — AWS's own words: "any AWS
authenticated user in the world"). S3Scanner's `perm_auth_users_*` only populate when AWS creds are
configured; we run anonymous, so they stay `unknown(2)` — that's expected.

### Disclosed-report severity anchors (calibrate, don't overclaim)
- H1 #819278 Greenhouse — open bucket, marketing assets → **Low / $100** (non-sensitive content).
- H1 #209223 Ruby — `rubyci` bucket writable by any AWS user → **High** (CI integrity/availability).
- H1 #2262939 rubygems/IBB — CloudFront caching from unclaimed S3 origin → **Medium** (cached XSS/supply-chain).
- H1 #1474017 Omise — CDN bucket → **Info / $100**. H1 #1062803 DoD — real sensitive data but **$0 (VDP)** → reinforces the per-asset `pays` gate.
- Bugcrowd VRT: "Disclosure of Secrets → Publicly Accessible Asset" = **P1**; "Publicly Accessible Cloud Storage" = **null/contextual** (content-driven).

## Why PUBLIC-WRITE is high/critical (operator: report ALL of these)
A writable bucket enables *active compromise*, not just disclosure: overwrite a served `.js`/`.css`
→ **stored XSS / supply-chain in the trusted origin**; host malware/phishing under the legit domain;
without versioning, overwrites are **irrecoverable**. In-the-wild: the npm `bignum` attack re-registered
a deleted dependency bucket and served malicious binaries to every install.

**SAFE write CONFIRMATION (no object created — Detectify invalid-Content-MD5 trick):** send an anonymous
`PutObject` with a deliberately invalid `Content-MD5`. AWS checks the checksum AFTER the access check
but BEFORE writing — so `AccessDenied` = not writable, checksum/`BadDigest` error = writable with
**nothing written**. This is our `recon-buckets writecheck` primitive (AWS only — the order is verified
for S3, not other providers). It's a PUT *method* but zero state-change; kept **operator-on-demand**, not
in the unattended GET-only loop.

**The accepted human PoC (operator-run, prove-impact):** `aws s3 cp poc.txt s3://BUCKET/poc-<uuid>.txt
--no-sign-request` with a UNIQUE random key → screenshot success + read it back → `aws s3 rm …
--no-sign-request` (cleanup MANDATORY). HARD LINE: never overwrite an existing key, never deface
served assets, never upload malware/phishing, never WRITE_ACP-lock-out the owner.

## Impact demonstration WITHOUT harvesting (recon-vs-attack line)
Evidence that triages well, lowest-risk first — all with `--no-sign-request` (anonymous):
1. **Listing XML** — `aws s3 ls s3://BUCKET --no-sign-request` → a `<ListBucketResult>` 200 IS the evidence.
2. **ACL JSON** — `aws s3api get-bucket-acl --bucket BUCKET --no-sign-request` → the AllUsers/AuthenticatedUsers grant block (non-data evidence).
3. **Redacted screenshot of object KEYS** (file *names* can themselves signal sensitivity: `users.csv`, `db-backup.sql`).
4. **Region** — from `x-amz-bucket-region`.
NEVER download PII/contents — the PoC is "this lists/returns/writes without auth," not a dump.

## S3 error-code semantics (the FP table)
| Response | Code | Meaning |
|----------|------|---------|
| 200 + `<ListBucketResult>` | — | **REAL hit** (public list) → CONFIRMED primitive |
| 404 | `NoSuchBucket` | name unregistered → **takeover lane** (only if a live target ref/CNAME points here) |
| 403 | `AccessDenied` | exists but secure — **FP** (the normal hardened state) |
| 403 | `AllAccessDisabled` | AWS-disabled (abuse/billing) — **FP, not reportable** |
| 400 | `InvalidBucketName` | malformed candidate — wordlist artifact |
| 409 | `BucketAlreadyExists` | name globally taken (shared namespace) |
| 301/307 | `Permanent/TemporaryRedirect` | wrong region — **re-query, don't discard** |
| 503 | `SlowDown` | rate-limit, not a result — back off |

**403-vs-404 nuance:** whether a *missing object* returns 403 or 404 depends on whether you hold
`s3:ListBucket` (AWS does this deliberately to defeat recon). **A 403 alone is never a confirmed
misconfiguration.** S3Scanner JSON encodes this as `perm_*` = `1`(allowed)/`0`(denied)/`2`(unknown).

## Provenance gate (MANDATORY — hard line, not just an FP)
The S3 namespace is **global** — `acme-backups` could be anyone's. **A name-only match may be a third
party's data; testing it crosses the hard line.** Confirm the bucket BELONGS to the in-scope target:
(a) it is referenced from the target's own site/JS/source-maps/HTTP headers/DNS; (b) `site:example.com
"bucketname"`; (c) file names/content unambiguously match the org. **Our scanner seeds ONLY from
target-referenced names (Lane A) — never blind permutation — so provenance is inherent.**

## Seeding lanes (where the UNIQUE edge is)
- **Lane A — target-reference mining (UNIQUE, low-dup; our default):** grep the target's own JS,
  source-maps, HTML, HTTP responses for bucket refs. Patterns (gf `s3-buckets`, the missing-`+` issue #23 fixed):
  `[a-z0-9.-]+\.s3[.-][a-z0-9-]*\.amazonaws\.com`, `s3[.-][a-z0-9-]*\.amazonaws\.com/[a-z0-9._-]+`,
  `[a-z0-9._-]+\.storage\.googleapis\.com` / `storage\.googleapis\.com/[a-z0-9._-]+`,
  `[a-z0-9.-]+\.digitaloceanspaces\.com`, `[a-z0-9]+\.blob\.core\.windows\.net` (Azure = manual, no S3Scanner support).
  S3-backed hosts also flagged by headers `Server: AmazonS3`, `x-amz-bucket-region`, `x-amz-request-id`.
  Highest-value sub-class: a **dangling/unclaimed bucket still referenced by live production JS** → register → supply-chain.
- **Lane B — CT-log/certstream freshness (medium dup):** permute names of newly-issued certs (bucket-stream idea). Race the crowd. (Future feeder.)
- **Lane C — blind permutation + GrayhatWarfare (SATURATED, high-dup — last resort):** everyone runs
  cloud_enum/lazys3/s3enum on the same public program lists; obvious names are exhausted; a GrayhatWarfare
  hit proves "public," not "yours." **Off by default in our module** (dup-magnet + provenance risk).
  Recurring mutation tokens when you DO permute: `dev stage staging prod backup assets media uploads logs data jenkins deployments`.

## Anti-burn (provider frontend, not the target)
- The bug-bounty **target is NOT in the request path** (we hit the AWS/GCS/Azure frontend) and AWS does
  not bill cross-account 403s — so target-side WAF/rate-limits are irrelevant; only provider-frontend
  throttling matters. AWS serves **503 `SlowDown`** under aggressive probing (no IP ban, but single-source
  403 storms are detectable — stay gentle).
- **Cap ~3–5 threads** (S3Scanner default 4, no native backoff); bound the batch; long cycle interval.
  GCS autoscales (~5k reads/s) but back off on 429/5xx; Azure can't enumerate containers anonymously.
- All egress stays on **Mullvad** via the daemon (`run_scanner` vpn-gate + egress slot).

## S3Scanner (sa7mon v3) operational notes
- **Read-only by default; there is NO destructive flag** — the CLI hardcodes non-destructive `Scan`, so
  `PutObject`/`DeleteObject`/`PutBucketAcl` never fire. It does `HeadBucket` (read), `GetBucketAcl`
  (read-acl → parses ALL grants, incl. WRITE), and `ListObjectsV2` only with `-enumerate` (lists object
  KEYS/sizes — no download). So **public-write is auto-detected ONLY when the ACL is publicly readable**
  (`perm_all_users_read_acl=1`); if the ACL is private, `perm_all_users_write` stays `2`(unknown) →
  flag for the on-demand `writecheck`.
- Install: `go install github.com/sa7mon/s3scanner@latest` (binary at `~/go/bin/s3scanner` + `/usr/local/bin`).
- Run: `s3scanner -provider aws -bucket-file names.txt -json -threads 3` (one bucket NAME per line, not URLs).
  Providers: `aws digitalocean dreamhost gcp linode scaleway` (+ `custom` via config.yml). **No Azure, no stdin; queue mode is RabbitMQ not SQS.**
- Output (line-delimited JSON): `{"bucket":{name,region,exists,provider,num_objects,perm_all_users_read,
  perm_all_users_write,perm_all_users_read_acl,perm_all_users_write_acl,perm_all_users_full_control, …},"level","msg","time"}`.
  `exists`/`perm_*` = `1` allowed / `0` denied / `2` unknown.

## Our module's verdict mapping (recon_bucket_scanner.sh)
- `perm_all_users_write|write_acl|full_control == 1` → **CONFIRMED public-write/ACL-write** (high/critical) → `db_confirm` → Claude VERIFY → #review/SUBMIT. (operator: report ALL public-writes.)
- `perm_all_users_read == 1` → **LEAD public-read** → `leads.jsonl` + briefing (verify content sensitivity + that it's not a by-design CDN bucket before reporting).
- `perm_all_users_read_acl == 1` only → **LEAD read-acl** (low; also reveals write grants).
- `exists == 0` but referenced by a live in-scope host → **dangling-bucket takeover LEAD** → takeover lane.
- `exists == 1`, all perms `0` → **secure (403) FP** → note a representative, drop.
- Unattended loop = **GET-only** (list + get-acl + key-listing). The invalid-MD5 `writecheck` (PUT, zero-write) and the benign-marker upload PoC are **operator-on-demand** only.

## Sources
S3Scanner source (permission.go, worker.go, aws.go, bucket.go) · gf s3-buckets + issue #23 · Intigriti
"Hacking misconfigured AWS S3 buckets" · YesWeHack "Abusing S3 bucket permissions" · Detectify "Deep dive
into AWS S3 access controls" (invalid-MD5) · Checkmarx bignum supply-chain · AWS API_Error.html · cloud_enum
aws_checks.py (503 SlowDown) · Bugcrowd VRT · ott3rly S3 axiom · disclosed H1 reports above.

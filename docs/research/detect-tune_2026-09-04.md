# Research digest — detect-tune — 2026-09-04

# Research digest — detect-tune — 2026-09-04 (pass 5)

## 1. Origin-IP-behind-CDN discovery consolidated into a maintained tool (`unwaf` v2.0) — directly un-blinds our CDN-fronted-host skip rule (HIGH PRIORITY, feeds `class-cdn-origin-bypass.md`)

Our CHAIN-TO-IMPACT law skips port/protocol confirmation on CDN-fronted hosts ("a CDN ACKs every port, so those results are meaningless") — that's correct as a default, but it means every Cloudflare/CloudFront-fronted host in our top-tech list is currently a dead end for the port-confirm chain. `unwaf` v2.0 (Go, actively maintained, [github.com/mmarting/unwaf](https://github.com/mmarting/unwaf)) consolidates the standard passive-discovery playbook into one tool with automatic candidate verification (HTML similarity, TLS cert fingerprint match, HTTP header comparison) — turning "maybe the origin is X" into a verified match, not a guess.

**7 discovery methods (all passive/OSINT, zero target traffic — same posture as our uncover/permute lanes):**
- SPF `ip4:` directives, MX records (skip Google/Microsoft-hosted mail)
- 30+ common subdomain brute (`direct`, `origin`, `backend`, `staging`, `dev`, `cpanel`) — DNS only
- Certificate Transparency (crt.sh) for forgotten subdomains/staging hosts still pointing at origin
- DNS history via **AlienVault OTX + HackerTarget** (SecurityTrails free tier and Censys API access for this purpose are both gone in 2026 — update `reference_api_credit_budget` assumptions)
- Shodan **favicon hash correlation** (mmh3 hash → `http.favicon.hash:<hash>` finds the same app on a non-CDN IP; devs almost never randomize favicons across environments) and **TLS cert SHA-1 fingerprint search** (`ssl.cert.fingerprint`) — both cheap, single Shodan queries against our already-scarce budget
- WAF/CDN self-fingerprinting (Cloudflare/Akamai/CloudFront/Fastly/Sucuri/Imperva) to know which discovery methods apply
- **IPv6 AAAA record enumeration** — a method we likely don't run today; admins frequently forget to CDN-proxy the AAAA record even when the A record is fronted

**Two items not on the standard list, both fit our existing lanes:**
- GitHub code search for committed IP literals in `.env`/`.yaml`/`.tf`/`.conf` — same class of leak our `recon_ghleaks.sh` already hunts, just add IP-literal patterns to that lane's queries.
- SSRF webhook-callback (issue a unique URL, see which IP calls it back) — "definitive proof," and matches our interactsh-for-OOB doctrine; only applicable when we already have interactsh evidence in-flight for that host, never a standalone active probe.

**Actionable for us:** run `unwaf`-style passive discovery (favicon-hash + cert-fingerprint via Shodan, crt.sh, MX/SPF, AAAA) against our CDN-fronted in-scope+paying hosts. A **verified** origin match (cert/HTML match, not just "an IP responds") reclassifies that host from "CDN-fronted, skip port-confirm" to eligible for `recon_port_proto.py`'s protocol-speak confirm — this is new surface for the money chain, not just more recon. Passive/OSINT only, so it runs as d0k (no Mullvad gate), same posture as `recon_uncover.sh`.

- Sources: [github.com/mmarting/unwaf](https://github.com/mmarting/unwaf), [ddactic.net — 11 Ways to Find a Hidden Origin](https://ddactic.net/blog/BLOG_POST_ORIGIN_DISCOVERY)



## 2. GCS unauthenticated bucket read/list — our bucket lane is S3-only; Google Cloud is one of our top-scanned techs (feeds `class-bucket-exposure.md`)

`recon_bucket_scanner.sh` is S3Scanner-backed only. Google Cloud / Google Cloud CDN sit in our own top-tech list, meaning a real slice of in-scope infra almost certainly uses GCS buckets our current lane can't see at all — an under-hunted gap in our own coverage, not a new external threat.

**Unauthenticated check (no service account needed):**
- `GET https://www.googleapis.com/storage/v1/b/<BUCKET>/o` — lists objects with zero auth if the bucket (or an object) has an `allUsers` IAM binding or legacy ACL entry. A 200 with an object listing = public-read confirmed; a 403 `PERMISSION_DENIED` is the secure/normal state (same "403 ≠ finding" discipline we already apply to S3).
- `GET https://storage.googleapis.com/<BUCKET>/<object>` — legacy XML-API direct object fetch, same shape as our S3 anonymous-GET check.
- IAM/ACL distinction that matters for our severity model: `allUsers` = internet-public; `allAuthenticatedUsers` = readable by *any* Google account holder, not just internet-anonymous — still a real exposure but should be scored/labeled distinctly from `allUsers` in our severity function (mirrors how we already distinguish public-read from public-write on S3).
- Reference tool for technique validation only, **never as a blind-permute source** — `GCPBucketBrute` (RhinoSecurityLabs) demonstrates the same unauthenticated-first enumeration order (try anonymous before any credentialed call), which matches our own provenance-seeded doctrine.

**Actionable for us:** extend `recon_bucket_scanner.sh`'s provenance-seeded bucket-ref miner (jsintel/params → candidate names, same as today for S3) to also emit `storage.googleapis.com`/`storage.cloud.google.com`/bare-bucket-name-as-GCS candidates, and add the two anonymous-GET checks above as a second backend alongside S3Scanner. Keep the existing hard line: provenance-confirmed candidates only, never blind-permute GCS bucket names (the GCS namespace is global exactly like S3's).

- Sources: [github.com/RhinoSecurityLabs/GCPBucketBrute](https://github.com/RhinoSecurityLabs/GCPBucketBrute), [rhinosecuritylabs.com — GCP Bucket Enumeration](https://rhinosecuritylabs.com/gcp/google-cloud-platform-gcp-bucket-enumeration/)

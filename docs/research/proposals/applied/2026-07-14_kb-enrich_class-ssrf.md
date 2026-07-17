# PROPOSAL (proposal) for docs/knowledge/class-ssrf.md — kb-enrich 2026-07-14
_Review and apply manually; not auto-merged into the KB._

## FIX: file was cut off mid-sentence — the confirm primitive section below completes it.

Point every tested SSRF sink at an **interactsh** collaborator URL: `<subdomain>.oast.<region>.interactsh.com`
(or our self-hosted instance). A DNS/HTTP callback logged on the interactsh side = definitive OOB proof the
target server itself made the outbound request. No callback = not confirmed, regardless of response body/
status code. Never point a sink at `file://`, `169.254.169.254`, or any internal-data-fetch target as the
"confirm" step — the canary callback IS the PoC; chasing actual cloud creds/internal data past that is
exploitation, not confirmation, and stays operator-only (same discipline as every other class here).

---

## Where to look — sinks beyond the obvious `?url=` param (research added 2026-07-14)

Classic SSRF hunting stops at a visible `url`/`callback`/`redirect` query param. The higher-yield,
less-crowded surface is functionality that fetches a remote resource **as a side effect**, often with
no URL param visible in the UI at all — these overlap directly with our jsintel-mined endpoint surface,
so route jsintel hits through this lens instead of just grepping for `url=`:

- **Webhook / integration config** — any endpoint accepting a `webhookUrl`/`callbackUrl`/`notifyUrl`/
  `endpointUrl` field (Slack/Zapier-style integrations, payment-status callbacks, CI/build-status
  hooks). Frequently only discoverable via JS, not the rendered UI.
- **URL preview / unfurl** — chat apps, ticketing systems, and CMSs that render a link preview
  (title/thumbnail) server-side when a URL is pasted.
- **PDF/report generation** — wkhtmltopdf, headless-Chrome/Puppeteer print-to-PDF, WeasyPrint. Any
  "export to PDF" / invoice / report feature that renders attacker-influenced HTML fetches external
  resources (`<img src>`, `<link>`, `@import`, `<iframe>`) server-side. Dedicated writeup: Intigriti's
  "Exploiting PDF generators" guide.
- **SVG upload → image processing.** SVG is XML — an uploaded SVG containing
  `<image href="http://<canary>/">` gets server-side-fetched by ImageMagick/librsvg/etc. when the
  processor rasterizes or thumbnails it. Distinct from URL-param SSRF: the "URL" is invisible, embedded
  inside a file that passes normal image-upload validation (extension/MIME checks don't catch it).
- **Import/sync features** — "import from URL" (avatar-from-URL, RSS/feed add, remote file import),
  document conversion services, any "fetch this resource for me" backend action.
- **OAuth/SSO callback + custom HTTP-client wrappers** — anywhere the app itself makes an outbound
  call using attacker-influenced host/path (not just full-URL) is in scope; don't dismiss a sink just
  because it only accepts a hostname or path segment, not a full scheme+URL.

## IMDSv2 is not an automatic "SSRF is unexploitable-for-creds" signal

IMDSv2 requires `PUT /latest/api/token` first, then the returned token as `X-aws-ec2-metadata-token` on
the follow-up GET. A pure GET-only, no-custom-header SSRF genuinely can't complete this handshake — but
many real sinks (webhook configs, generic HTTP-fetch proxies, "test this URL" features) let the attacker
control **method AND headers**, in which case IMDSv2 is fully bypassable by performing the handshake
through the SSRF itself. Real case: Typebot.io webhook SSRF (Nov 2025) obtained EKS node-role credentials
this way despite IMDSv2 being enabled. When ranking/reasoning about a confirmed SSRF's severity, check
whether the sink exposes method/header control before assuming metadata creds are out of reach.

Newer AWS managed services have also shipped metadata surfaces WITHOUT IMDSv2-style enforcement — e.g.
Bedrock AgentCore Runtime's microVM Metadata Service (MMDS), disclosed by Palo Alto Unit 42 in 2025.
Worth a version/service-specific check on any AWS-hosted target running newer managed AI/compute
offerings, same doctrine as KEV/CVE version-reasoning elsewhere in the pipeline (LEAD until confirmed,
never assumed).

## Multi-cloud metadata targets (beyond the default AWS canary point)

For post-confirm severity reasoning only (the interactsh OOB ping remains the actual confirm primitive
— never chase real metadata/creds autonomously):
- **AWS:** `http://169.254.169.254/latest/meta-data/` (IMDSv1) / token-gated IMDSv2 as above.
- **GCP:** `http://metadata.google.internal/computeMetadata/v1/` — requires `Metadata-Flavor: Google`
  header (another method/header-control-dependent case, same as AWS IMDSv2).
- **Azure:** `http://169.254.169.254/metadata/instance?api-version=2021-02-01` — requires `Metadata: true`
  header.
Header-gated in all three cases → same "does the sink give header control" question determines real
exploitability, not just "does 169.254.169.254 respond."

## Bypass class to assume, not enumerate

Don't rely on payload lists — the underlying bug class is that **the validator and the actual HTTP
client parse the URL differently** (userinfo-`@` tricks, backslash/unicode normalization, IDN
homoglyphs, `#`-fragment truncation, decimal/octal/hex IP encodings). Any allowlist/blocklist-style
SSRF filter should be treated as inherently bypassable rather than a "this sink is protected" signal —
worth a second look even on a target that appears to validate the host.

## DNS rebinding / TOCTOU

Validate-then-fetch flows that resolve DNS once to check the host, then again to make the actual
request, are rebindable (attacker's DNS answers differently between the two lookups). Disclosed
real-world instance: Craft CMS's GraphQL Asset mutation SSRF (CVE/GHSA-gp2f-7wcm-5fhx) validated via
one DNS resolution and fetched via another. Relevant if we ever reason about *why* a target's
allowlist-based SSRF guard failed, not something our OOB-only confirm primitive needs to exploit.

## Sources (added 2026-07-14)
- vulnsy.com/cheat-sheets/ssrf
- github.com/craftcms/cms/security/advisories/GHSA-gp2f-7wcm-5fhx
- ringsafe.in/ssrf-beyond-aws-gcp-azure-onprem/
- appsecure.security/blog/ssrf-cloud-environments
- intigriti.com/researchers/blog/hacking-tools/exploiting-pdf-generators-a-complete-guide-to-finding-ssrf-vulnerabilities-in-pdf-generators
- gecko.security/blog/ssrf-file-upload-processing-prevention-guide
- blackhillsinfosec.com/hunting-for-ssrf-bugs-in-pdf-generators/

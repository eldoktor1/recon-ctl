# class-ssrf — Server-Side Request Forgery (SSRF) hunting

Research compiled 2026-07-03. Sources: PortSwigger Web Security Academy, Craft CMS CVE-2026-27129, HackerOne #1369312, herish.me five-bounties-one-ssrf writeup.

**Pipeline role:** SSRF is a CONFIRMED finding only via an OOB callback to a canary we control (interactsh). Reflection of the URL or a non-200 response is NOT confirmation. No `file://`, no internal-data exfiltration — one OOB ping is the PoC.

---

## The confirm primitive (pipeline-safe)

Point every tested SSRF sink at an **interactsh** collaborator URL:
`<subdomain>.oast.<region>.interactsh.com` (or our self-hosted instance). A DNS/HTTP callback logged
on the interactsh side = definitive OOB proof the target server itself made the outbound request. No
callback = not confirmed, regardless of response body/status code. Never point a sink at `file://`,
`169.254.169.254`, or any internal-data-fetch target as the "confirm" step — the canary callback IS the
PoC; chasing actual cloud creds/internal data past that is exploitation, not confirmation, and stays
operator-only (same discipline as every other class here).

---

## Where the id hides — SSRF sinks beyond the obvious `?url=` param (added 2026-07-14)

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
  resources (`<img src>`, `<link>`, `@import`, `<iframe>`) server-side.
- **SVG upload → image processing.** SVG is XML — an uploaded SVG containing
  `<image href="http://<canary>/">` gets server-side-fetched by ImageMagick/librsvg/etc. when the
  processor rasterizes or thumbnails it. The "URL" is invisible, embedded inside a file that passes
  normal image-upload validation (extension/MIME checks don't catch it).
- **Import/sync features** — "import from URL" (avatar-from-URL, RSS/feed add, remote file import),
  document conversion services, any "fetch this resource for me" backend action.
- **OAuth/SSO callback + custom HTTP-client wrappers** — anywhere the app itself makes an outbound
  call using attacker-influenced host/path (not just full-URL). Don't dismiss a sink just because it
  only accepts a hostname or path segment, not a full scheme+URL.

## Absolute-form request-target SSRF — reverse-proxy → forward-proxy (added 2026-07-11)

A distinct SSRF class hides in how a reverse proxy (Nginx/ALB/anything) hands the RAW request-target
through to a Node/Express backend. If the backend does `new URL(req.url)` (or equivalent) without
checking for a leading `/`, an **absolute-form** request line (e.g. `GET http://<canary>/ HTTP/1.1`
instead of `GET /path HTTP/1.1`) can make the backend treat the request-target as a full URL and fetch
it — turning the app into a forward proxy. No visible URL param needed.
(NOTE: the source proposal was truncated mid-example; concept is actionable, but confirm the exact
absolute-form payload against the specific proxy/framework before relying on a precise byte sequence.)

## Severity reasoning after a confirmed SSRF (added 2026-07-14)

For **post-confirm severity reasoning only** — the interactsh OOB ping remains the actual confirm
primitive; never chase real metadata/creds autonomously.

### IMDSv2 is NOT an automatic "SSRF can't reach creds" signal
IMDSv2 requires `PUT /latest/api/token` first, then the returned token as `X-aws-ec2-metadata-token`
on the follow-up GET. A pure GET-only, no-custom-header SSRF genuinely can't complete this handshake —
but many real sinks (webhook configs, generic HTTP-fetch proxies, "test this URL" features) let the
attacker control **method AND headers**, in which case IMDSv2 is fully bypassable by performing the
handshake through the SSRF itself. Real case: Typebot.io webhook SSRF (Nov 2025, verify) obtained EKS
node-role credentials this way despite IMDSv2 being enabled. When reasoning about severity, check
whether the sink exposes method/header control before assuming metadata creds are out of reach.
Newer AWS managed services have also shipped metadata surfaces without IMDSv2-style enforcement — e.g.
Bedrock AgentCore Runtime's microVM Metadata Service (MMDS), reported by Palo Alto Unit 42 in 2025
(verify) — worth a service-specific check on AWS targets running newer managed AI/compute offerings,
same LEAD-until-confirmed doctrine as KEV/CVE version-reasoning.

### Multi-cloud metadata targets (all header-gated)
- **AWS:** `http://169.254.169.254/latest/meta-data/` (IMDSv1) / token-gated IMDSv2 as above.
- **GCP:** `http://metadata.google.internal/computeMetadata/v1/` — requires `Metadata-Flavor: Google` header.
- **Azure:** `http://169.254.169.254/metadata/instance?api-version=2021-02-01` — requires `Metadata: true` header.
Header-gated in all three → the "does the sink give header control" question determines real
exploitability, not just "does 169.254.169.254 respond."

## Filter-bypass class to assume, not enumerate (added 2026-07-14)

Don't rely on payload lists — the underlying bug class is that **the validator and the actual HTTP
client parse the URL differently** (userinfo-`@` tricks, backslash/unicode normalization, IDN
homoglyphs, `#`-fragment truncation, decimal/octal/hex IP encodings). Treat any allowlist/blocklist-style
SSRF filter as inherently bypassable rather than a "this sink is protected" signal — worth a second look
even on a target that appears to validate the host.

### DNS rebinding / TOCTOU
Validate-then-fetch flows that resolve DNS once to check the host, then again to make the actual
request, are rebindable (attacker DNS answers differently between the two lookups). Disclosed instance:
Craft CMS's GraphQL Asset mutation SSRF (GHSA-gp2f-7wcm-5fhx, verify) validated via one DNS resolution
and fetched via another. Relevant when reasoning about *why* a target's allowlist-based guard failed;
not something the OOB-only confirm primitive needs to exploit.

## Sources (added 2026-07-11 / 2026-07-14)
- vulnsy.com/cheat-sheets/ssrf
- github.com/craftcms/cms/security/advisories/GHSA-gp2f-7wcm-5fhx
- ringsafe.in/ssrf-beyond-aws-gcp-azure-onprem/
- appsecure.security/blog/ssrf-cloud-environments
- intigriti.com/researchers/blog/hacking-tools/exploiting-pdf-generators-a-complete-guide-to-finding-ssrf-vulnerabilities-in-pdf-generators
- gecko.security/blog/ssrf-file-upload-processing-prevention-guide
- blackhillsinfosec.com/hunting-for-ssrf-bugs-in-pdf-generators/

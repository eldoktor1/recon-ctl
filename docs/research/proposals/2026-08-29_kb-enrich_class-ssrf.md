# PROPOSAL (proposal) for docs/knowledge/class-ssrf.md — kb-enrich 2026-08-29
_Review and apply manually; not auto-merged into the KB._

## Concrete filter-bypass payload catalog (added 2026-08-29)

Use these to TEST whether a sink's allowlist/blocklist actually normalizes before comparing — the
canary-callback discipline is unchanged (point the payload at our interactsh host's IP-encoded form,
never at a real internal/metadata target as the "test"). A payload that gets through the filter and
reaches OUR canary = confirmed parser-mismatch; do not chase further.

- **IPv4 alt-encodings:** decimal (`http://2130706433/`), hex (`http://0x7f000001/`, per-octet
  `0x7f.0x0.0x0.0x1`), octal (`0177.0.0.1`, dotless `017700000001`), short-form (`127.1`, `127.0.1`),
  octet-overflow (`127.0.0.257`, some parsers modulo-256 this).
- **IPv4-mapped IPv6:** `[::ffff:169.254.169.254]` and its hex-encoded IPv4 part.
- **URL-parser confusion:** userinfo-injection (`http://allowed.com@169.254.169.254/` — many
  validators regex the hostname-looking prefix, the HTTP client uses the real host after `@`),
  fragment confusion (`http://169.254.169.254#@allowed.com/`), suffix/subdomain tricks
  (`allowed.com.evil.com`, trailing dot `allowed.com.`), IDNA decorated-unicode digits
  (`①②⑦.⓪.⓪.①` normalizes to `127.0.0.1` in some resolvers).
- **Exotic schemes** (only relevant if the sink doesn't hard-restrict to http/https): `gopher://`,
  `dict://`, `ftp://`, `ldap://` — these are internal-protocol-speaking primitives, not http fetches;
  treat scheme-acceptance itself as the finding signal (LEAD), never use them to actually pull data.

### Redirect bypass is a DISTINCT bug from DNS rebinding — test both
Rebinding = the DNS answer changes between validation-lookup and connect-time (same request, same
hostname, TOCTOU on resolution). **Redirect bypass = the sink validates the URL string itself, then the
HTTP client transparently follows a 3xx `Location:` header to an internal/metadata target with NO
re-validation of the final URL.** Disclosed case: crewAI's scrape tools (bugcrowd report, June 2026) —
guard checked the original public URL, returned it unchanged, and the underlying HTTP client followed
redirects by default. Test independently: (1) does the sink follow redirects at all (send a 302 to
our own canary and see if it's followed), and if so (2) does it re-validate the *post-redirect* URL,
or only the one the caller supplied. A sink that follows redirects and re-validates only the input URL
is bypassable regardless of how strict its input-URL allowlist is.

Sources: intruderlabs.com.br/en/blog/ssrf-bypass-techniques; github.com/crewAIInc/crewAI/issues/6520.

# PROPOSAL (proposal) for docs/knowledge/class-cache-deception.md — vulns 2026-06-25
_Review and apply manually; not auto-merged into the KB._

## URL Delimiter Confusion Variants (2026 active research)

URL parsing discrepancies between origin and CDN can flip a `Cache-Control: private` / `no-store` response cacheable under a path-confused variant. New delimiter vectors beyond the classic `.php/.js` path-append:

**Delimiters to try (add to `recon_wcd.sh` probe set if missing):**
- `;<extension>` — semicolon before static ext: `/account/profile;.js`
- `%3B<extension>` — percent-encoded semicolon: `/account/profile%3B.css`
- `/<junk>/../<static>` — dotdot normalize: `/account/profile/.js`
- `//` double-slash prefix variations

**CDN specificity:** Cloudflare and Varnish most surface-rich for normalization discrepancies. Cloudflare Pingora normalizes differently than classic CF cache layer.

**Detection gate (pipeline doctrine — unique cache-buster is the safety primitive):**
1. Probe `GET /path<variant>?cb=<unique>` — check if response is cacheable (`CF-Cache-Status`, `Age`, `X-Cache`)
2. Second GET same URL (different session, no cookies) — if `CF-Cache-Status: HIT` while base path returns `DYNAMIC/private` = cacheability flip = LEAD
3. Impact PoC (authenticated data in cache) = operator owned-account step

**Source:** https://blogs.jsmon.sh/from-cache-poisoning-to-account-takeover-a-modern-web-security-case-study/

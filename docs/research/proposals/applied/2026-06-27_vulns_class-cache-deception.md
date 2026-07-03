# PROPOSAL (proposal) for docs/knowledge/class-cache-deception.md — vulns 2026-06-27
_Review and apply manually; not auto-merged into the KB._

## Framework-Specific Path Delimiter Attacks (PortSwigger "Gotta Cache 'Em All", 2026)

Prior WCD relied on appending `.js`/`.css` to dynamic paths. This maps framework-specific path terminators that CDNs don't recognize but origin frameworks strip:

| Framework | Delimiter | Probe |
|---|---|---|
| Spring (Java) | `;` (path param) | `/account;.js` |
| Ruby on Rails | `.` (format extension) | `/account.css` |
| OpenLiteSpeed | `%00` (null byte) | `/account%00.js` |
| Nginx | `%0a` (newline) | `/account%0a.js` |

CDN sees a static extension → caches. Origin strips the delimiter → serves the dynamic authenticated response. Cache stores it under an attacker-accessible key.

**Affected CDNs:** Cloudflare, CloudFront, Google Cloud CDN, Akamai, Fastly (all confirmed by PortSwigger research).

**Cloudflare Cache Deception Armor bypass:** `.avif` and other non-standard extensions bypassed Armor at time of research.

**Normalization WCP angle:** `%3F`/`%2F` combined with dot-segment traversal (`../`) allows poisoning path A while CDN caches it under path B.

**Add to `recon_wcd.sh` probe list:** `;.js`, `%00.js`, `.css`, `%0a.js` (in addition to existing `.js` suffix probes).

Source: https://portswigger.net/research/gotta-cache-em-all

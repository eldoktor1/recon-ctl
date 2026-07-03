# PROPOSAL (proposal) for docs/knowledge/class-cache-deception.md — vulns 2026-06-20
_Review and apply manually; not auto-merged into the KB._

## URL Delimiter Cache Attacks (PortSwigger, June 2026)

Source: https://portswigger.net/research/gotta-cache-em-all

**Technique:** URL parser discrepancies between CDN layer and origin server allow non-standard path delimiters to flip cache behavior. These are DISTINCT from the standard WCD path-confusion variant (dynamic base → cacheable suffix) — here the delimiter itself is the wedge.

### Delimiter gadgets by framework
| Delimiter | Framework | Effect |
|-----------|-----------|--------|
| `;` | Spring (Java) | Treated as path parameter separator by origin; CDN caches as static path |
| `.` | Rails | Treated as format extension by origin |
| `%00` | OpenLiteSpeed | Null byte strips suffix before routing |
| `%0a` | Nginx | Newline splits request |

### Attack variants
- **Cache deception via delimiter:** `GET /account;.css` — CDN caches as static CSS, origin serves dynamic account page.
- **Cache poisoning via delimiter:** Inject unkeyed input (header/param) into a response cached under the delimiter path.

### Detection approach (add to `recon_wcd.sh`)
After standard WCD probe pass, run a second "delimiter pass":

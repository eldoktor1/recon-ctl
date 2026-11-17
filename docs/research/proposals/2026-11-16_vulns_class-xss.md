# PROPOSAL (proposal) for docs/knowledge/class-xss.md — vulns 2026-11-16
_Review and apply manually; not auto-merged into the KB._

## 2026-11-16 — Cache-Control-strips-CSP + SVG-sanitizer-bypass chain (image-proxy/CDN XSS)
- Origin technique ("Cache Me If You Can", Searchlight Cyber, disclosed against Cloudflare's own `/cdn-cgi/image/`, now fixed there): a sanitizer bypass lets an SVG carry a script payload past the proxy's cleaner; separately, a specific `Cache-Control` value on the ORIGIN image response makes Chromium exclude the CSP header from its cached copy on replay, so a `default-src 'none'` CSP meant to neutralize the SVG never applies to the cached hit.
- Researchers confirmed the same cache/CSP-strip primitive generalizes to Netlify Image CDN and public S3 objects under specific conditions — i.e. it's not Cloudflare-specific.
- Test on in-scope hosts that: (1) accept SVG upload and reflect/serve it back (avatar/logo/image upload features are the common case), (2) front it through ANY image-proxy/CDN/resizing service, (3) rely on CSP rather than Content-Disposition/sandboxed-origin to neutralize uploaded SVGs.
- Source: https://www.slcyber.io/research/cache-me-if-you-can-xss-in-cloudflares-cdn-cgi-image

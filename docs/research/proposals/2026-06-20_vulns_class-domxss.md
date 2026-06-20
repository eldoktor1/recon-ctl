# PROPOSAL (proposal) for docs/knowledge/class-domxss.md — vulns 2026-06-20
_Review and apply manually; not auto-merged into the KB._

## Prototype Pollution → DOMPurify Gadget Chain (June 2026)

Source: https://labs.trace37.com/blog/dompurify-pp-ceh-bypass/

**Technique:** If `Object.prototype.tagNameCheck` or `Object.prototype.attributeNameCheck` is polluted (via lodash merge, `JSON.parse` + `Object.assign`, qs library, etc.), DOMPurify's `CUSTOM_ELEMENT_HANDLING` inherits the polluted prototype — bypassing ALL tag/attribute sanitization.

**Affected:** DOMPurify 3.0.1–3.3.3 (fixed in 3.4.0)

**Chain required:** (1) PP vector present on page → (2) DOMPurify ≤ 3.3.3 called to sanitize rendered HTML → (3) attacker controls sanitized input.

### Detection augmentation for `recon-domxss`
When scanning JS for DOMPurify:
```bash
# Version detection
grep -oE 'DOMPurify[^"]*"version"\s*:\s*"[0-9.]+"' *.js
# Regex: 3\.(0\.[1-9]|[1-2]\.|3\.[0-3]) → vulnerable range

# PROPOSAL (proposal) for docs/knowledge/tech-nextjs.md — kb-enrich 2026-09-03
_Review and apply manually; not auto-merged into the KB._

## React2Shell — CVE-2025-55182 (unauth RCE, RSC/Flight deserialization) — added 2026-09-03

**Class:** unauthenticated RCE via React Server Components "Flight" protocol deserialization.
CVSS 10.0. Disclosed Dec 2025, mass-exploited within days (multiple public PoCs).

**Root cause:** `getOutlinedModel()` in the RSC Flight deserializer walks object property
paths without a `hasOwnProperty` guard. A crafted `Next-Action` POST (multipart form-data)
with a field reference like `$1:__proto__:then` traverses the prototype chain to `constructor`
→ `Function` constructor → arbitrary server-side JS execution. Single unauthenticated request,
no session/auth required.

**Affected:**
- `react-server-dom-parcel` / `react-server-dom-turbopack` / `react-server-dom-webpack`:
  19.0.0, 19.1.0, 19.1.1, 19.2.0
- Next.js: 15.0.4 – 16.0.6, and 14.3.0-canary.77+
- Also hits: React Router (RSC mode), Waku, Parcel RSC, Vite RSC, RedwoodSDK

**Fixed:** React 19.0.1 / 19.1.2 / 19.2.1. Next.js 15.0.5 / 15.1.9 / 15.2.6 / 15.3.6 / 15.4.8 /
15.5.7 / 16.0.7.

**SAFE version-detection primitive (no code execution — use this, never the full exploit):**
POST a Flight-encoded payload of `["$1:a:a"]` against an empty target object on the app's
Server-Function endpoint (identified by a `Next-Action` header in normal traffic). A
**vulnerable** server crashes and returns HTTP 500 with a JSON body containing a `"digest"`
field; a **patched** server rejects the malformed payload cleanly with no crash/digest. This
distinguishes vulnerable-vs-patched with zero impact — appropriate for our unauth n-day lane.
Full exploitation (RCE) requires targeting `__proto__`/`constructor` paths and is HUMAN-ONLY
under our doctrine (RCE primitives are never auto-run).

⚠️ A companion identifier "CVE-2025-66478" circulates in vendor blog posts for the Next.js
side of the same bug, but NVD reportedly rejected/disputed that assignment — cite
CVE-2025-55182 as primary and verify -66478's status before it appears in any report.

**Detection fit for our pipeline:** fingerprint Next.js hosts already flagged by our tech
detector, check version against the ranges above (`recon-nday`/`recon-mood cve`), then run the
safe `["$1:a:a"]` probe as the confirm step before minting — matches the n-day
CHAIN-TO-IMPACT requirement (confirm the RUNNING VERSION in range, safe primitive only).

Sources: sysdig.com/blog/detecting-react2shell, securitylabs.datadoghq.com/articles/cve-2025-55182-react2shell-remote-code-execution-react-server-components, blog.securelayer7.net/cve-2025-55182, praetorian.com/blog/critical-advisory-remote-code-execution-in-next-js-cve-2025-66478-with-working-exploit

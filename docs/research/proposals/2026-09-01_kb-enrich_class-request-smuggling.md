# PROPOSAL (proposal) for docs/knowledge/class-request-smuggling.md — kb-enrich 2026-09-01
_Review and apply manually; not auto-merged into the KB._

## 2026 update — 0.CL / CL.0 / Expect-based desync + HTTP/2 downgrade smuggling

**Why this matters for us:** our top in-scope tech (Cloudflare, CloudFront, Varnish, Nginx) is exactly the
CDN-front + HTTP/1.1-backend shape these bugs live in. HTTP/2 is desync-immune on its own (explicit
frame-length), but a front-end that *downgrades* H2→H1.1 before forwarding upstream reopens every classic
desync trick plus new H2-only injection gadgets — and almost every major CDN does this downgrade.

### New attack classes (PortSwigger, portswigger.net/research/http1-must-die)
- **0.CL desync**: front-end never sees a `Content-Length` header (it's hidden from it via an
  "early-response gadget" — e.g. IIS serving a reserved filename `/con`/`/nul`, or a server-level redirect
  that answers before the body arrives), so the front-end treats the request as bodyless while the backend
  still consumes/misparses the trailing bytes → smuggled prefix.
- **Double-desync**: chains two poisoned connections to convert a 0.CL primitive into a full CL.0 injection
  of an attacker-controlled prefix into a victim's request — the two-stage variant that got Cloudflare a
  $7k H2.0 internal-desync bounty.
- **Expect-based desync**: abuses `Expect: 100-continue` two-phase handshake mishandling. Vanilla
  (`Expect: 100-continue`) and **obfuscated** (`Expect: y 100-continue` — still parsed as 100-continue by a
  lenient parser, bypasses naive filters) both trigger 0.CL/CL.0 variants. This is the CVE-2025-32094 Akamai
  vector and the GitLab attachment-domain 0.CL ($7k).
- **H2.CL** (CDN→H1.1 downgrade): send `POST / HTTP/2` with `Content-Length: 0` plus a smuggled raw
  HTTP/1.1 request appended after it. H2 frame length is authoritative so the front-end ignores
  Content-Length entirely; the downgraded H1.1 backend honors the `Content-Length: 0` header and treats the
  smuggled bytes as the start of the next pipelined request, poisoning the next victim's connection.
- **H2.TE** (CRLF-in-header-value): HTTP/2 headers are length-prefixed, not newline-delimited, so a raw
  `\r\n` is a *legal byte sequence inside a header value* at the H2 layer (inject via Burp Repeater's raw
  Inspector view, not the rendered text view — text view will re-encode it). Injecting
  `foo: bar\r\ntransfer-encoding: chunked` smuggles a second header past the CDN; the downgraded H1.1
  backend sees two headers and switches to chunked parsing, treating everything after the terminating
  `0\r\n\r\n` as the next request.
- **Browser-driven CL.0** (client-side desync, no attacker-controlled connection needed): a CL.0 endpoint
  (commonly static resources / redirects / error pages, where the backend silently ignores
  Content-Length) can be triggered by a victim's own browser — `fetch()` a POST with a raw smuggled request
  as the body against e.g. `/robots.txt`/`/favicon.ico`/a 301 redirect/a 404 page, then fire a second
  same-origin `fetch` with credentials; the smuggled prefix gets prepended to the victim's own follow-up
  request on that connection. Relevant to our XSS/CSRF-adjacent testing on Cloudflare-fronted hosts.

### Safe, single-request detection (fits our SSRF/OOB-canary confirm-primitive discipline)
- **H2.CL / H2.TE**: Burp's "HTTP Request Smuggler" extension (v3.0+) does single-request timing/behavioral
  probes — no need to actually poison a live connection to get a signal. Manually: disable
  "update Content-Length", inject the CRLF via the raw Inspector byte view, and watch for a **10+ second
  hang** — the backend accepted `transfer-encoding: chunked` and is waiting on a terminating chunk that
  never comes. A hang alone is a strong LEAD (not yet a mint — matches our CONFIRMED-vs-LEAD discipline;
  actual exploitation requires the two-request poison-then-observe sequence, which is a state-changing
  active PoC and needs our ACTIVE-PoC gates).
- **CL.0**: probe the classic bodyless-response endpoints (`/robots.txt`, `/favicon.ico`, `/sitemap.xml`,
  a known 301/302 redirect, a 404 page) with a mismatched Content-Length; if a follow-up request on the
  same connection reflects the smuggled prefix, that's the confirm.
- **Expect obfuscation probe**: send both `Expect: 100-continue` and `Expect: y 100-continue` variants at
  static/redirect/error endpoints on Cloudflare/Akamai/Netlify-fronted hosts specifically — vanilla filters
  usually only strip the exact string.

### Known-vulnerable-shape targets from the 2025-2026 disclosures (n-day/pattern awareness, not a direct
CVE match — verify per-host before treating as anything beyond a LEAD)
- Netlify: CL.0 via vanilla Expect (reported, unbountied — still a valid pattern to check).
- Akamai: CL.0 via obfuscated Expect — CVE-2025-32094.
- Cloudflare: H2.0 internal desync (patched, but the downgrade-desync *class* generalizes to any
  Cloudflare-fronted origin still on a legacy backend).
- IIS behind an ALB: Host-header malformation → H-V discrepancy (Host visible to front-end, hidden from
  back-end or vice versa).
- **Nginx was reported resistant** to the early-response-gadget primitive in this research round — don't
  burn time chasing 0.CL against a pure-Nginx origin; H2.CL/H2.TE (CDN-downgrade-driven) is the more
  promising angle there instead.

### Scope note
Actually exploiting a desync to poison another user's connection is an ACTIVE, state-changing test —
gated the same as any other ACTIVE-PoC (in-scope+authorized, minimal, own-traffic only, stop at proof).
The single-request timing/behavioral detection above is safe to run unattended as a LEAD-only signal.

Sources: [portswigger.net/research/http1-must-die](https://portswigger.net/research/http1-must-die),
[blogs.jsmon.sh — HTTP/2 Request Smuggling: H2.CL, H2.TE, Browser Desync](https://blogs.jsmon.sh/http-2-request-smuggling-why-h2-cl-h2-te-and-browser-desync-still-pay/)

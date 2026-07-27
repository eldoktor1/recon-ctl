# PROPOSAL (proposal) for docs/knowledge/class-request-smuggling.md — kb-enrich 2026-07-26
_Review and apply manually; not auto-merged into the KB._

## 2026-07-26 update — desync frontier (Kettle "HTTP/1.1 Must Die" generalization)

### CL.0 / Browser-Powered Desync Attacks (BPDA)
Newer than classic CL.TE/TE.CL: **CL.0** = frontend honors `Content-Length`, backend effectively ignores it (treats as CL:0) and reads the "leftover" body bytes as the start of the *next* request on the same reused connection. The breakthrough is these can be triggered by a **fully spec-compliant browser `fetch()`** — no raw-socket tooling needed — meaning a same-site XSS-adjacent or even cross-origin request can poison a shared connection pool (victim's own browser desyncs itself). Reference targets from the research: Amazon.com (H2.0 variant), Akamai (stacked HEAD), Cisco WebVPN (cache poisoning via desync), Varnish (synth-timeout variant) — useful fingerprint list for our in-scope CDN/reverse-proxy stack (we see Cloudflare, Varnish, AWS CloudFront heavily).

### Pause-based detection (new, safe-ish primitive)
Send the request headers (with a `Content-Length` promising a body) and then **pause** before sending the body bytes. If the server/backend responds *before* the body arrives, it finished parsing using something other than the declared Content-Length (backend truncated/ignored it) — a CL.0 candidate without needing to actually smuggle a second request. This is closer to our unauth-safe philosophy than classic differential-timing smuggling probes (still requires care: this is an ACTIVE probe against a live target, not a passive read — gate same as our existing smuggling lane: in-scope+pays, low volume, stop at detection, no actual smuggled-request payload delivery on shared infra beyond confirming desync exists).

### Chunk-extension smuggling
Some servers loosely parse (or ignore) `; extension=value` suffixes on chunk-size lines in `Transfer-Encoding: chunked` bodies; a front/back disagreement on how to handle these extensions can desync the same way as a CL/TE mismatch. Worth adding to our smuggling differential test matrix as a third dimension beyond CL vs TE.

Sources: [PortSwigger BPDA research](https://portswigger.net/research/browser-powered-desync-attacks), [Imperva chunk-extension trick](https://www.imperva.com/blog/smuggling-requests-with-chunked-extensions-a-new-http-desync-trick/). ⚠️ CVE-2025-32094 / CVE-2025-55315 mentioned only in secondary aggregation, NVD-unverified — don't cite as confirmed CVE in a report without checking NVD directly.

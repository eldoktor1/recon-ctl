# PROPOSAL (proposal) for docs/knowledge/class-cdn-origin-bypass.md — vulns 2026-09-05
_Review and apply manually; not auto-merged into the KB._

## HTTP/2 framing WAF-bypass class (added 2026-09-05, source: lab.ctbb.show/research/h2-WAF-Bypasses)
Distinct from cache/origin-IP bypass — this is a WAF-*inspection* gap caused by H2→H1.1 frame translation, worth testing on any in-scope host sitting behind a reverse-proxy WAF (not just CDN-fronted ones).

Four safe black-box tests, in order of cheapness:
1. **Content-Type gap**: send the same "should be blocked" payload (e.g. a path-traversal or SQLi-shaped string) once as `application/x-www-form-urlencoded`, once as `application/json`. A 403→200 flip = the WAF only parses form bodies (confirmed gap in Apache mod_security2 + Caddy/Coraza; Nginx+libmodsecurity3 parses all content-types — immune).
2. **Path-normalization gap**: request a rule-blocked path (`/.env`) then its encoded variants (`/%2eenv`, `/.%65nv`). A pass on the encoded form = the WAF matches pre-decode.
3. **Body-size gap**: pad a malicious payload with ~64KB of junk before the real content; a bypass on the padded request but not the bare one confirms an inspection-buffer cutoff.
4. **Body-timing race** (harder, needs a raw H2 client / `h2load`-style tooling): send HEADERS, hold DATA for ~500ms, then send it — probes whether an out-of-process WAF (HAProxy+SPOA-style) approves on HEADERS alone.

Fingerprint the proxy first (`Server:` header, ALPN behavior, error-page signature) to pick which gaps are plausible before spending probes. A bare bypass (Info: "WAF didn't block my test string") is not reportable alone — pair it with a payload that actually does something on the backend (XSS/SQLi/traversal) to make it a real finding, per PoC-OR-GTFO.

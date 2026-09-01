# PROPOSAL (proposal) for docs/knowledge/class-request-smuggling.md — detect-tune 2026-09-01
_Review and apply manually; not auto-merged into the KB._

## 2026-09-01 update — Pingora (Cloudflare's OSS reverse-proxy crate) smuggling + cache-poisoning cluster

Three new CVEs in Cloudflare's open-source `pingora`/`pingora-proxy`/`pingora-core` Rust crate, exploitable
under DEFAULT config in self-hosted deployments (Cloudflare's own CDN edge has extra layers that block it —
this is NOT a Cloudflare-fronted-target technique, it's for targets that vendor Pingora themselves):

- **CVE-2026-2833/2835** (request smuggling): (a) Pingora switches to passthrough mode on an `Upgrade:` header
  BEFORE the backend confirms with `101 Switching Protocols` — a smuggled second request appended to the
  upgrade payload rides straight to the backend, bypassing proxy-level controls; (b) non-RFC-compliant
  HTTP/1.0 handling (close-delimited bodies + mishandled `Transfer-Encoding: chunked`).
- **CVE-2026-2836** (cache poisoning): default `CacheKey` for the alpha proxy-cache feature hashes only the
  URI path — no `Host` header, no upstream scheme — so two different hosts hitting the same path can poison
  each other's cached response.
- Fixed in **Pingora 0.8.0**.
- **Fingerprint:** no distinctive default `Server:` banner (commonly rewritten/stripped) — look instead for
  leaked `Cargo.lock`/build artifacts referencing the `pingora`/`pingora-proxy`/`pingora-core` crate (GitHub
  leak lane), error-page stack traces, or the behavioral tell (passthrough begins before the backend's `101`
  response — confirming this IS an active smuggling PoC, so any positive is a CONFIRMED primitive, not a
  state to transition-gate).
- Sources: https://blog.cloudflare.com/pingora-oss-smuggling-vulnerabilities/ ,
  https://github.com/cloudflare/pingora/security/advisories/GHSA-93c7-7xqw-w357

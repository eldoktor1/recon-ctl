# PROPOSAL (proposal) for docs/knowledge/class-request-smuggling.md — detect-tune 2026-09-01
_Review and apply manually; not auto-merged into the KB._

## Safe single-request parser-discrepancy timing primitive (2026-09-01)
Source: James Kettle, "HTTP/1.1 must die: the Desync Endgame" (PortSwigger, 2025/2026) —
https://portswigger.net/research/http1-must-die

Closes the gap noted in `tech-nginx.md` ("CVE-2026-42926 is the most promising for a future
safe differential-probe design") — this IS that design, generalized to any version-in-range
desync-class CVE (Nginx CVE-2026-42926, Varnish CVE-2026-50052, etc).

**Primitive:** send ONE request with deliberately ambiguous body-framing (the class Kettle
calls "0.CL" — front-end treats `Content-Length` as implicitly 0 while the back-end doesn't),
capped at a short client-side timeout (3-5s). Never send a second "smuggled" follow-up request
— that's what would actually touch another user's traffic and cross the line into exploitation.
**Classify:**
- fast, clean, well-formed response → proxy normalizes correctly, likely NOT vulnerable (secure FP)
- hang-then-timeout, or a garbled/partial/truncated response → parser-discrepancy LEAD (the
  origin is waiting on bytes that never arrive — a real desync condition, but still zero
  cross-user impact demonstrated, so it clamps to LEAD, not P0)
**Scope:** only fire on hosts already version-gated in-range for a known desync CVE (avoid
blind-firing this at every host — expensive per KEV-unverified-version doctrine). Operator-
reviewed n-day candidate, same tier as our other version-LEAD n-day matches.

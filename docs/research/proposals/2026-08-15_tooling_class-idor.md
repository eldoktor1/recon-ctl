# PROPOSAL (proposal) for docs/knowledge/class-idor.md — tooling 2026-08-15
_Review and apply manually; not auto-merged into the KB._

## Tool: AuthProbe (added 2026-08-15)
Black-box BOLA/IDOR scanner (Apache 2.0, https://github.com/jbarach2012/AuthProbe, arXiv 2607.20574,
2026-07-22). Drives tests off an OpenAPI spec + 2+ operator-owned identities: detects object-returning
resources from the spec, learns what each identity legitimately owns via collection endpoints, attempts
cross-identity reads, confirms a leak by diffing against the true owner's ground-truth fetch. Also flags
enumerable IDs / missing-auth as supplementary signal.

Fits our locked authed-IDOR SOP exactly (2 owned accounts, enumerate-then-differential, no third-party
IDs) — candidate to mechanize the manual Claude-in-Chrome/Burp enumerate+differential step, ONLY when we
already have 2 owned accounts + a real OpenAPI/Swagger spec for the target (pair with autoswagger/
kiterunner-derived specs). Hard-gates itself: refuses non-local targets without `--i-have-authorization`.
Young (145 stars, single author) — trial on one target before trusting output; still human-adjudicated,
never auto-mints a finding.

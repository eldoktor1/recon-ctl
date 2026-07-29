# Research digest — detect-tune — 2026-07-28

Now composing the digest.

# Research digest — detect-tune — 2026-07-28 (third pass)

## 1. CVE-2026-44575 / CVE-2026-45109 — Next.js middleware bypass, NEW variant beyond the CVE-2025-29927 we already track (HIGH PRIORITY, unauth-safe, feeds `tech-nextjs.md`)

Our KB (`tech-nextjs.md` §4) only documents the 2025 `x-middleware-subrequest` header bypass. Two **distinct, newer** middleware-bypass CVEs exist and aren't covered:

- **CVE-2026-44575** (App Router, Next.js 15.2.0–15.5.15 and 16.0.0–16.2.4; fixed 15.5.16/16.2.5): middleware-based authorization is enforced on the normal route path but **not on the `.rsc` transport variant or segment-prefetch requests**. `GET /dashboard` correctly redirects to login; `GET /dashboard.rsc` or `GET /dashboard.segments/$c$children/__PAGE__.segment.rsc` serves the protected React Server Component payload with **HTTP 200, no auth**. Not affected: Pages Router, Vercel-managed deployments (self-hosted only).
- **CVE-2026-45109**: same bypass class, specific to `middleware.ts` builds compiled with **Turbopack**; fixed in 15.5.18 / 16.2.6 (note the *Turbopack* fix version trails the general fix — a host patched to 15.5.16 but still on 15.5.17 w/ Turbopack may remain exposed).

**Confirm primitive (safe, matches our doctrine exactly):** identify a route that 401/403/redirects unauthenticated on its normal path, then request the same path with `.rsc` appended (and the segment-prefetch variant). 200 + RSC payload = bypass confirmed; this is GET-only, unauthenticated, non-destructive — fits `recon_safe_probe.sh` directly, no probe-harness change needed, just a version/path check to add to the Next.js n-day version table.



## 2. vBulletin CVE-2026-61511 — pre-auth RCE via `ajax/render/pagenav`, public PoC (LEAD-not-P0, watch-list add for `class-nday.md`)

vBulletin 5.x ≤5.7.5 / 6.x ≤6.2.1: unsanitized input reaches `runMaths()` → PHP `eval()` via the `ajax/render/[template]` endpoint (`pagenav` template is the known-vulnerable route). Public PoC exists, actively getting scanned. Not in our current top-tech list, but PHP-forum software shows up incidentally on programs — worth a version-fingerprint-only check (banner/generator meta), never firing the actual payload per our n-day version-gate discipline (a real trigger is destructive/RCE, out of our safe-probe primitive set — this stays LEAD/version-match only, never auto-confirmed).



## Checked, nothing new to add
- **Subdomain-takeover provider fingerprints** (Cargo Collective, Tilda, Pantheon, Strikingly, Surge.sh, Anima, LaunchRock, Readme.io, Help Scout) — verified against `scripts/data/takeover_fingerprints.tsv`: **all already present** (94 entries). No gap here.
- **IDOR/BOLA OpenAPI-based detection research** — academic approach (rank params by object-ref semantics + type from spec) matches what `recon_idor_candidates.py` already does; no new actionable heuristic surfaced.
- Origin-IP/CDN-bypass, GraphQL introspection-bypass, dalfox v3, JWT alg-confusion — already covered in the last 4 digests, confirmed still current, not re-surfaced.

Sources: [CVE-2026-44575 analysis](https://securityboulevard.com/2026/05/cve-2026-44575-middleware-authorization-bypass-in-next-js-app-router/), [CVE-2026-45109](https://www.sentinelone.com/vulnerability-database/cve-2026-45109/), [vBulletin CVE-2026-61511](https://www.bleepingcomputer.com/news/security/vbulletin-fixes-critical-pre-auth-rce-flaw-with-public-exploit/), [vulnsy takeover cheat sheet](https://www.vulnsy.com/cheat-sheets/subdomain-takeover)

# Detection & Verification Audit — 2026-06-17

System-wide research audit of EVERY detection + verification lane against current (2025-2026)
best practice. Four parallel research agents each read the actual code AND web-researched the
class, citing sources. This is the "check all detection and verification with internet research"
deliverable. Fixes are tracked as tasks; status noted inline.

## Verdict

**Verification discipline is current and FP-resistant across the board** (CONFIRMED-vs-LEAD,
0.85 gate, headless-exec / interactsh-OOB / sqlmap-BEUT / NXDOMAIN-gate / version-gate). The
drift is in **(a) a few genuine FP holes that mint time-wasting reports**, **(b) detection
breadth** (modern variants/surface we don't cover = missed bugs), and **(c) "wire up what
already exists"** gaps. Nothing is obsolete; the deltas are coverage + a few calibration bugs.

## Prioritised fix backlog

### HIGH — genuine FP holes / live bugs (cause the time-wasting you wanted gone)
1. **brief_filter ES auth = 401 (LIVE BUG)** — used legacy `~/.recon_es_pass`; ES rotated to netrc
   2026-06-14 → `es_sibling_count()` returned -1 → shared-tenant/third-party-data suppression
   silently disabled. **✅ FIXED 2026-06-17** (netrc-first; verified unifi-hosting → 6222 siblings).
2. **portscan: open-port → 0.85 CONFIRMED** violates our own doctrine ("critical port from the
   number alone"). The nuclei service template doesn't gate `db_confirm`. **FIX:** require the unauth
   service template (redis/mongo/docker-api/…) to FIRE before CONFIRMED; bare TCP-open = LEAD.
3. **SSRF OOB callback attribution** — a callback proves *something* fetched the canary, but
   link-unfurlers/WAF-prefetch/AV/crawlers fire it from non-target IPs. `recon_ssrf_oob.sh` already
   captures `callback_remote_ip`. **FIX:** flag/downgrade callbacks whose IP is CDN/cloud-egress or
   doesn't correlate to the target ASN; prefer a DNS+HTTP pair.
4. **GitHub-leaks: no ownership gate** — a verified secret in a THIRD-PARTY repo that merely mentions
   the domain is minted CONFIRMED (the exact `_THIRD_PARTY_RE` FP our KB warns about). **FIX:** owner-in-
   program-org / secret-validates-against-in-scope-service gate before `db_confirm`; else LEAD.
5. **recon_bypass: 7 of 27 nomore403 techniques** — missing GET-safe parser-confusion/trust-header
   families (`header-confusion`/X-Original-URL, host-override, forwarded-trust, hop-by-hop, path-
   normalization, http-parser, raw-duplicates, ip-encoding…). Biggest detection uplift at ~zero FP.
   **FIX (verify names against the local ~/Tools/nomore403 build first):** expand the GET-safe set;
   keep excluding `verbs,verbs-case,method-override,raw-desync` (state/smuggling — operator-only).
6. **nuclei templates frozen** — `-duc` + no `nuclei -update-templates` anywhere → missing every
   monthly FP-fix + new CVE. **FIX:** scheduled (weekly) `-update-templates` out-of-band.
7. **n-day: two systems that don't talk** — `recon_vuln_feed.sh` already computes EPSS + nuclei-
   template + T0-T3 risk tiers, but `recon_nday.sh` ignores it and re-derives from raw KEV. **FIX:**
   consume vuln_feed (race T0/T1 first); add EPSS to the nday sort + triage score.

### MEDIUM — detection breadth (false-negatives = missed bugs)
8. **IDOR ranker blind to ~48% of BOLA** — no action-level/state-change model (41.7% of confirmed
   BOLA), no object-rebinding (owner_id in body), no chained-disclosure, UUID under-weighted, no
   GraphQL global-ID (base64 decode→increment) model. **FIX:** add action-level verb/ mutation signal
   (+3), object-rebinding (+2), raise UUID to +4, graphql-global-id tag, tenant/org boost. (arXiv 2605.25865)
9. **No active exposed-file/service lane** — `.git/HEAD`, `.env`, `/actuator/{env,heapdump,configprops}`,
   swagger/openapi, open buckets are not actively probed (U1 only mines JS routes). High-signal 2026
   surface (heapdump→AWS creds; Spring CVE-2026-40976 actuator authz bypass). **FIX:** dedicated
   content-signature confirm lane (GET via recon_safe_probe): `ref: refs/heads/` for git, property-source
   JSON for actuator, `ListBucketResult` for buckets.
10. **takeover CNAME-only** — misses dangling **NS + A-record** takeovers (dominant 2025 class, Hazy
    Hawk). **FIX:** add dangling-NS (lame delegation/NXDOMAIN-at-delegated-NS) + dangling-A (cloud-pool
    IP returning provider error) checks; consider shelling BadDNS. Sync fingerprints.tsv vs
    can-i-take-over-xyz (add bitbucket.io, discourse, youtrack, surveysparrow, uptimerobot, gemfury, readthedocs).
11. **jsintel: no source maps** — fetch `.js.map` (grep `sourceMappingURL`), reconstruct, scan with
    trufflehog/jsluice (map-only secrets + clean routes survive minification). Bump `katana -d 2→4`.
12. **injection variant breadth** — SSTI add `{a*b}` (Smarty/Latte), `[[a*b]]` (Thymeleaf), `{{=a*b}}`
    (dotjs), Velocity `#set`; open-redirect add userinfo-`@`, `%2f%2f`, whitespace, host-confusion bypass
    forms; XSS chain reflected-no-exec → the new dalfox-DOM lane + add markup payloads (iframe srcdoc,
    details ontoggle) + detect exec via a global marker not only `alert`; SQLi worker error-diff double-tap
    to kill transient-500 FPs (sqlmap path already mitigates).
13. **SSRF breadth** — GET/query-only misses POST/JSON/header sinks (surface as LEAD; safe-probe is
    GET-only by design) + 60s window misses delayed callbacks (persist canary→sink map, re-poll later cycle).
14. **trufflehog analyze** — run on verified secrets for blast-radius (read/write/admin) → honest severity.
15. **brief_filter fan-out normalization** differs from `recon_idor_candidates._fanout_key` (raw path vs
    ID-templated) → some product-class dups leak. **FIX:** share one normalization.
16. **true_fresh static-CT coverage (time-sensitive)** — LE shut legacy CT logs Feb 2026 (writes only to
    static-ct-api). **Verify gungnir's log list covers post-Feb-2026 LE**; cert lifetimes halving → renewal
    churn ~2× (watch `MAX_PER_FLUSH=5000` truncation).
17. **SPA-shell discriminator** (unauth_expose) is prefix+length only → harden to a normalized structural/
    body-hash compare.

### LOW
18. **Dead-field reads** `ai_relevance_score`/`ai_recommendation` in `recon_digest_leads.sh` (Ollama
    pre-scorer retired v3.1; reindex drops them; always null) → remove.
19. **tech:nextjs** lists CVE-2025-29927 as a confirmed action with no version-gate clamp (unlike
    Spring/Drupal) → add to `kev_surface_dependent`.
20. **js_secret_hit +10** public-token exclusion lives only in brief_filter, not triage's scoring path → apply there too.
21. Flag modernization `--only-verified` → `--results=verified` (both work).

## What is GOOD (current + FP-resistant — do not touch)
- Takeover NXDOMAIN-gate + TKO_NOTVULN claimability + S3 NoSuchBucket authoritative string.
- KEV version-gating in triage (Drupal≥8 drop, WP plugin+version, surface-dependent appliance clamp, `kev_unverified_sole` cap).
- Evidence-gate 0.85 promote bar + per-host FP-signature learning.
- XSS headless-exec (dialog+unique marker), SSTI random-product+baseline guard, open-redirect exact-host-on-3xx, SQLi sqlmap-BEUT (no stacked) + `'`vs`''`.
- U1 unauth-expose classifier (data-content-type + sensitive markers + SPA-shell + public-token suppression; redacted evidence).
- portscan CDN suppression (IP-dedup + httpx -cdn + CIDR guard + >6-port artifact cap).
- true_fresh renewal filter (known_hosts NUL-safe grep + SAN-root + cooldown).
- brief_filter structural FP-class rules (public token / third-party-repo / >6 ports / SPA-shell / KEV-no-version).

## Sources (representative)
BOLA taxonomy arXiv 2605.25865 · can-i-take-over-xyz · IONIX dangling-DNS 2026 · BadDNS · FIRST EPSS API ·
Picus CVSS/EPSS/KEV · TruffleHog (verify/analyze) · HackTricks GitHub leaks · ProjectDiscovery Nuclei
templates Apr-2026 + Nov-2025 · Wiz Spring Boot Actuator · nomore403 README · PortSwigger URL-validation
bypass cheat sheet + DOM/prototype-pollution · PayloadsAllTheThings SSTI/Open-Redirect · YesWeHack SSRF +
port-scanning · Hive SQLi 2026 · gungnir / certspotter / Cloudflare CT. (Full per-lane URLs in the agent
transcripts.)

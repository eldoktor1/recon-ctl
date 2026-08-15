# Changelog — Autonomous Bug Bounty Recon Pipeline

## v3.11 - 2026-06-21 - Blind/stored-XSS lane (recon-blindxss) — the #1 unused dalfox feature

dalfox has always had `-b`/`--custom-blind-xss-payload`; the gap was the persistent collector + the
correlation that maps a fire DAYS later back to where it was planted. This lane is that infra — a
dup-resistant, high-payout class (stored XSS firing inside an admin/staff console) the crowd's
reflected scanners never reach.

- **`recon_blindxss.sh`** (new) — `collector` (persistent `interactsh-client`; `-sf` session ⇒ stable
  correlation-id across restarts so multi-day-late fires still resolve; d0k, NOT vpn-gated), `correlate`
  (callback → strip CID → token → injection-map → mint), `emit-payload` (register a per-host token + write
  the dual-beacon payload + print the dalfox `-b` URL), `status`, `test`.
- **Dual-beacon correlation.** Every payload carries (1) an **interactsh** crafted per-host subdomain
  `<CID><token>.<oast>` — interactsh routes ANY subdomain whose first 20 chars equal our correlation-id back
  to our client (verified empirically; the trailing token is free), so a fire maps to the exact host; and
  (2) the operator's **XSS Hunter** (`js.rip`) probe for screenshot/DOM/firing-page/secrets forensics (the
  report PoC). Hosted XSS Hunter has no machine API → interactsh drives the autonomous mint.
- **Minting is gated.** A fire → `state.py record-confirmed` (`signal_class=blind-xss`, score 15, conf 0.9)
  → 2IC verify → `#review`, HARD-GATED on `ai_verdict='real'` like every lane. Uncorrelated fires (planted
  pre-session / XSS-Hunter-only) surface as manual-correlate LEADs, never auto-minted against unknown hosts.
- **Planting** = `recon_dast.sh` in `DAST_BLIND_ONLY` mode: per-host crafted `-b` + custom payload, fresh-first,
  7d cooldown, `--waf-evasion`, egress-governed, Mullvad-gated — and it SKIPS nuclei + reflected-finding
  recording (planting is fire-and-forget; the collector confirms later). No `#vulns` spam.
- **Also folded in:** `--waf-evasion` added to `recon_params.sh confirm` (dalfox) + `recon_domxss_confirm.sh`
  so on-WAF self-throttle protects the shared Mullvad exit during confirms.
- **Config** `~/.recon_blindxss.conf` (LOCAL): public oast.* by default (works now), self-host upgrade path
  documented (own domain = not a WAF-blocklisted IOC). Daemon: collector restart-loop + `blindxss-plant` (3h)
  + `blindxss-correlate` (5m) loops; killswitch `state/kill/v2_blindxss`; `recon-blindxss`/`recon-bx` aliases;
  `state/blindxss` ACL'd for d0k+reconrun. KB: `docs/knowledge/class-blind-xss.md`.
- **Validated end-to-end:** collector registers → plant a per-host token → simulated fire (pinned resolver)
  → collector captures (DNS+HTTP) → correlator extracts the firing page + mints exactly one gated finding
  (state=confirmed, ai_verdict=NULL → pending 2IC). interactsh crafted-subdomain routing + dalfox dual-beacon
  injection both confirmed on the wire.

## v3.10 - 2026-06-20 - Standing Claude research routines (recon-research) — keep the system updated

The pipeline had DATA feeds (CVE/KEV, nuclei-update, self-audit) but no Claude-driven RESEARCH layer.
`recon_research.sh` + `recon_research.py` add it: headless Claude on the Max subscription (no API key)
with WebSearch/WebFetch, on a cadence, feeding tooling/detection/verification/vuln knowledge into the repo.

- **Four topics** (daemon loops, killswitch v2_research): vulns (daily — new CVE/KEV + writeups
  version-reasoned to OUR top tech from ES), tooling (weekly — new/better tools per lane, skeptical
  adopt/evaluate/skip), kb-enrich (weekly — deepen KB docs), detect-tune (weekly — fingerprints/dorks/
  FP patterns/confirm primitives).
- **Web research is NOT target traffic** (Anthropic→web) → runs as d0k, no Mullvad/run_scanner gate.
  Self-serializes (flock) so the 4 topics never run Claude concurrently. ~6-8 search budget/run.
- **Autonomy (operator-chosen):** dated digest (docs/research/<topic>_<date>.md) + brand-NEW KB docs
  auto-commit+push; edits to EXISTING KB → review-only proposals (docs/research/proposals/) — never a
  silent rewrite. bash controls ALL file writes; Claude gets only WebSearch/WebFetch (no Write/Edit/Bash).
  Router (recon_research.py) enforces the new-vs-existing split. One Discord summary per run.
- **Validated live:** the vulns run found in-range CVEs for our actual stack (nginx 1.29.7, PHP SOAP,
  Varnish, Apache 2.4.66, Drupal JSON:API SQLi) with detection fingerprints + n-day actions, auto-created
  a high-quality tech-wordpress.md, and queued cache-deception/domxss enrichment proposals. LLM-search CVE
  IDs are self-flagged ⚠️ for NVD verification (LEAD-not-P0, per the KEV doctrine).
- Wiring: daemon loops, recon-ctl `research` dispatch + usage, `recon-research` alias, CLAUDE.md section.

## v3.9.1 - 2026-06-20 - GraphQL: Clairvoyance-style field-suggestion recovery (introspection OFF)

When introspection is disabled, `recon_graphql.py` now recovers the schema via field-suggestion leakage:
it sends GUARANTEED-INVALID 1-char near-miss field names (`<candidate>z`) — so a real field/mutation can
NEVER validly execute (no side effects, no data) — and harvests the engine's "did you mean <real field>"
error suggestions to reconstruct the query/mutation op set, ranked by name (sensitive-op patterns). The
1-char suffix stays inside graphql-js's edit-distance suggestion threshold (~floor(len*0.4)+1); a longer
nonce defeats it. Bounded (GQL_SUGGEST_MAX≈140) + rate-limited; early-bails after 12 no-suggestion probes
(suggestions off). Recovered endpoints flow to the worklist/briefing/ES (graphql_recovery field) exactly
like introspected ones. Validated: full op set recovered from a graphql-js endpoint via suggestions alone.

## v3.9 - 2026-06-20 - Three new lanes: GraphQL schema→worklist, active param discovery (arjun), web-cache deception

Tool-gap research (VulnAPI evaluated + rejected — it doesn't beat existing coverage and its safe parts
are authed/narrow) surfaced three GENUINE gaps; built all three, each source-grounded and doctrine-fit
(unauth-safe, dup-resistant, Mullvad-gated). KB: class-graphql.md, class-cache-deception.md.

- **GraphQL schema→worklist** (`recon_graphql.sh` + `recon_graphql.py`, native — no graphw00f/graphql-cop
  dep; the value is reasoning over the schema graph). Discover in-scope GraphQL endpoints (jsintel + ES
  url/title/tech + bounded path-expansion) → scope+pays gate → read-only `{__typename}` + introspection →
  rank sensitive unauth mutations + IDOR object-ref args + injectable args + PII-returning queries (reusing
  the recon_idor_candidates.py ID scoring) → `briefings/graphql_candidates_<date>.md` + worklist + briefing.
  LEADs only (IDOR/injection/auth-bypass = human 2-account test). Validated: found a live introspection-ON
  Atlassian gateway schema among in-scope candidates. Daemon 3h, killswitch v2_graphql, `recon-graphql`.
- **Active param discovery** (arjun bolted onto `recon-params arjun <host>` / `crawl-host --arjun`). Finds
  HIDDEN params absent from any URL/JS (the inputs that drive SSRF/cache-poison/reflected bugs) and rides
  the existing gf→catalog→confirm pipeline. ON-DEMAND ONLY (live traffic; never the daemon crawl), polite
  (`-t1 -d2 --rate-limit 3`, GET-only, no-redirect), in-scope+pays gated.
- **Web-cache deception/poisoning** (`recon_wcd.sh` + `recon_wcd.py`, native detect-only). CDN-fronted
  in-scope hosts; every probe carries a UNIQUE cache-buster so it NEVER poisons the real shared cache (the
  critical safety primitive). WCD = path-confusion variant of a non-cached base becomes cacheable; WCP =
  unkeyed header reflected into a cached response. LEADs → briefing; impact PoC = operator + owned account
  (`recon-wcd confirm` → Hackmanit WCVS `-ot deception -rr 0.5`). Daemon 6h, killswitch v2_wcd, `recon-wcd`.
- Wiring: daemon loops + killswitches, `recon-ctl` dispatch (graphql/gql, wcd, params arjun), `recon-*`
  aliases, three new briefing sections (🔮 GraphQL, ☁️ WCD, ☁️ buckets already added), CLAUDE.md pillars + FP entries.

## v3.8 - 2026-06-20 - Cloud-bucket exposure lane (S3Scanner) — dup-proof, provenance-seeded, FP-resistant

New lane `recon_bucket_scanner.sh` (+ `recon_bucket_scanner.py`) hunting misconfigured cloud storage
(S3 / GCS / DO Spaces) with the S3Scanner sa7mon v3 binary as backend. Built from source-grounded
research (S3Scanner source + top-hunter writeups → `docs/knowledge/class-bucket-exposure.md`). The
edge vs the saturated, dup-prone way everyone runs bucket tooling:

- **Provenance-seeded, never blind permutation (the MOTTO).** We mine bucket references from the
  target's OWN surface (jsintel `endpoints.jsonl` + the params catalog → Lane A), so every candidate
  is provenance-confirmed (the in-scope host itself references it). No name-guessing = no dup-magnet
  and no third-party-data risk (global namespace hard line). Validated on real data: surfaced Comcast/
  SEEK/iFood/Monzo export+asset buckets with full provenance.
- **Per-asset scope + pays gate** on the source host before any provider request (drops no-provenance
  + OOS + non-paying).
- **Read-only grading + authoritative list probe.** S3Scanner runs non-destructive (v3 has no
  destructive flag — `PutObject`/`PutBucketAcl` never fire). Because its `HeadBucket` read check is
  unreliable (it MISSED a real public-read Comcast bucket, reporting `read=unknown`), we add an
  authoritative anonymous list probe (region-aware, path-style → also handles dotted bucket names)
  that resolves READ definitively. `unknown ≠ denied` — undetermined buckets are dropped, not mis-noted
  as secure.
- **CONFIRMED-vs-LEAD routing.** public-WRITE / ACL-write → CONFIRMED → `db_confirm` → Claude VERIFY →
  #review/SUBMIT (operator: report ALL public-writes — non-damaging). public-READ / read-acl → LEAD →
  nightly briefing (verify content sensitivity / not by-design CDN). NoSuchBucket referenced by a live
  host → dangling-takeover lead. exists-but-403 → secure FP (note 2-3 reps per doctrine).
- **Safe-by-construction.** Unattended loop is GET-only (list + get-acl). The Detectify invalid-MD5
  `writecheck` (confirms writability with ZERO objects written) and the benign-marker upload PoC are
  operator-on-demand. Anti-burn: ≤3 threads, bounded batch, 7d re-scan cooldown, 4h cycle; egress is
  the provider frontend (not the target) and stays Mullvad-gated via `run_scanner`.
- **Wiring.** Daemon loop (killswitch `state/kill/v2_buckets`, `BUCKETS_INTERVAL`), `recon-buckets`
  command (`scan|check <b> [prov]|writecheck <b> [region]|results`), briefing `☁️ Cloud-bucket`
  section, KB doc, CLAUDE.md pillar + FP entry.

## v3.7.1 - 2026-06-14 - Params engine overhaul: unfrozen, jobs-and-queues, sliding window, archive-proxy, liveness

The sus_params catalog had silently frozen at ~9k and was dragging the confirmers down with it.
Root-caused and rebuilt the whole params lane end-to-end. All changes keep the egress posture
(Mullvad-only for target traffic) and are anti-burn by design.

- **Unfroze the catalog (silent-freeze bug).** A `PARAMS_CANDIDATE_POOL` bump to 20000 made the
  candidate query exceed ES `index.max_result_window` (10000) → `search_phase_execution_exception`
  → jq saw 0 rows → logged the benign "no candidates" forever. Fix: `search_after` paging (page
  ≤10000) + LOUD `.error` detection so an ES error can never again masquerade as "nothing to do".
- **Jobs-and-queues** (matches recon_validate.sh): split `collect` into a PRODUCER (`enqueue`,
  ES-only) that drops 50-host job files into `queue/params/`, and a CONSUMER (`crawl`) that claims
  ONE job/cycle under the global egress governor and indexes incrementally. The old model held one
  egress slot but fanned out 5-wide for hours (≈5× under-count) and indexed only at end-of-run.
  `collect` kept as a one-shot alias for zero-downtime migration.
- **Sliding-window cooldown** — per-host cooldown moved to `recon_alive.params_scanned_at` with a
  server-side `must_not range`, so the candidate window slides through the ~619k eligible pool:
  crawls 24/7, never goes idle, never re-hammers a host.
- **Reach the real surface** — ephemeral/CI junk (dev/test/qa/staging/preprod) scored high and
  filled the top tier (~77%); added a token-bounded non-prod filter + deepened the pool (30k via
  search_after) so the producer pages past the junk to real param-bearing hosts.
- **Cool-on-examine — the real window-advance fix (2026-06-14).** The non-prod filter above ran
  *client-side, after* the fetch, so filtered hosts were never crawled → never stamped
  `params_scanned_at` → they permanently re-anchored the top of the score-sorted window (unifi
  UUID tenants at score 25/16, `*-internal` infra, 168k `*.s3.*.backblazeb2.com` buckets). The
  producer could only surface the 2-3 real hosts mixed into the top 30k → `enqueued 2 host(s)`
  every cycle, forever. Fix: run the structural/ephemeral filter on the RAW window and COOL the
  junk (`cool_hosts` → `params_scanned_at=now`, chunked `_update_by_query`) so the window slides
  past it; diversity-cap only the survivors. Measured immediately: one cycle went from `enqueued 2`
  → `cooled 9177 junk` + `enqueued 343 host(s) as 7 jobs` (~170× producer throughput). The
  deterministic filter makes the 7d cooldown safe — a false-dropped host just returns after the TTL.
- **Product-class fan-out suppression (data-driven, 2026-06-14).** Even with cool-on-examine,
  the producer ground 3 hosts/cycle through mass per-user/per-tenant fan-outs that yield ~0
  params — `quora.com` (31k "spaces"), `artstation.com` (27k portfolios), `statuspage.io` (16k
  tenants), `elastic.dev` (15k CI — **938 crawled, 0 params**), `elstc.co`, `amazon.in`.
  `compute_dead_roots` now flags a root as dead only when ALL three hold: mass fan-out
  (`>=8000` eligible hosts), well-sampled (`>=20` crawled), and ~zero yield (`<0.05`
  params/crawled-host); the producer adds them to its candidate `must_not`. The eligible-count
  gate is the safety: low *archive*-param yield != no attack surface, so real programs with
  modest subdomain counts (paypal/tesla/hilton) are never suppressed — only genuine fan-outs.
  Self-maintaining (a fresh root must accrue the sample before judgement) and scoped to THIS
  lane (suppression never removes a host from jsintel/IDOR/takeover/nuclei). Tunable via
  `PARAMS_DEADROOT_{MIN_FANOUT,MIN_SAMPLE,MAX_YIELD}`; the live set is written to
  `state/params_deadroots.txt`. Same pass: archive timeout 30s->60s (big domains were timing
  out and losing their param-rich surface) and the ephemeral filter gained `ci|jenkins|gerrit|vpn|np`.
- **true-fresh cert-renewal fix** — gungnir can't tell a first cert issuance from a renewal, so
  ~90-day renewals of long-known hosts were mislabeled `true_fresh`. recon_true_fresh.sh now drops
  hosts already in the known_hosts ledger (`grep -a` — it has NUL bytes); existing mislabels written
  back across ES.
- **Archive proxy (the big yield fix)** — IA blackholes web.archive.org/CDX (and CommonCrawl) for
  our Mullvad datacenter egress, so gau/waybackurls returned 0. Added a locked Cloudflare worker
  (`tools/cdx_worker.js`) that proxies Wayback CDX from Cloudflare's unblocked egress; `crawl_host`
  now does katana(live,Mullvad) + gau(otx/urlscan) + archive_fetch(worker). Only the public-archive
  lookup leaves via Cloudflare — the target is never contacted; all target traffic stays on Mullvad.
- **Liveness verification + tracking-param filter** — archive URLs are historical → dead 404s +
  analytics-only params. crawl_host drops tracking-ONLY URLs (utm_*/fbclid/gclid/…); new `verify-live`
  stage (daemon `params-live` loop) probes catalog URLs deduped by path, KEEPS live, DELETES dead
  (404/410), leaves transient for retry — so only worth-keeping, live params remain.

## v3.7.0 - 2026-06-07 - Be UNIQUE: differentiated pillars (JS-intel, IDOR, n-day, GH-leaks, briefing)

Hard pivot after an honest reckoning: the pipeline was a commodity dupe-factory (default
nuclei on saturated programs) and its only submission was a dup. Researched how the top
earners / XBOW / AI hunters actually win and rebuilt around the edge — go where the crowd
doesn't, use Claude's understanding where tools are blind, be first. ADDITIVE: every
existing working lane (takeover, injection confirmers, the Claude brain, discovery,
js-scanner, …) kept; five unique pillars added.

- **recon_jsintel.sh** — mine each host's JavaScript for the HIDDEN API surface (jsluice,
  filtered) + verify LIVE secrets (trufflehog --only-verified; fixes our 53%-FP token noise).
  Proven: 244 clean endpoints incl. admin actions from admin.indeedflex.com's JS.
- **recon_ai_idor.sh** — the money pillar: Claude reasons over that surface → ranked
  BAC/IDOR worklist with the exact two-account test. Proven: 10 ranked leads incl. critical
  priv-esc on /admin/agency_shift_workers/bulk_update. (Reasoning only; human exploits.)
- **recon_nday.sh** — n-day racing without the KEV false-positive: Claude version-reasons
  CVE matches, dropping tech-class FPs (proven: killed 3/3), surfacing only in-range candidates.
- **recon_ghleaks.sh** — GitHub-leak hunting: code-search → trufflehog-verify live secrets +
  GitHub subdomain harvest. Token-gated.
- **recon_briefing.sh** — the 6:30pm "TONIGHT" card: IDOR leads to test + validated findings
  to submit (pulls real findings from the brain). Proven compile.
- Fixes en route: IFS space-split bug that silently zeroed the param-confirm + DAST injection
  lanes; gate nuclei -c concurrency so probes finish instead of timing out at 63%.
- All wired as daemon loops (38 total, +5), recon-ctl stop pattern updated, CLAUDE.md motto.


## v3.6.0 - 2026-06-07 - Claude becomes the BRAIN: hard gate + consensus panel + authored reports

Claude was a bypassable filter at the edges. Now it owns the decisive path — the verdict,
the FP-kill, and the report — so it is load-bearing and drives FP elimination + report quality.

- **HARD GATE** (`engine/reporter.py`) — nothing reaches a report without Claude's
  `ai_verdict='real'`. Removed the deterministic-confidence bypass; if the AI layer is down,
  confirmed findings wait (nothing auto-ships un-validated).
- **CONSENSUS PANEL** (`recon_ai_review.sh`) — the FP-elimination engine. The primary pass
  investigates (multimodal + active probe); a confident fp dies cheaply; anything heading
  toward `real` (or uncertain) faces a panel of independent adversarial lenses, each trying
  to REFUTE from a distinct angle — **exploitability**, **scope-&-reward** (would a program
  pay, not a dup/N/A), **evidence-&-repro**. Unanimous confirm → `real`; majority refute →
  fp; else needs-human. Panel uses the strong model. Verified: eToro CORS → 3 lenses refuted
  with distinct concrete reasoning → CONSENSUS FP.
- **CLAUDE-AUTHORED REPORTS** (`recon_ai_review.sh` + `engine/{state,reporter,formatters}.py`)
  — for a consensus-`real`, Claude writes the report: honest severity (no overclaiming),
  impact, reproducible read-only PoC from the actual evidence, dedup assessment. Stored in a
  new `ai_report` column (idempotent `_migrate` ADD COLUMN); renderers use it, template is
  fallback. Verified: authored High/CVSS-8.2 packet flows through the H1 renderer.

## v3.5.0 - 2026-06-07 - Anti-burn rate limiting + Claude MONITOR role (unattended-ready)

Hardening so active verification can run unattended without getting the egress IP banned,
plus Claude's third role — oversight. Claude now spans the whole pipeline: ANALYZE (aim the
net) → VERIFY + safe probe (confirm) → MONITOR (oversee).

- **Anti-burn rate limiting** (`recon_safe_probe.sh`) — the article's politeness rule, in
  code: min-gap + jitter between probes, per-host and global rolling-window caps, a host
  COOLDOWN on a 429/403/503 (back off the moment a target pushes back), and a global
  CIRCUIT-BREAKER that pauses ALL probing after repeated blocks. All `PROBE_*` tunable.
  Verified: per-host cap, min-gap timing, cooldown-on-403, global breaker all fire.
- **Claude MONITOR** (`recon_ai_monitor.sh`, hourly daemon loop) — read-only reasoning over
  LOCAL telemetry (burn signals, verdict precision, failures/halts, daemon errors, VPN);
  emits a skeptical health + burn_risk + guidance card to #ops and `recon-ai monitor`,
  persisted to `~/recon/state/ai_monitor_latest.json`. Issues NO target traffic. Primary
  job: catch "getting burned" early. Registered in the daemon; added to stop LOOP_PAT.
- Full pre-flight audit passed: python+bash compile/syntax; invariant that the VERIFY agent
  never gets Bash (only Read/empty tools); probe guard battery (metadata/POST/file/
  out-of-scope/vpn_down all refused) re-verified post-rewrite; vpn_down fail-closed in every
  target-facing loop; no secrets in git.

## v3.4.0 - 2026-06-07 - Active verification: Claude runs safe tests (harness-mediated)

VERIFY can now ACTIVELY TEST a finding, not just reason over stored evidence — "Claude can
run any safe test it wants to verify" — without ever giving the model execution capability.

- **Harness-mediated safe probing.** When the evidence can't settle a finding, Claude sets
  `verdict="need-probe"` and lists `probe_requests` (url + GET/HEAD/OPTIONS) in its
  schema-validated output. The TRUSTED harness — not Claude — runs each through the new
  `recon_safe_probe.sh`, appends the real responses, and re-judges. Bounded by `PROBE_ROUNDS`
  (2) and `PROBE_BUDGET` (6) per finding.
- **Why harness-mediated (security finding).** Adversarial testing showed scoped-Bash does
  NOT confine the model: `--permission-mode dontAsk` auto-approves "benign" commands (echo,
  id) regardless of `--allowedTools`, so a prompt-injected agent with Bash could run
  `cat ~/.recon_es_pass`. Therefore Claude gets NO shell — only `Read` (the screenshot,
  proven path-confined by `--add-dir`). The model only *requests*; the harness executes.
- **Safe by construction** (`tools/safe_probe_worker.py` + `scripts/recon_safe_probe.sh`):
  unauthenticated, GET/HEAD/OPTIONS only, no credentials, no redirect-follow, SSRF/metadata
  guard (refuses any host resolving to private/loopback/169.254/reserved/multicast), live
  scope+pays gate at probe time, per-finding budget (anti-runaway), polite jitter, full
  audit log, vpn_down fail-closed, Mullvad-only egress. Unauthenticated ONLY — authenticated
  testing stays human-in-the-loop.
- Verified end-to-end on a real in-scope host: a finding claiming an unauth admin panel at
  /admin/ → Claude requested 3 probes → harness GET/HEAD'd them → real 404 (IIS default) →
  FP 0.98 citing the probe results. Guard battery all green (metadata/internal/POST/file:///
  out-of-scope/over-budget/vpn_down all refused).
- Doctrine (CLAUDE.md) updated: autonomous active verification is allowed, but ONLY as safe
  unauthenticated non-destructive probes via the vetted harness; the model never executes.

## v3.3.0 - 2026-06-07 - Claude at full capability: multimodal, schema-locked, measured

Built with the pipeline maintenance-locked. The Claude layer was using ~half its
capability — judging from a one-line summary string. Now it works the actual case file,
multimodally, while staying pure reasoning (never issues a request against a target).
Every change verified end-to-end on Max auth (claude 2.1.165): real ES + real Claude.

- **MULTIMODAL VERIFY** (`recon_ai_review.sh`) — the asset SCREENSHOT is handed to Claude
  as primary evidence. Each finding gets a throwaway temp dir holding ONLY its own
  screenshot; Claude is Read-scoped to that dir (`--tools Read --add-dir --permission-mode
  dontAsk`), never the broader filesystem. Proven: a `cors-misconfig`/"unauth-surface"
  gate hit on the eToro marketing homepage → **FP 0.95**, reasoning citing the screen
  ("eToro marketing homepage, no admin surface"). Findings also enriched with ES asset
  truth (tech/title/server/status/content-type/final-url + the gate's nuclei evidence).
- **SCHEMA-VALIDATED OUTPUT** (both agents) — `--json-schema` → `.structured_output`,
  replacing brittle regex/text-scraping (kept as fallback). Root must be an object (the
  API wraps it as a tool input_schema; a top-level array 400s) — analyze verdicts live
  under `assets`.
- **SMARTER ESCALATION** — re-judge with the big model on genuine ambiguity OR a
  LOW-confidence (<0.75) real/fp, not just literal `needs-human`.
- **ANALYZE MODEL TIERING** (`recon_ai_analyze.sh`) — a chunk whose top `triage_score` ≥
  `ANALYZE_HI_SCORE` (60) is judged by sonnet; bulk stays haiku.
- **PRECISION SELF-AUDIT** (`engine/state.py ai_accuracy` + `recon-ai accuracy` + daily
  digest) — measures the human-decided precision of `real` verdicts (accepted=submitted
  vs rejected=dismissed) — the only ground truth — plus verdict mix, escalation count,
  AI-learned FP signatures, KB size. We measure the layer now instead of asserting it.
- **FIX** — `recon-ctl` `_ai_table`/`detail` still read the dropped `tier` column; removed
  (would error once `_migrate` drops it live). Never pass `--bare` (forces API-key auth,
  bypasses Max OAuth).

## v3.2.0 - 2026-06-07 - Claude analysis layer, wide reliable multi-class net, clean ES

Two Claude layers + a precise per-class confirmation net, all FP-gated. "Bigger net,
more fish — without drowning in noise." Built with the pipeline maintenance-locked.

**Claude as the reliability layer (both on Max, headless, no API key/spend):**
- NEW `scripts/recon_ai_analyze.sh` — ANALYSIS agent (Haiku, bulk/cheap): reads in-scope+
  paying assets (prioritised true-fresh→score, quota-bounded, TTL'd), decides worth /
  interest / vuln-class, writes `claude_*` to ES, and flags evidence-gate candidates.
  Conscious surface selection (not blanket scanning); feeds the gate → verify.
- `recon_ai_review.sh` — VERIFY agent now: injects KB context (RAG-lite), escalates
  ambiguous `needs-human` to opus, mirrors the verdict to ES (`claude_verdict/confidence/
  reason/reviewed_at/verify_model`), records every outcome to the knowledge base, and
  posts the human-decision card to **#review** on `real`/`needs-human` (fp silent).
- `v3/state.py` — `knowledge_base` table + `kb_record`/`kb_lookup` (keyword RAG-lite, no
  embedding dep); `umask 0o002` so the cross-user gate(reconrun)/agents(d0k) SQLite
  writes stop hitting "readonly database".
- `triage.sh` — Claude prioritisation bonus alongside true_fresh (`real` +8 & clamp-
  exempt, `fp` −12 suppress, `worth` interest-scaled). Validated on live data.

**Wide reliable multi-class confirmation (each SAFE: unauth, non-destructive):**
- XSS — browser marker EXECUTION (`tools/xss_confirm_worker.py`, Playwright); offline-validated.
- SSTI / open-redirect / SQLi — HTTP differential (`tools/param_confirm_worker.py`:
  `{{a*b}}`→product / `Location`→canary / error-diff on `'` vs `''`, no data harvest);
  driven by `recon_param_confirm.sh` over the params catalog. Offline-validated.
- GraphQL / Swagger-OpenAPI — nuclei detection in the evidence gate.
- SSRF / XXE — gate OOB probe via interactsh (projectdiscovery); callback = definitive.
- IDOR / LFI / RCE — operator-LEAD only (hard line). Claude routes each class
  (`map_gate_class`); pattern-match = LEAD, primitive firing = CONFIRMED; all flow
  through Claude verify (the adversarial FP filter) → #review.

**Params net reliability** — was covering 0.05% (178/342k hosts), erratic:
- `recon_params.sh` per-host crawl parallelised (`PARAM_PARALLEL=4`), hosts/cycle 10→30,
  pool 400→1200, `waybackurls` gau fallback; per-host rate-limits + jitter preserved.
  ~480→~3600 host/day ceiling — feeds the confirmers instead of starving them.

**Clean ES (production)** — `recon_alive` reindexed into clean `recon_alive_v3` (alias-
  swapped; original kept 7d as `recon_alive_old`): dropped 26 dead fields (11 Ollama
  `ai_*` + 13 legacy orphans + 2 stray), retyped 3, 722460 docs verified. NEW
  `scripts/recon_es_reindex.sh` (gated, count-verified). Bootstrap/validate templates +
  `verify_mapping` updated to `claude_*`; index ops are alias-aware.

**Discord v3** — verdict-driven, 9 channels → 4 (`#review`/`#takeovers`/`#ops`/`#digest`);
  shared webhook dir; `observability.py` posts a compact daily `#digest`.

**Scope is the only gate** — removed the Gate-0 financial-tier classifier entirely
  (`v3/tier.py` + `tier_list.tsv`, the `tier` column, the GENERAL/FINANCIAL autonomy
  split, and the `staged`/PoC-staging state). If a host is in scope, it's in play; the
  hard line is now the *type* of action (no unsupervised authed/state-changing requests,
  hard-coded fund-moving endpoint denylist), not the program. `state.py init` self-heals
  older DBs (idempotent `_migrate` drops a stray `tier` column natively).

**Unified repo layout** — renamed the version-named code dir `v3/` → role-named
  `engine/` (the Python detection→validation→report package), so every top-level dir is
  now role-named (`scripts/`, `tools/`, `engine/`, `docker/`, `docs/`). Done as `git mv`
  (history preserved) + repointed the 7 code-path references (STATE_PY / `V3_PY_DIR`).
  Least-damaging on purpose: the **runtime data dir** `~/recon/v3/` (live findings.db,
  reports, digests) and the `V3_*` env-var names are left untouched — moving a live DB
  with the daemon up is a separate, WSL-up maintenance step. All engine call sites are
  guarded (`[[ -f ]]`/`|| true`), so the rename self-heals on the next daemon cycle.

**Ops/cleanup** — `recon-ctl maintenance on|off` lock (fail-closed start guard);
  `ai-analyze`/`xss-confirm`/`param-confirm` daemon loops (d0k, VPN-gated where target-
  facing); `cmd_stop` LOOP_PAT updated. Purged dead Ollama dashboard columns from
  `recon_ctl` (cmd_top/fresh/view/leads) + removed unreachable `cmd_firstblood`; added
  `recon-ai analysis`. Live integration of target-facing confirmers pending go-live.

## v3.1.0 - 2026-06-07 - Claude-Max validation agent becomes the AI layer; Ollama retired

The AI layer is now **Claude on the Max plan, headless (`claude -p`), no API key/spend**
— the article's "validation agent." It judges only evidence-gate-CONFIRMED findings
(a handful/day) adversarially (assume false-positive until the evidence proves
otherwise) and writes a verdict to SQLite. This replaces the legacy Ollama pre-scorer
entirely: detection + the deterministic evidence gate are the cheap pre-filter; Claude
validates the confirmed survivors for accuracy/relevancy.

- **NEW `scripts/recon_ai_review.sh`** — Claude-Max validation agent (daemon `ai-review`
  loop, runs as `d0k` for Claude auth). Pulls confirmed findings via `state.py ai-pending`,
  one adversarial prompt each, parses a single-line JSON verdict, writes via
  `state.py ai-verdict`. `real` → reaches reporter; `fp` → dismissed + FP signature
  learned; `needs-human` → held for operator. Graceful no-op if `claude` is missing
  (deterministic confidence stands). Live-validated end-to-end on real Claude: a CORS
  info-hit → `fp` (0.95, dismissed+learned), a Jenkins script-console template-only hit
  → `needs-human` (0.6, "template match alone is unconfirmed — manual GET required").
- **`v3/db/schema.sql`** — `findings` gains `ai_verdict / ai_confidence / ai_reason /
  ai_reviewed_at`. **`v3/state.py`** — `ai-pending` / `ai-verdict` CLI + `record_ai_verdict`
  (fp → dismiss + FP signature). **`v3/reporter.py`** — reports only
  `ai_verdict='real'` (deterministic `confidence >= fallback` only when AI un-run).
- **RETIRED the Ollama AI-review layer**: `git rm` `recon_ai_score.sh`, `recon_ai_pack.sh`,
  `recon_ollama.sh`; removed `triage.sh`'s `run_ai_review_layer` call + the
  `ai_recommendation/ai_relevance_score` scoring map and sort key (triage scoring is
  deterministic again); dropped `ENABLE_OLLAMA_AI/OLLAMA_*/AI_MAX_LEADS` from the daemon
  and the `ai_review/` dir creation; bootstrap now one-time-`rm -rf`s the legacy
  `~/recon/ai_review` packet queue (claude/codex/pending/done/rejected + ai_scored.jsonl).
- **`recon-ai` (`recon_ctl.sh cmd_ai`) rebuilt on SQLite** — `status` shows validation-agent
  health + verdict breakdown (real/needs-human/fp/pending/reported); `real|human|pending|fp|
  top|detail` subcommands query `findings.db` via a read-only `_ai_db` helper. Fixed the
  footer that advertised the now-dead `recon-ai-now/recon-ai-high`.
- **Docs** — `claude.md` *(removed in v3.2; superseded by README + CLAUDE.md)*, `agent/CLAUDE.md`, `agent/init_prompt.md`, `v3/README.md` updated
  to the Claude-Max validation model (flow diagram now shows the `ai-review` node; operator
  brief reads verdicts from SQLite / `recon-ai`, not `ai_scored.jsonl`).

## v3.0.0 - 2026-06-07 - detection → validation → report (evidence gate + state machine + orchestrator)

New `v3/` layer that turns detection into confirmed, reported, non-duplicate findings
plus safety scaffolding for unattended operation. Scanners unchanged (kept as tools).
ES = asset truth; SQLite (`~/recon/v3/findings.db`, WAL) = finding-state truth. Each
phase committed + self-test validated; live integration pending (daemon was stopped
during build, no target-facing probes run). See `v3/README.md`.

- **Gate 0** — `v3/tier.py` + `tier_list.tsv`: financial-tier classifier, default-unknown
  → FINANCIAL; GENERAL only via human review. 609 programs seeded FINANCIAL/unreviewed.
- **Phase A — evidence gate** — `triage.sh` clamps every detection-only P0 to a
  P0-CANDIDATE (held at P1); `recon_evidence_gate.sh` runs the non-intrusive class
  probe (nuclei detect/exposure, dalfox via params-verify, bypass auth-differential)
  and promotes to P0 only on a real fire; N=5/3h/5d → lead-exhausted. Reconnects
  nuclei/dast as the gate's probes. Daemon registers the `evidence-gate` loop.
- **Phase B — state machine** — `db/schema.sql` + `state.py`: guarded atomic
  transitions, WAL crash-safe resume (stale `verifying`→`scored`, no double-fire),
  FP-signature table (queried before scanning), failure_patterns (6-cat backoff),
  run_counters, audit_log.
- **Phase C — reporter** — `formatters.py` + `reporter.py`: Finding → H1/Bugcrowd/
  Intigriti reports; dup pre-check; evidence-freshness re-probe (since-patched →
  bounce, not reported); never auto-submits.
- **Phase D — orchestrator** — `orchestrator.py`: tier autonomy boundary (GENERAL
  autonomous read-only / FINANCIAL detect+stage-only); hard-coded guardrails (4
  concurrent, per-program 750/day, ban/captcha/3×403 → halt-no-resume, scope gate,
  fund-moving endpoint denylist, backoff, $20 LLM spend ceiling, vpn pause).
- **Phase E — observability** — `observability.py`: auditable daily digest from SQLite.

## v2.9.0 - 2026-06-06 - Triage P0 false-positive hardening (CONFIRMED vs LEAD)

Established the CONFIRMED-vs-LEAD discipline (see CLAUDE.md): only a directly
observed exploitable primitive mints P0; pattern/class matches are LEADs (P1-max);
stale-past-TTL → LEAD. Worked through a multi-phase pass; one validated change per
phase.

### PHASE 0 - Fixed: two P0 false-positive classes + stale-priority persistence (triage.sh)
- **Spring actuator KEV → LEAD.** `tech:spring-actuator` (+ defensive `tech:springboot`/
  `tech:actuator`) added to the surface/version-unverified KEV gate in
  `apply_scope_kev_enrichment`. A bare spring fingerprint's `/actuator` surface is
  usually auth-gated (401/404); it now scores `KEV_UNVERIFIED_BONUS` (+1) and tags
  `version-or-surface-unconfirmed`, not full `KEV_BONUS`.
- **Critical-port exemption now requires portscan-confirmed-open.** `score_raw`'s
  `has_critical_port` gate previously fired on the recorded `.port` number alone; a
  host can carry `.port=6379` while nmap shows 0/10 open. Now gated on membership in
  `portscan_open_ports[]` (the portscanner's confirmed-open set).
- **Enforcement clamp (`cap:kev-unverified-no-p0`).** Reducing the KEV bonus alone
  could not clear P0 — a confirmed tech base (+7/+9) plus payout-tier already reaches
  the P0 threshold of 15. New `kev_unverified_sole` flag (set when an unverified-KEV
  host has NO exploit evidence independent of the version/surface-bound fingerprint —
  no other confirmed signal, no portscan-confirmed critical port, no confirmed
  takeover) clamps the host to P0_THRESHOLD-1 in Phase 2.
- **Root cause of stale P0 surviving a full re-score: `demote_dropped_docs()`.**
  `update_es_scores` only writes P2+ survivors, so any fetched doc dropped by the
  score floor / Phase-2 selects (ignored -50, UUID -10, low-score, out-of-scope)
  kept whatever `triage_priority` a prior run wrote. Added a primitive-safe
  demotion-writeback: dropped docs whose fetched priority was P0/P1/P2 are reset to
  P3, EXCEPT those carrying an out-of-band confirmed primitive
  (`portscan_critical` / `bypass_confirmed` / `takeover_confirmed`).
- **Index-wide re-score + one-time cleanups.** Full re-score (`TRIAGE_MODE=full`)
  rewrote 347,890 survivors; stale `takeover:dangling-cname` tags (593, pre-fix
  leftover — no current emitter, 0 `takeover_confirmed`) demoted to P3; 2,978 stale
  P0/P1 demoted (primitive-guarded).
- **Validated:** P0 1006 → 739 (738 current-logic + 1 protected primitive,
  `sandbox-api.fireblocks.io`, 47 confirmed-open ports). Safety audit clean — 0 of
  the 939 `kev_unverified_sole` / 2,978 `stale_reset` docs carry a confirmed
  primitive. Real findings retained: fireblocks P0, `qa-www.elastic.co`
  (`bypass_confirmed`) P1. `needs_verify=version-or-surface-unconfirmed` 202 → 484.
  (NOTE: PHASE 1 later reclassified fireblocks as a CDN phantom → P1; see below.)

### PHASE 1 - Fixed: portscan reliability — CDN phantoms, scan artifacts, stale opens
A connect-scan against a CDN edge ACKs every port, so naabu "opens" behind a CDN are
phantom (real case: `sandbox-api.fireblocks.io`, 47 "open" ports incl Docker/Redis/
Kafka/ZK, all Cloudflare). Stale `portscan_open_ports` also mislead (atlas.ripe.net
showed 2181/11211; live nmap = filtered). Implemented CONFIRMED-vs-LEAD discipline
for the portscan lane:
- **(a) CDN-range emit guard (recon_portscan.sh).** New `ip_in_cdn()` (integer CIDR
  match over Cloudflare/Fastly/Akamai blocks) — in addition to the existing
  cdn_name/IP-dedup/httpx filters. A CDN-range IP now never emits `portscan_critical`.
- **(b) Artifact cap.** >6 "open" critical ports on one host = scan artifact →
  `portscan_suspect=true`, excluded from scoring.
- Suspect hosts: `portscan_critical=0`, `portscan_open_ports=[]` (audit copy in
  `portscan_suspect_ports` + `portscan_suspect_reason`), no score bump, no P0 promotion.
- **(c) Freshness TTL (triage.sh).** `has_critical_port` now requires the portscan
  confirmation to be FRESH (`portscan_at` within `PORTSCAN_CONFIRM_TTL_SECS`, default
  7d) AND `portscan_suspect != true`. Stale/suspect → LEAD, cannot exempt a host from
  the pattern_only clamp.
- **Backfill (snapshot first):** the 2 existing `portscan_critical=1` docs (atlas,
  fireblocks) reset — `portscan_critical` 2 → 0, `portscan_suspect`=2, +12 bonus
  removed, phantom `port:*` signals stripped, priority recomputed (fireblocks P0→P1,
  atlas P1→P3). **P0 739 → 738.** Snapshot:
  `state/phase1_portscan_snapshot_*.json`.

### PHASE 2 - Fixed: scope --pays leak was stale data, not a program-level field
- **Finding (lanes are correct).** Audited every output lane — fetch (recon_ctl
  cmd_fetch), takeovers, nuclei, screenshot, digest, restale, fresh_modules,
  portscan, dast, params — ALL filter on `triage_pays`, the **per-target
  authoritative** field (recon_scope_db.sh per-target `pays`, line ~154, → scope TSV
  → scope_check → triage_pays). **No lane uses program-level pays.** The scope TSV is
  correct (`*.bpost.be` handle "dummy" = pays=false, in-scope VDP).
- **Root cause of the leak:** STALE `triage_pays=true` on docs triage never rewrote
  (dropped before writeback — same persistence class as PHASE 0). `recon-fetch --pays`
  returned develop.bpost.be because its ES `triage_pays` was stale (last written
  before the bpost FP fix).
- **Data resync (authoritative, snapshot first).** Re-checked all 8,946 stale-pays
  (not-rewritten) hosts against the scope DB; **769 were authoritatively pays=false**
  (incl 624 program="dummy"/bpost) → flipped to `triage_pays=false`,
  `triage_payout_tier=none`. The other ~8,177 are legitimately paying (dropped but
  in-scope) — left untouched. Snapshot: `state/phase2_pays_snapshot_*.jsonl`.
  `develop.bpost.be` now pays=false; program=dummy & pays=true: 624 → 0.
- **Recurrence fix (triage.sh `demote_dropped_docs`).** The demotion-writeback now
  also refreshes `triage_pays` / `triage_in_scope` / `triage_out_of_scope` /
  `triage_payout_tier` from the FRESH enriched verdict for every dropped doc (absent
  from the enriched set ⇒ out_of_scope ⇒ pays=false), so a doc can no longer retain a
  stale paying verdict after it drops out of scope/score. Primitive guard unchanged.

### PHASE 3 - Fixed: JS secret detector re-scoped to CONFIRMED vs LEAD (recon_fresh_modules.sh)
A token-shaped string is not a secret. Of the current JS findings, **17/17 "secret"
hits were `google_key`** (Google AIza browser keys — public-by-design). Re-scoped the
detector:
- **CONFIRMED secret** (finding_type=`secret`, mints `js_secret_hit`): `aws_key` AKIA,
  `private_key`, `conn_string` (db creds) — kept — PLUS added high-confidence
  server-token prefixes: GitHub `ghp_/github_pat_`, Slack `xox*` + webhooks, Stripe
  `sk_live_/rk_live_`, GitLab `glpat-`, SendGrid `SG.`, npm `npm_`, Twilio `SK…`,
  Mailgun.
- **LEAD** (finding_type=`secret_lead`, does NOT mint `js_secret_hit`): `google_key`
  (AIza), `jwt` (client JWTs are usually anon/public).
- **Public-by-design excluded** (context-aware — new `_match_one` keeps line context
  so markers actually fire): Stripe `pk_`, `googleusercontent.com` OAuth client_id,
  `apiKey`/`publishableKey`/`anon_key`, and `NEXT_PUBLIC_`/`VITE_`/`REACT_APP_`/
  `VUE_APP_` env prefixes.
- **(c)** findings now store a redacted `sample` (`first6***last4`) + `match_type` for
  auditability (was: boolean only).
- **Projected:** confirmed-secret findings from the current corpus **17 → 0** (all 17
  `google_key` → leads); real high-confidence credentials caught going forward.
- **NOT bulk-applied:** re-scanning the JS corpus is target-facing — deferred (it runs
  on the next scheduled fresh-modules cycle with the new ruleset).
- **Live-verified + backfill (2026-06-06):** post-commit scans confirmed 0 google_key/jwt
  written as `secret` and the new `sample` field present. `findings.jsonl` is append-only,
  so 17 pre-commit google_key(11)/jwt(6) `secret` lines persisted and kept
  `js_secret_hit=5` alive — downgraded those to `secret_lead` and cleared the 5 stale ES
  flags (`js_secret_hit` 5→0). Snapshot: `state/phase3_findings_snapshot_*.jsonl`.

### PHASE 4 - Fixed: XSS verify was reflection-only → now requires break-out (recon_params.sh)
`recon-params verify xss` labelled `[XSS CONFIRMED]` on bare canary reflection
(`grep -qi d0k_recon`) — so a value reflected inside a JSON string (e.g. Shopify
`utm_campaign`, inert) was mislabelled exploitable. Now:
- Inject a break-out payload `'"></script><d0kxss>` and CONFIRM only if the unique
  tag `<d0kxss>` survives **UNENCODED** in the response (real executable HTML
  injection).
- Reflection where the angle brackets are entity-encoded (or the marker only appears
  in a JSON/encoded context) → `status="reflected-not-exploitable"` (LEAD) — logged
  but NOT counted as a confirmed hit and NOT labelled CONFIRMED.
- `verify_xss.jsonl` now carries `status` + `confirmed` (bool). Validated: raw tag →
  confirmed; encoded / JSON-string reflection → lead; no reflection → no hit.

### PHASE 5 - Fixed: params candidate starvation — bias to param-surface hosts (recon_params.sh)
`collect` ran every 30 min but indexed ~0 because the score-sorted in-scope pool was
full of API/staging/device hosts with no GET-parameter surface. cmd_collect candidate
selection now:
- **Excludes no-GET-param-surface host shapes** (API/RPC: `api`/`apis`/`graphql`/
  `grpc`/`gql`; brokers/IoT: `mqtt`/`push`/`device`/`iot`/`broker`; mail/DNS:
  `smtp`/`imap`/`pop`/`mx`/`ns`/`dns`) — these have no archive param-URLs and burn
  GAU quota. Conservative `^name[.-]` anchor (keeps e.g. `apidocs.`, `pushsgp.`).
- **Biases toward proven archive coverage:** floats hosts whose `root_domain` already
  appears in the params catalog (`recon_params`, 130 covered roots) to the front of
  the candidate list (score order preserved within groups). New roots still get
  scanned, just after proven ones. Validated: exclusion + reorder logic in isolation;
  takes effect next collect cycle (no target-facing re-run tonight).

### Fixed — recon-stop now FULLY stops everything (recon_ctl.sh cmd_stop)
- The kill logic no longer gates on the pidfile. The old code printed "Not
  running" and killed NOTHING when the pidfile was missing/stale — which left
  orphaned supervise_loop subshells (reparented to PID 1, shown as
  `bash recon_daemon.sh`) firing scanners forever, plus in-flight reconrun-owned
  scanners still sending traffic. (Observed live: a "stopped" pipeline with ~19
  orphaned daemon procs and reconrun httpx still running.)
- Now ALWAYS pkills recon_daemon.sh (master + orphaned loops) + every module
  loop + the discord bot, kills gungnir's setsid process group, and kills
  reconrun-owned scanners/tools via `sudo -n -u reconrun pkill` (recon_ctl runs
  as d0k and otherwise cannot signal reconrun procs). Verifies + reports leftovers.

### Added — VPN leak guard (recon_vpnguard.sh + daemon wiring)
- Fail-closed guard as the FIRST, fastest daemon loop (VPNGUARD_INTERVAL=20s).
  Authoritative check: am.i.mullvad.net `mullvad_exit_ip`.
  * CONFIRMED leak (reachable, says NOT a Mullvad exit = real VPN drop) → trips
    immediately (LEAK_THRESHOLD=1): sets $STATE_DIR/vpn_down and kills ALL egress
    (reconrun scanners + tools + gungnir + passive feeds + discord bot).
  * "unknown" (check service unreachable — usually transient/rate-limit under
    scan load, NOT a leak) → 3 retries/check, tolerated to UNKNOWN_THRESHOLD=6
    before a fail-closed backstop trip. (Initial naive fail-closed-on-unknown
    false-tripped a healthy pipeline once under load — fixed by this split.)
  * Auto-resumes (clears vpn_down) once Mullvad is reconfirmed.
- Daemon enforcement: supervise_loop pauses EVERY loop (guard exempt) while
  vpn_down is set; run_scanner hard-blocks launching any target-facing scanner;
  the discord bot loop also pauses. The pipeline cannot scan over the real IP.
- cmd_start refuses to launch unless egress is a confirmed Mullvad exit — the
  WSL2 preflight explicitly does NOT verify the tunnel. Override: RECON_SKIP_VPN_CHECK=1.
- Verified live: trip → kill-egress → pause → auto-resume cycle observed end to
  end; fail-closed on confirmed leak; stable (no false trips) under 150-thread load.

### Fixed — triage_true_fresh was ALWAYS false (recon_true_fresh.sh)
- The CT feed (true_fresh.jsonl) is written by recon_true_fresh as d0k, but
  triage runs as reconrun. mktemp(0600)+mv on the 7-day prune stripped the state
  dir's default reconrun ACL, so triage read an EMPTY true_fresh map and scored
  triage_true_fresh=false on every host — silently starving DAST fresh-first AND
  the Discord true-fresh alert gate. Now re-grants reconrun read after every feed
  write (setfacl u:reconrun:r, chmod 0644 fallback). Confirmed: runtime map went
  from {} to ~2000 entries readable as reconrun.

### Operator notes
- TRUE kill-switch: this guard DETECTS a drop and halts within a check interval
  but cannot block traffic at the instant a tunnel drops (the tunnel lives on
  Windows). For zero-exposure, ALSO enable Mullvad "Lockdown mode" in the Windows
  app — the OS/network-layer kill-switch WSL cannot provide itself.
- WSL interface churn: the active NIC migrates (eth0→eth7→eth8) across VPN/network
  events, which also wedged WSL twice. The v2.8 eth0-pinned MTU is therefore
  fragile; a udev rule setting MTU 1380 on any eth* is the durable fix (pending).

## v2.8 - 2026-05-23 - gungnir freshness engine, cloud/DAST lanes, Mullvad-safe parallelism

Studied g0ldencybersec (Gunnar Andrews) — gungnir, CloudRecon/Caduceus, sus_params,
and the DEF CON 32 "Efficient Bug Bounty Automation" talk — and rebuilt the most
fragile parts of the pipeline around his real-time-CT approach.

### Changed — freshness engine (recon_true_fresh.sh)
- PRIMARY freshness source is now **gungnir** (`~/go/bin/gungnir`, Go): a long-lived
  listener that streams ~30+ CT logs DIRECTLY in real time, filtered by
  `paying_roots.txt` (`-r ... -f`), piped into a no-network flock-append reader.
  Replaces certstream + crt.sh entirely.
- Why: certstream.calidog.io was chronically degraded (its Python client wedged in
  WSL2 D-state for 24h) and crt.sh is Cloudflare-blocked. Both hit single aggregator
  chokepoints over curl/python sockets that block uninterruptibly on half-open
  Mullvad WireGuard connections. gungnir uses Go's epoll netpoller + ctx-aware
  backoff, so a stalled log never blocks the others and the process stays killable.
- **certspotter** demoted to a low-frequency (hourly), bounded BACKFILL for
  newly-added roots / outage gaps (`CERTSPOTTER_BACKFILL=1`); gungnir carries realtime.
- `build_paying_roots` is now **PSL-aware** (`publicsuffixlist`, offline): emits true
  registrable domains (eTLD+1) instead of naive last-2-labels — which previously
  collapsed `*.foo.com.br` → `com.br` and made gungnir match the whole public suffix
  (flooded holding ~750 hosts/s, pushing real hosts past the flush cap). Plus a DENY
  set of shared cloud/CDN/multi-tenant-SaaS apexes (amazonaws.com, zendesk.com,
  auth0app.com, cloudfront.net, …). Net ~240x volume drop to real brand subdomains.
- gungnir listener launched under `setsid`; pidfile holds the process-GROUP id so the
  daemon and recon_ctl terminate gungnir + its reader together.

### Added — recon lanes (g0ldencybersec-derived)
- **recon_cloudrecon.sh** (daemon loop "cloudrecon", hourly): **Caduceus** neighbor
  cert-scan. Pulls IPs of already-validated in-scope hosts from ES, scans those exact
  IPs :443 for TLS certs, extracts co-hosted vhost domains from cert SANs,
  scope-filters in-scope-paying, queues `11_cloudrecon_*` batches. Deliberately NOT
  asnmap-based (asnmap returns hyperscaler ranges for cloud-hosted targets =
  infeasible/noisy). `CLOUDRECON_EXPAND_24=1` widens to each seed IP's /24.
- **recon_dast.sh** (daemon loop "dast", 30 min): **fresh-first** param-fuzz lane.
  Pulls in-scope-paying hosts from ES sorted `triage_true_fresh` DESC (gungnir feed
  first), then newest; skips hosts scanned within `DAST_COOLDOWN_DAYS` (7). Per host:
  katana + gau crawl → qsreplace dedup → `gf` filter (sus_params patterns in ~/.gf)
  → dalfox (XSS) + `nuclei -dast` (sqli/ssrf/lfi/…). Findings → ~/recon/dast/findings.jsonl
  + Discord. NOTE: live dalfox/nuclei fuzz path not yet exercised end-to-end (public
  test target was unreachable via Mullvad); chain components verified individually.
- Both lanes run as `reconrun` via Mullvad, killswitch-gated (`touch
  ~/recon/state/kill/v2_cloudrecon` / `v2_dast`).
- New tools installed: gungnir, caduceus, katana, gau, gf, qsreplace (`~/go/bin`);
  sus_params' gf-patterns copied to `~/.gf/`.

### Changed — Mullvad-safe parallelism (local resources idle; ceiling is tunnel + per-target)
- httpx (breadth: many hosts, ~1-2 req each): threads 80 → **150** (total rps still
  capped at 100, so no target is hammered). `ulimit -n 65536` in the daemon.
- caduceus (breadth: distinct IPs) `-c 100`.
- DAST depth tools made gentle PER HOST (protects the shared Mullvad exit IP from WAF
  bans): katana `-rl 15`, `nuclei -dast -rl 15`, dalfox `-w 20 --delay 50`.
- nuclei bounty scan `-bulk-size 25` (parallel across hosts, keeps its 10 rps cap).
- Did NOT add IP-rotation: for bug bounty it tends to backfire (programs want stable/
  allowlistable source IPs; rotation is a bot signal) and it doesn't fix the real
  ceiling (per-target politeness + tunnel health), which the above changes target.

### Operator action required (root; not done by the agent)
- Run `sudo bash scripts/setup_mtu.sh` to pin WSL eth0 MTU 1500 → 1380 (live + a
  systemd unit for persistence) so packets fit the WireGuard tunnel and stop
  blackholing under load. Cheap insurance; Mullvad's MSS clamping may already cover
  TCP today.

## v2.5.6-no-tor - 2026-05-15 - Strip Tor/proxychains, Mullvad-only egress

### Removed
- All Tor / proxychains4 plumbing. The pipeline now relies entirely on
  the host's default route (assumed Mullvad WireGuard), enforced by the
  nftables kill-switch on the `reconrun` uid.
- `-proxy` / `-http-proxy` flags from every CLI tool call:
  * recon_validate.sh:    httpx
  * recon_nuclei.sh:      nuclei (bounty + KEV scan paths)
  * recon_fresh_modules.sh: deep-scan nuclei
  * recon_discovery.sh:   subfinder
  * recon_scope_watch.sh: subfinder enrichment
- The `proxy_required` / `ensure_proxy_ready` / `run_net` blocks that
  were duplicated across 5 scripts. They now exist only in recon_net.sh
  as no-op shims for back-compat (so any future call sites compile).
- `USE_PROXYCHAINS=1` and `PROXY_URL=socks5h://127.0.0.1:9050` removed
  from tools/start_recon_safe.sh, recon_daemon.sh defaults, and the
  per-child env in `run_scanner`.
- `recon_discovery.sh`: removed the "Skipping assetfinder because
  USE_PROXYCHAINS=1" warning path — assetfinder now runs normally.
- README + RUNBOOK rewritten: no more Tor SOCKS references, kill-switch
  rule updated to allow only loopback + the Mullvad WG interface,
  troubleshooting section now diagnoses VPN not Tor.

### Changed
- tools/check_recon_killswitch.sh now does a direct egress test (should
  show VPN IP, not home IP) instead of a Tor-SOCKS test.
- recon_net.sh `curl_net`, `curl_direct`, `run_net` are all direct
  passthroughs; v2.5.5's `curl_direct` distinction (for Discord-bypass)
  becomes trivially correct everywhere.
- Single capable-mode profile commentary updated: bottleneck is now
  laptop/network, not Tor.

### Operator action required (NOT in repo)
- `/usr/local/sbin/recon-safe-preflight` (root-owned, not in this repo)
  must be updated: drop the "verify Tor SOCKS 9050" check, add a
  "verify Mullvad WG interface up + has default route" check.
- nftables kill-switch rule must be updated: instead of allowing
  `127.0.0.1:9050`, allow `oifname "wg0-mullvad"` (or whatever your WG
  interface is named). Loopback + local ES allowances unchanged.
- Mullvad daemon must be running before `recon-start`. If WG drops mid-
  run, the kill-switch correctly blackholes reconrun traffic — supervised
  loops back off and resume when VPN comes back.

## v2.5.5-day1-audit - 2026-05-15 - Perms, Tor-bypass, listener instrumentation

### Fixed
- v2.5.4 atomic mv left agent_targets.jsonl with mask::--- inherited
  from mktemp, blocking every reader. chmod 0664 + setfacl mask reset
  before mv.
- Discord bot polling + ALL webhook POSTs went through Tor via curl_net;
  Discord blocks Tor exits → HTTP=000 for 17h. Added curl_direct helper
  and switched bot api_get/api_post + triage notify + nuclei notify +
  smart-scan notify to bypass Tor for Discord traffic.
- Certstream listener `lstrip("*.")` was character-stripping incorrectly.
  Use explicit `startswith("*.")` prefix removal.

### Added
- Listener 5-min stats line (certs/domains_seen/matches/emit_errors/
  scope_size) so we can see if matching is firing.
- `emit()` failures surfaced instead of swallowed.

## v2.5.2-single-profile - 2026-05-14 - One sane multi-worker profile

### Removed
- `browse` / `boost` mode toggling. The `load_profile` case-statement,
  `~/.recon_mode` reads, on-battery auto-downgrade-to-browse path, and
  the `schedule` supervise loop (with `scripts/recon_schedule.sh`) are
  all gone.
- `recon_ctl mode`, `recon_ctl schedule`, `recon_ctl schedule-check`
  commands removed from dispatch + usage. `recon_ctl mode` now prints
  a deprecation notice.

### Changed
- One always-on production profile (`load_runtime_env` in `recon_daemon.sh`):
  HTTPX_THREADS=80, HTTPX_RATE=100/worker, HTTPX_MAX_RUNTIME=1200s,
  BATCHES_PER_CYCLE=3, VALIDATE_SLEEP=420s, DISCOVERY_SLEEP=1800s,
  HOT_SEED_SLEEP=300s, SCOPE_SLEEP=5400s. Tor SOCKS is the real bandwidth
  bottleneck — these values saturate it without melting the laptop.
- On-battery auto-throttle: halves HTTPX_THREADS + HTTPX_RATE and drops
  BATCHES_PER_CYCLE to 2 when AC is unplugged. Reported via `POWER_STATE`
  in supervise_loop log lines and `recon_ctl status`.
- `recon_ctl status` "Mode: ..." line replaced with "Power: AC | battery".

## v2.5.1-consolidation - 2026-05-14 - Collapse 4 scan modules into a dispatcher

### Changed
- Consolidated `recon_smart_scan.sh`, `recon_deep_scan.sh`,
  `recon_active_checks.sh`, and `recon_js_scanner.sh` into a single
  dispatcher `recon_fresh_modules.sh {smart-scan|deep-scan|active-checks|js-scan}`.
  All four shared substantial boilerplate (lockfile setup, Discord webhook
  loading, ES auth, true-fresh+paid host selection) — now deduplicated into
  one file with mode-specific functions and per-mode lockfiles. No behavior
  change.
- Daemon `run_smart_scan` / `run_deep_scan` / `run_active_checks` /
  `run_js_scanner` now call `recon_fresh_modules.sh <mode>`.
- `recon_ctl.sh stop` `pkill` pattern simplified accordingly.

### Removed
- `scripts/recon_smart_scan.sh`
- `scripts/recon_deep_scan.sh`
- `scripts/recon_active_checks.sh`
- `scripts/recon_js_scanner.sh`

## v2.5.0-true-fresh - 2026-05-13 - True-freshness engine and bounty-first pivot

### Removed
- Deleted the local `first_seen`-based "freshblood" scoring path: removed
  `novelty_bonus`, `freshblood_payday` / `FRESHBLOOD_PAYDAY_BONUS`,
  `DISCORD_ALERT_FRESH_HOURS`, and 🩸 markers from `triage.sh`, report output,
  and Discord embeds.
- Deleted `recon_fresh_confirm.sh` and all references (daemon supervise loop,
  `recon_ctl fresh`, `recon_discord_bot !fresh`, `v2_fresh` killswitch slot,
  `seed_seen_files` / `clean-start` paths, `pkill` patterns).

### Added — Phase 1: True-Freshness Engine
- New `recon_true_fresh.sh` (passive, direct egress — not via Tor): runs a
  certstream listener via single-instance pidfile that loads in-scope-paying
  patterns into memory and emits matching domains in real time, plus a 6h
  crt.sh poller. Hits hit a holding file, get scope-filtered + 24h-deduped,
  then split into `00_truefresh_<ts>_<batch>.txt` (500 hosts each) under
  `queue/inbox/`. Durable feed lives at `~/recon/state/true_fresh.jsonl`.
  Holding + per-host JSON responses cleaned every cycle.
- New daemon supervise loop `true-fresh` at `TRUE_FRESH_SLEEP=120`.
- `triage.sh` now loads `state/true_fresh.jsonl` and adds
  `triage_true_fresh`, `triage_true_fresh_bonus`, `triage_external_first_seen`.
  `TRUEFRESH_BONUS` defaults to 10 (sized to be meaningful but not dominant
  over confirmed-tech KEV/elite tier stacks).
- Discord gate is now strict: only `triage_true_fresh && in_scope && pays &&
  (P0 || P1) && !triage_ignored` reach Discord.

### Added — Phase 2: Browser-like HTTP
- `recon_net.sh` now exposes `random_user_agent()` and `browser_curl()`. The
  UA pool lives at `~/recon/state/user_agents.txt` (seeded with 16 current
  Chrome / Firefox / Safari UAs on Win/Mac/Linux). `browser_curl` adds
  matching Accept-*/Sec-Ch-Ua headers, derives `Sec-Ch-Ua-Platform` from the
  picked UA, and respects `USE_PROXYCHAINS`.

### Added — Phase 3: Bounty-focused detection
- `tools/sync_bounty_templates.sh` clones projectdiscovery/nuclei-templates
  shallowly and copies only templates tagged `exposed-panels|exposures|cors|
  open-redirect|idor|ssrf|xss|auth-bypass|misconfig` into
  `~/recon/nuclei/bounty_templates/`.
- New `recon_nuclei.sh bounty <target_file>` subcommand uses the curated set.
- New `recon_smart_scan.sh` (30 min): top 10 true-fresh + P0 hosts → bounty
  scan → Discord "BOUNTY FINDING" alert on new hits. Daemon loop
  `bounty-scan`.
- New `recon_deep_scan.sh` (daily): builds `nuclei/tech_template_map.json`
  from the curated set, then runs tech-specific templates per true-fresh
  host returned by ES. Daemon loop `deep-scan`.

### Added — Phase 4: Active confirmation
- New `recon_active_checks.sh`: HTTP-only safe probes via `browser_curl`
  (Tor-routed when enabled) against top 5 P0 true-fresh in-scope-paying
  hosts. Probes Docker API version, Jenkins /script, k8s /api/v1/secrets,
  Grafana datasources, GitLab open signup, Confluence anon. Positive results
  append to `triage/active_confirmed.jsonl`, update ES (active_check_result,
  active_checked_at, force priority P0), and fire a Discord "ACTIVE
  CONFIRMATION" embed. Daemon loop `active-checks` (10 min), gated by
  agent_targets mtime.

### Added — Phase 5: JS secret + endpoint disclosure scanner
- New `recon_js_scanner.sh` (30 min): for the latest true-fresh batch,
  fetches each main page via `browser_curl`, extracts `<script src>` URLs
  via a tiny Python HTMLParser, downloads each (≤2 MB), and matches against
  high-confidence regexes (AWS, Google API key, private key headers, JWT,
  connection strings) plus internal endpoint patterns. Strict ignore list
  drops heroku/firebase/example/test/etc. Findings emitted to
  `~/recon/js_findings.jsonl` (filename + match type only, never raw
  secrets). Per-host dump dir is removed immediately after scan.
- `triage.sh` integrates `js_findings.jsonl` and adds `js_secret_hit` /
  `js_endpoint_hit` signals with bonuses (+10 / +5), gated to true-fresh
  hosts.

### Added — Phase 6: Quality fixes
- 6A: `triage.sh` now reads `~/recon/vuln/vuln_targets.jsonl` and applies
  `triage_breaking_vuln` + tier bonus (T0=12, T1=8, T2=5, T3=2) — gated to
  true-fresh hosts only.
- 6B: simpler `fetch_es_data()` filter (drop `should/minimum_should_match`),
  `ES_PAGE_SIZE` bumped to 10000.
- 6C: new `recon_ctl ignore <host> [reason]` command appends a 7-day TTL
  record to `~/recon/state/ignored.jsonl`. Triage applies a -50 penalty to
  non-expired entries.
- 6D: tightened `pattern_only` — a host is now only confirmed (not
  pattern-only) if it has a `strength=="confirmed"` signal OR is on a
  critical port (2375, 2376, 6379, 27017, 9200, 9300, 5432, 3306, 11211,
  2181). Bare 403/5601-only hosts no longer count as confirmed tech.
- 6E: `recon_validate.sh` now accepts `--prefix <s>` and
  `--exclude-prefix <s>`. The daemon spawns two parallel lanes:
  `validate-fast` (`--prefix 00_`) every 120s for true-fresh batches, and
  the original `validate` lane (`--exclude-prefix 00_`) on its normal
  cadence. Per-lane lockfiles so they do not block each other.
- 6F: `recon_takeover_hunter.sh` recheck cadence dropped from 30 min to 15
  min. Inside `mode_recheck`, non-fresh hosts are skipped if probed within
  30 min, while true-fresh hosts (looked up in `state/true_fresh.jsonl`)
  always re-probe.

### Added — Phase 7: ES mapping
- `recon_validate.sh` `ensure_index()` now performs an additive PUT
  `_mapping` on every cycle for `triage_true_fresh*`, `active_check_*`,
  `js_secret_hit`, `js_endpoint_hit`, `triage_breaking_vuln*`,
  `triage_vuln_tier`, `triage_ignored*`, and `triage_external_first_seen`.
  No existing fields removed.

### Notes
- Certstream needs `pip install certstream`. If missing, the listener is
  skipped (warning logged) and crt.sh polling still feeds the engine.
- Certstream and crt.sh polling use direct egress — `recon_true_fresh.sh`
  bypasses `run_scanner` so it does not run under `reconrun`/Tor. All
  target-facing modules (smart/deep/active/JS scan) still run under
  `reconrun` via `run_scanner` and the kill switch.

## v2.4.4-audit-hardening - 2026-05-10 - Strict-mode and health audit

### Fixed
- Hardened `recon_cve_intel.sh` NVD fetch retries so curl/network failures do
  not bypass the intended retry logic under `set -e -o pipefail`.
- Made `tools/check_recon_killswitch.sh` non-interactive by requiring
  passwordless sudo up front and using `sudo -n` for privileged checks.
- Fixed `recon_ctl health` tool version display so banner-printing tools such
  as `httpx` show their actual version line instead of a blank value.

### Verified
- `bash -n` passed for all scripts and tools.
- `git diff --check` passed for touched files.
- Live non-scanning health checks passed: daemon running in boost, queue clean,
  ES reachable, AI reachable with 25 scored leads, and vuln status refreshed.

## v2.4.3-ai-score-visibility - 2026-05-10 - AI scoring log banner

### Added
- Added a visible ASCII AI review banner and per-lead progress lines to
  `recon_ai_score.sh` so daemon/manual logs clearly show when Ollama is scoring
  leads.
- Added rejected raw response capture under `~/recon/ai_review/rejected/` for
  any future invalid model output.

### Fixed
- Fixed AI JSON extraction so the parser reads the Ollama response body instead
  of losing stdin to the embedded Python script.
- Fixed AI candidate selection under `pipefail`; `jq | head` could abort with
  `141` before scoring began.

### Verified
- One-lead smoke test showed the banner and accepted `1/1`.
- Production run scored `25/25` leads with `rejected=0`.

## v2.4.2-tor-stability - 2026-05-10 - Remove forced Tor restart loop

### Fixed
- Diagnosed Tor "intermittency" as an external crontab issue, not a Tor crash:
  `d0k` had a cron entry restarting Tor every 3 minutes.
- Removed only that cron line and saved a backup at
  `~/recon/archive/cron_backups/d0k_crontab_before_tor_fix.txt`.

### Verified
- Tor PID stayed stable across the old 3-minute restart boundary.
- `127.0.0.1:9050` accepts TCP connections.
- Latest Tor journal entries no longer advance with a new 3-minute
  stop/start cycle.
- Pipeline health stayed clean without stopping the daemon.

## v2.4.1-live-hotfix - 2026-05-10 - No-stop health and AI cleanup

### Fixed
- Prevented `recon_vuln_feed.sh status` from exiting `141` under `pipefail`
  after printing top matches. The daemon now treats successful vuln-feed
  refreshes as successful instead of backing off after a good run.
- Corrected `recon_ctl health` duplicate-worker counting so wrapper `sudo`
  processes and child shell helpers do not appear as duplicate daemon workers.
- Hardened Ollama review output handling by requesting Ollama JSON mode and
  extracting JSON from wrapped responses before rejecting a lead.

### Verified
- Applied without stopping the daemon.
- `bash -n` passed for touched scripts.
- `git diff --check` passed.
- Live health now reports one discovery worker, one takeover watcher, and zero
  duplicate validation/nuclei/vuln-feed workers.

## v2.4.0-vuln-intel - 2026-05-10 - Passive fresh-vuln race queue

### Added
- Added `scripts/recon_vuln_feed.sh`, a passive vulnerability intelligence
  layer that normalizes KEV/NVD-local data plus optional EPSS, CISA
  Vulnrichment, and ProjectDiscovery nuclei-template signals.
- Added `~/recon/vuln/vuln_feed.jsonl`, `summary.json`, and
  `vuln_targets.jsonl` outputs. These are intelligence and local ES matching
  artifacts only; they do not launch scans or probes.
- Added daemon `vuln-feed` supervision loop, default interval 1 hour, running
  as `reconrun` behind the existing Tor/proxy and nftables model.
- Added `recon_ctl vuln status|top|refresh` and Discord `!vuln` visibility.
- Extended `recon_brain.sh` so full/quick refreshes update passive vuln
  intelligence before triage.
- Added duplicate-worker detection to `recon_ctl health` for validation,
  discovery, scope-watch, takeover-watch, nuclei, and vuln-feed loops.

### Security
- Preserved the scanner user boundary: target-facing and feed worker paths
  still run as `reconrun`; no scanner code was moved to the main `d0k` user.
- `recon_vuln_feed.sh` is passive. It fetches public intelligence feeds and
  matches against local Elasticsearch only; nuclei execution remains gated in
  `recon_nuclei.sh`.
- Fresh ES resets now clear derived vuln target queues so old asset matches
  cannot repopulate a fresh start.

### Fixed
- Repaired shared directory ACL preparation so `reconrun` can create queue,
  state, CVE, vuln, AI, scope, spool, and log artifacts without weakening the
  kill-switch model.
- Ensured `reconrun`-created vuln feed outputs remain readable by the control
  user for `recon_ctl vuln status`.

### Verified
- `bash -n` passed for changed shell scripts.
- `git diff --check` passed for the vuln-intel changes.
- Local-only vuln normalization produced 1,590 KEV-derived records and refused
  to create asset work while `recon_alive` was empty.
- `recon_ctl health` reports no duplicate long-running workers.

## v2.3.4-live-hygiene - 2026-05-10 - Duplicate watcher and fresh-confirm cleanup

### Fixed
- Corrected triage/report summary counters to count JSONL records with compact
  `jq` output. Previous counters counted pretty-printed object lines, producing
  impossible values such as `P0` counts larger than total target count.
- Expanded fresh `recon_alive` index creation mappings to explicitly align base
  httpx fields, `triage_*`, `v2_nuclei_*`, and post-score `ai_*` fields.
- Stopped takeover watch mode from re-streaming recent validation outputs by
  default. `recon_validate.sh` already owns per-batch takeover streaming, so the
  watch loop now focuses on periodic WATCH rechecks unless
  `TAKEOVER_WATCH_PROCESS_DONE=1` is explicitly set for manual recovery.
- Hardened `recon_fresh_confirm.sh` scope filtering against non-object lines
  from batch scope-check output, preventing `jq` errors like
  `Cannot index string with string "in_scope"`.
- Quieted the expected triage seen-file fallback when daemon runs under
  `reconrun` and uses its per-UID dedup file.

### Added
- Optional post-score Ollama review layer: `recon_ollama.sh`,
  `recon_ai_score.sh`, and `recon_ai_pack.sh`.
- Ollama runs by default after deterministic triage scoring and can be disabled
  with `ENABLE_OLLAMA_AI=0`; output is isolated under `ai_*` fields.
- Daemon now passes `ENABLE_OLLAMA_AI`, `OLLAMA_URL`, `OLLAMA_MODEL_LEAD`, and
  AI review limits into the `reconrun` worker environment.

## v2.3.3-takeover-noise - 2026-05-10 - Empty fingerprint guard

### Fixed
- Corrected the NationBuilder takeover fingerprint CNAME regex, which had an
  empty provider pattern and caused broad false Stage 2 hits.
- Added a defensive guard in `match_provider` so empty CNAME regexes are skipped
  instead of matching every CNAME target.

## v2.3.2-profile-pass - 2026-05-10 - Scanner profile env propagation

### Fixed
- Passed daemon profile tuning (`HTTPX_THREADS`, `HTTPX_RATE`,
  `HTTPX_TIMEOUT`, `HTTPX_MAX_RUNTIME`, `BATCHES_PER_CYCLE`,
  `INBOX_FILE_CAP`, and `BATCH_SIZE`) through `run_scanner` into the
  `reconrun` worker environment.
- This prevents boost mode from silently falling back to browse defaults inside
  `recon_validate.sh`.

### Operational
- Pipeline was stopped, lingering `httpx`/daemon loop processes were killed,
  stale lock/pid files were cleared, and the half-run processing batch was moved
  back to inbox for a clean restart.

## v2.3.1-clean-start - 2026-05-09 - Stale-output cleanup and archive-safe reset

### Fixed
- Stopped stale high-priority triage findings from re-polluting Discord by
  requiring recent `first_seen` age for alerts and using a stable
  host/classes/KEV dedup key instead of `host:score`.
- Preserved shared triage seen history when falling back to a per-uid seen file,
  preventing daemon/user ownership drift from resetting Discord dedup state.
- Made `recon_fresh_confirm.sh` actually enforce `.seen_keys`, so the same
  host/kind does not repeatedly confirm and notify after cooldown.
- Added nuclei confirmed-finding dedup via `.confirmed_seen`, seeded from
  existing `confirmed.jsonl`, to avoid repeated host/template alerts and result
  pollution.
- Ignored WSL/Windows `Zone.Identifier` metadata files that were cluttering git
  status.

### Changed
- `recon_ctl clean`, daemon cleanup, and validation `done/` pruning now archive
  stale files under `~/recon/archive/` instead of deleting evidence.
- `recon_ctl reset-queue` now archives queue files before clearing the active
  queue.

### Added
- `recon_ctl clean-start --yes` to archive active stale views/logs/results while
  preserving useful state: scope/CVE DBs, submissions, known/alive hosts,
  false-positive lists, and seen/dedup files.
- Discord bot `!clean` command for safe stale spool/done archival.
- README clean-start runbook.

### Verified
- `bash -n` clean across all shell scripts in `scripts/` and `tools/`.
- `git diff --check` clean.
- `recon_ctl help` and `recon_ctl clean-start` dry-run output checked.

## v2.3.0-brain — 2026-05-09 — Payout & KEV-aware triage

Major upgrade to the post-discovery "brain". Triage now factors in scope payout
tier and active KEV exploitation, and the freshest target on the highest-paying
program rises to the top automatically.

### Added
- **Payout-tier propagation** through the scope DB:
  `recon_scope_db.sh` now records `max_bounty` (numeric) and `payout_tier`
  (`elite` ≥ $10k, `high` $3k–$10k, `mid` $500–$3k or unknown-paying,
  `low` $1–$500, `none`) for every program across HackerOne, Bugcrowd,
  Intigriti, YesWeHack, Federacy.
- **5-column `inscope_patterns.tsv`** (added `payout_tier`).
  `recon_scope_check.sh` reads the new column and emits `payout_tier` in JSON,
  with backward-compat fallback for pre-v2.3 4-column TSVs.
- **Brain enrichment in `triage.sh`** (Phase 1.5):
  - Reads `recon_scope_check --batch` and `kev_targets.jsonl`
  - Hard-excluded hosts (e.g. `.mil`) are dropped before clustering — never
    reach Discord or `agent_targets.jsonl`
  - Out-of-scope hosts get `OOS_PENALTY` (default −10) so they fall below
    the alert threshold automatically
  - Score bonuses stack: `pays` +2, tier `low`/`mid`/`high`/`elite` +1/+3/+5/+8,
    KEV match +5
  - **Fresh-blood-on-payday** mega bonus +5 when novel (<24h) AND
    confirmed-tech AND program pays
- **Tier-aware sorting** of `agent_targets.jsonl` and Discord embeds:
  `(tier_rank, score, novelty)` instead of `score` alone.
- **Discord embeds** now surface `Program · Platform · payout_tier`,
  KEV CVE IDs, and a 🩸 marker for fresh-blood-payday hits. KEV hits are
  red-coded; elite-tier hits are bright red.
- **ES write-back** extended: every triaged doc now persists
  `triage_program`, `triage_platform`, `triage_payout_tier`, `triage_pays`,
  `triage_in_scope`, `triage_out_of_scope`, `triage_kev_match`,
  `triage_kev_signal`, `triage_kev_cves[]`.
- **Triage report header** now shows tier counts (elite/high/mid), KEV-matched
  count, and fresh-blood-payday count.
- New **`scripts/recon_brain.sh`** one-shot orchestrator:
  `recon_brain.sh full | quick | triage-only | status`. The `status` mode
  prints brain health (programs by tier, KEV count, current agent targets by
  tier) without re-running anything.
- `recon_inspect.sh` now displays the program's `payout_tier` and highlights
  ELITE/HIGH payouts for the inspected host.

### Changed
- Old behavior preserved as graceful fallback: if `kev_targets.jsonl` or the
  scope DB is missing, `triage.sh` runs exactly as before — zero regression
  vs v2.2.x.
- All score bonuses are env-overridable: `PAYS_BONUS`, `TIER_LOW_BONUS`,
  `TIER_MID_BONUS`, `TIER_HIGH_BONUS`, `TIER_ELITE_BONUS`, `KEV_BONUS`,
  `FRESHBLOOD_PAYDAY_BONUS`, `OOS_PENALTY`.
- `recon_daemon.sh` takeover-watch supervisor: retry interval bumped from
  30s to 5 min and now logs only on state transitions. (Complements the
  v2.2.1 `recon_takeover_hunter.sh` exit-0 fix.)

### Verified
- `bash -n` clean on all 7 touched/new scripts.
- `jq` tier function unit-tested across 6 boundaries (none/low/mid/high/elite).
- Brain enrichment integration test on synthetic hosts: elite + KEV +
  fresh-blood produces +20 over base, hard-exclude drops the record,
  out-of-scope penalty applies correctly, no-scope hosts pass through
  unchanged.
- Patched `recon_scope_check.sh` runs cleanly against the existing live
  4-column TSV (paying patterns default to `mid` until next `scope_db`
  rebuild).

### Operational
- Pipeline wiring unchanged: daemon already runs `recon_scope_db`,
  `recon_cve_intel`, and chains `triage.sh` after every validation cycle.
  The next `scope_db` cycle (default 24h) regenerates the TSV with proper
  tier columns; the next triage cycle (default 15 min in browse mode)
  picks them up automatically.
- For an immediate refresh: `bash scripts/recon_brain.sh full`.
- For a status check without side effects: `bash scripts/recon_brain.sh status`.


## v2.2.1 — 2026-05-09 — Sudo fix and preflight self-heal

### Fixed
- **Critical: all workers were failing with `sudo: a password is required`** — the sudoers rule allowing `d0k` to run scanner processes as `reconrun` (via `sudo -n -u reconrun`) was missing. Added `/etc/sudoers.d/recon-reconrun` with `d0k ALL=(reconrun) NOPASSWD: ALL`.
- Updated `/usr/local/sbin/recon-safe-preflight` to self-heal the `recon-reconrun` sudoers rule on every startup. Fresh installs no longer require a manual sudoers step.
- Fixed `recon_takeover_hunter.sh` watch mode: when a second daemon restart loop detects the lock (instance already running), it now exits 0 instead of 1, eliminating noisy `[takeover-watch] died` log spam while the real watch process was healthy.

### Security
- `d0k ALL=(reconrun) NOPASSWD: ALL` grants privilege *down* to a locked, shell-less, network-isolated user — not up to root. The nftables kill switch on uid 996 is the real security boundary.

---

## v2.2.0 — 2026-05-08 — Final clean deployment

### Added
- Added `.gitattributes` to keep shell scripts and repo text files LF-normalized across Windows and Kali.
- Added shared fail-closed network helper `scripts/recon_net.sh` using Tor SOCKS with remote DNS by default.
- Added `scripts/recon_fresh_confirm.sh` for low-noise fresh confirmation on paying programs only.
- Added CLI `fresh` command and Discord `!fresh` command for the fresh confirmed queue.
- Added weekend boost schedule: Saturday/Sunday 3:00 AM-10:00 AM Pacific.
- Added `docker/.env.example` for required Elasticsearch/Kibana secrets and heap tuning.

### Changed
- Renamed the faster operating mode from `night` to `boost`; `night` remains a compatibility alias.
- Made safe startup and `recon_ctl start` refuse target-facing recon when secure preflight is missing or failing.
- Made nuclei and fresh confirmation exclude VDP/unknown-pay targets by default.
- Made scope-watch emit paying-program batches by default.
- **Removed home-directory fallback from `script_path()`** in `recon_daemon.sh`, `recon_ctl.sh`, and `recon_validate.sh`. Repo path is now the single source of truth; `~/recon_*.sh` compatibility symlinks can be removed.
- **Removed home-directory fallback from `tools/start_recon_safe.sh`**; always uses repo `scripts/recon_ctl.sh`.
- **Extended `recon_ctl stop`** to also kill `recon_fresh_confirm.sh`, `recon_schedule.sh`, and `triage.sh` processes.
- Removed leftover version-block comment markers (`V21_BLOCK_BEGIN/END`, `V213_INSPECT_BEGIN/END`, `V214_SCHED_BEGIN/END`, `V21_CTL_BEGIN/END`) — code is fully integrated, markers were noise.
- Bound Docker Elasticsearch/Kibana defaults to localhost in the repo compose file and documented the Windows LAN firewall model.
- Updated the kill switch helper to allow only Windows-host Elasticsearch on port 9200 when needed.
- Disabled live direct-egress leak testing by default in the kill switch checker.

### Fixed
- Fixed `curl_net()` in `recon_net.sh`: previously called `ensure_proxy_ready()` which required `proxychains4` even though `curl_net` uses `curl --proxy`, not proxychains4. Now only checks the Tor SOCKS listener.
- Routed Discord, CVE, scope feed, takeover HTTP/DNS, inspect, triage notification, and fresh-confirm outbound calls through the shared proxy helper where target/network-facing.
- Moved the fresh-confirm lock into `~/recon/fresh` to avoid `reconrun`/`d0k` ownership friction in shared state.
- Escaped scope-check JSON output fields so program names/patterns cannot break JSON formatting.

### Verified
- Kali/WSL can reach Windows Elasticsearch through the narrowed firewall rule.
- Broad Docker Desktop Public firewall rules can be disabled while preserving Kali-to-ES access.
- Paid-only CVE/nuclei flow filters in-scope VDP/unknown-pay targets out before scanning.

### Deploy checklist
- [ ] `cp docker/.env.example docker/.env` and fill in `ELASTIC_PASSWORD` and `KIBANA_PASSWORD`
- [ ] Remove home-dir compat symlinks: `rm -f ~/recon_*.sh ~/triage.sh`
- [ ] Verify `recon-start` alias in `~/.zshrc`: `alias recon-start='~/recon-ctl/tools/start_recon_safe.sh'`
- [ ] Update `C:\recon\start_recon_hidden.vbs` content (see RUNBOOK.md)
- [ ] Verify preflight at `/usr/local/sbin/recon-safe-preflight` and sudoers rule
- [ ] `tools/enable_recon_killswitch.sh` then `tools/check_recon_killswitch.sh`
- [ ] `tools/start_recon_safe.sh` — final smoke test


## v2.1.6-killswitch final hardening notes

### Added
- Hidden Windows `ReconWatchdog` startup through `wscript.exe C:\recon\start_recon_hidden.vbs`.
- Noninteractive safe startup through `tools/start_recon_safe.sh`.
- Root-owned preflight script `/usr/local/sbin/recon-safe-preflight`.
- Narrow sudoers rule allowing only the root-owned preflight script without a password.
- Final sanity documentation for IP leak prevention and startup safety.

### Changed
- Windows startup now uses the safe preflight path instead of calling `recon_daemon.sh` directly.
- Target-facing scanner paths run under the locked `reconrun` user.

### Verified
- Windows `ReconWatchdog` returns `Last Result: 0`.
- Task runs hidden through `wscript.exe`.
- `reconrun` direct outbound traffic is blocked.
- Tor SOCKS on `127.0.0.1:9050` works.
- Local Elasticsearch on `127.0.0.1:9200` works.
- No scanner-heavy processes are owned by `d0k`.
- Discord `!mode`, CLI mode, and scheduler all use `~/.recon_mode`.

### Operational Rule
Use the hidden Windows task or `recon-start`. Do not start target-facing recon with plain `~/recon_ctl.sh start` unless the kill switch has already been verified.


## v2.1.6-killswitch - 2026-05-07

### Fixed
- Added `run_scanner` daemon path to launch target-facing scanner tasks under locked user `reconrun`.
- Hardened scanner execution against IP exposure using an nftables kill switch.
- Added native SOCKS proxy flags for httpx, subfinder, and nuclei.
- Skipped assetfinder in proxy-safe mode because it lacks a trusted native proxy flag.

### Verified
- Direct outbound traffic from `reconrun` is blocked.
- Tor SOCKS via `127.0.0.1:9050` works.
- Local Elasticsearch via `127.0.0.1:9200` works.
- No scanner processes are owned by `d0k`.
- httpx and subfinder run under `reconrun`.
- nuclei daemon path uses `run_scanner` when triggered.

### Notes
- nftables rules may need to be restored after WSL restart.
- The kill switch, not proxychains alone, is the fail-closed control.


## v2.1.6-proxy-safe - 2026-05-07

### Fixed
- Enforced proxychains wrapping for target-facing recon tools when USE_PROXYCHAINS=1.
- Added fail-closed proxy checks for proxychains4 and Tor SOCKS listener on 127.0.0.1:9050.
- Wrapped httpx, subfinder, assetfinder, nuclei, and external scope/feed fetches through the network wrapper.

### Verified
- Direct and proxychains outbound IPs differed.
- Live httpx, subfinder, and nuclei child processes showed LD_PRELOAD with libproxychains mapped.

### Notes
- Parent shell processes may not show libproxychains; verify the actual scanner child processes.


## v2.1.5-recovered - 2026-05-07

### Fixed
- Restored missing runtime scripts after repo migration:
  - recon_discord_bot.sh
  - recon_discovery.sh
  - recon_validate.sh
  - recon_hot_seed.sh
  - recon_scope_watch.sh
  - recon_takeover_hunter.sh
- Restored functional supervisor daemon wiring.
- Restored Discord bot command handling for health, queue, status, logs, mode, and control commands.
- Restored live recon loops for validation, discovery, hot-seed, scope-watch, takeover-watch, CVE, nuclei, and schedule tasks.
- Recreated home-directory compatibility symlinks for scripts still expecting ~/recon_*.sh paths.

### Verified
- Bash syntax checks passed for restored scripts.
- Daemon started successfully.
- Discord bot responded to !help, !queue, !status, and !health.
- Elasticsearch health returned green.
- Repo tagged as v2.1.5-recovered.

### Notes
- Root cause was an incomplete repo migration where newer helper scripts were present, but required runtime scripts and Discord bot wiring were missing.
- Do not remove compatibility symlinks yet because some scripts still call the old flat ~/recon_*.sh paths.


---

## [v2.1.4] — Schedule-based mode switching + stop fix

**Scripts changed:**
- `recon_daemon.sh` — patched: schedule sub-loop added
- `recon_ctl.sh` — patched: stop pkill fixed + schedule commands added
- `recon_scope_db.sh` — patched: cosmetic stderr warnings suppressed
- `recon_schedule.sh` — **NEW**

**Changes:**
1. `recon_schedule.sh` — time-based automatic mode switcher integrated as daemon sub-loop
   - Weekdays 5:30pm–11:30pm PT → browse mode (low rate, won't impact browsing)
   - All other times → night mode (aggressive)
   - Weekends: manual mode preserved, no auto-switching
   - Runs as supervised sub-loop inside daemon, checks every 5 minutes
2. Stop command (`recon_ctl.sh stop`) — pkill pattern extended to include `discord_bot` and `nuclei` processes that were being left as orphans
3. `recon_scope_db.sh` — Intigriti/YesWeHack/Federacy normalizer stderr warnings suppressed (data was correct, warnings were cosmetic)
4. NVD health-check command added to `recon_ctl.sh`
5. `recon_ctl.sh` new commands: `schedule`, `schedule-check`, `schedule-status`

---

## [v2.1.3] — Hard exclusions + inspect helper

**Scripts changed:**
- `recon_scope_check.sh` — patched: `.mil` hard exclusion
- `recon_ctl.sh` — patched: `inspect` command added
- `recon_inspect.sh` — **NEW**

**Changes:**
1. `.mil` hard exclusion in `recon_scope_check.sh`
   - Hosts matching `.mil`, `.smil.mil`, `.nipr.mil`, `.sipr.mil` return `in_scope=false, hard_excluded=true`
   - Hard exclusion overrides any matching scope DB pattern
   - Protection against accidental DoD/classified network scanning
2. `recon_inspect.sh` — single-host manual triage helper
   - Full ES record: status, title, tech, IP, CNAME, CDN
   - Scope verdict: in scope / paying / VDP / out-of-scope / hard-excluded
   - KEV match details: which signal, which CVEs, max CVSS score
   - Live HTTP probe: current status code, redirect chain
   - Tech-specific suggested manual probes (Jenkins → `/script`, Confluence → CVE-2023-22527 paths, etc.)
   - Probe suggestions suppressed for hard-excluded hosts
3. `recon_ctl.sh` extended with `inspect <host>` command

---

## [v2.1.2] — Scope check performance + nuclei tier filter

**Scripts changed:**
- `recon_scope_check.sh` — full rewrite
- `recon_nuclei.sh` — patched: batch scope check + tier filter

**Changes:**
1. `recon_scope_check.sh` full rewrite — in-memory awk, single-pass batch mode
   - Was: O(n × forks), timing out at 200 hosts
   - Now: ~270,000 hosts/sec, entire kev_targets list processed in one call
   - Bug fix: out-of-scope now correctly overrides in-scope (host matching both `*.example.com` in-scope and `*.beta.example.com` out-of-scope was incorrectly marked in-scope)
2. `recon_nuclei.sh` — target build rewritten to use batch scope check (eliminated O(n) per-host fork loop)
3. `NUCLEI_TIER` env var added to `recon_nuclei.sh`
   - `high-value` (default): scans only proven KEV-vulnerable tech (moveit, confluence, jenkins, magento, exchange, fortinet, citrix, ivanti, vmware, weblogic, manageengine, gitlab, solr, zabbix, kibana, jira, nexus, phpmyadmin, argocd, rancher, portainer, thinkphp, coldfusion, airflow, joomla)
   - `all`: scans every signal in kev_targets including WP/Drupal/Spring/Tomcat noise
   - `kev_targets.jsonl` itself unchanged — tier filter only affects what nuclei fires on

---

## [v2.1.1] — Platform normalizer fixes + KEV match fix

**Scripts changed:**
- `recon_scope_db.sh` — replaced
- `recon_cve_intel.sh` — replaced

**Changes:**
1. Platform normalizers fixed — Intigriti, YesWeHack, Federacy now produce programs (was 0)
   - Intigriti: correct fields `targets.in_scope[].endpoint`, `max_bounty.value`
   - YesWeHack: correct fields `targets.in_scope[].target` with type filter, `max_bounty` as number
   - Federacy: correct fields `targets.in_scope[].target`, `offers_awards`
2. KEV → ES match fixed — critical bug: was returning 0 hosts
   - Root cause: ES stores tech as `"Jenkins"` (capitalized), wildcard query was case-sensitive on keyword field
   - Fix: ES `case_insensitive: true` flag (supported ES 7.10+, running 8.17)
   - Result: from 0 KEV-matched hosts to dozens/hundreds depending on ES contents
3. NVD curl `200000` bug fixed
   - `-w '%{http_code}'` was returning concatenated HTTP codes when curl reused connections
   - Fix: isolate final code via `tail -n1 | tr -dc '0-9' | head -c 3`
4. `kev_targets.jsonl` dedup — multiple `SIG_TO_TECH` terms matching same host now deduped by host

---

## [v2.1.0] — V2 integrated build (scope DB + CVE intel + nuclei)

**Scripts added (NEW):**
- `recon_scope_db.sh` — arkadiyt BB scope feed → `programs.json` pattern tables
- `recon_scope_check.sh` — per-host scope lookup against programs.json
- `recon_cve_intel.sh` — KEV catalog + NVD recent CVEs + tech match → `kev_targets.jsonl`
- `recon_nuclei.sh` — KEV-only, scope-gated nuclei scanning (6h cycle)
- `recon_killswitch.sh` — per-module enable/disable helper

**Scripts patched:**
- `recon_daemon.sh` — V2.1 sub-loops added (scope-db, cve-kev, cve-nvd, nuclei-v21)
- `recon_ctl.sh` — V2 commands added (kev, scope, programs, confirmed, fp, v2)
- `triage.sh` — V2 hook removed (cleaned from v2.0)

**Architecture — one daemon, one PID:**
```
recon_daemon.sh (master)
├── validate-loop      queue → httpx → ES → triage
├── discovery-loop     chaos + subfinder + assetfinder
├── hot-seed-loop      live subfinder
├── scope-watch-loop   new program detection
├── takeover-watch     takeover hunter
├── discord-bot        outbound-poll remote control
├── scope-db           arkadiyt scope DB (24h refresh)
├── cve-kev            KEV catalog + match (1h)
├── cve-nvd            NVD recent (24h)
└── nuclei-v21         KEV-only, scope-gated nuclei (6h)
```

**New data directories:**
- `~/recon/scope/` — `programs.json`, pattern tables (~3000 BB programs)
- `~/recon/cve/` — `kev.json`, `nvd_recent.json`, `tech_cve_map.json`, `kev_targets.jsonl`
- `~/recon/nuclei/` — results, `confirmed.jsonl`, `fp/` (false positives)
- `~/recon/state/kill/` — per-module killswitches

**New `recon_ctl.sh` commands:**
```
kev                    KEV-matched targets in ES
scope <host>           Scope check single host
programs               Programs by platform + paying count
confirmed              Latest nuclei-confirmed findings
fp <host> <template>   Mark false positive
v2 status              Killswitches + data ages
v2 enable <module>     Re-enable killed module
v2 disable <module>    Disable module with reason
v2 refresh-scope       One-shot scope DB refresh
v2 refresh-cve         One-shot KEV+NVD+map+match
v2 scan-now            One-shot nuclei pass
```

**Auto-disable triggers:**
| Condition | Action |
|---|---|
| 3 consecutive failures (supervise_loop) | Disable the failing module |
| RAM > 90% | Skip nuclei (not killed) |
| Disk free < 5GB | Skip nuclei (not killed) |
| > 10 nuclei confirms in 1 run | Disable nuclei in-script |
| `recon_ctl v2 disable <mod>` | Disable that module |

**Issues fixed from v2.0:**
- Separate V2 daemon removed — folded into V1 daemon as sub-loops
- `jq: Argument list too long` building tech_cve_map — now pure Python, file-based
- NVD page 0 failure — retry with exponential backoff, longer initial delay, 30-page cap
- Intigriti normalized to 0 programs — schema-tolerant jq filters
- HackEnProof 404 — removed (no longer in arkadiyt feed)
- `recon_ctl stop` left orphans — pkill pattern extended to catch all V1+V2 modules

---

## [v1.0] — Core pipeline baseline

**Scripts:**
- `auto_recon.sh` — one recon cycle: Chaos + subfinder + assetfinder → httpx → ES ingest
- `triage.sh` — 2-phase scoring engine → `agent_targets.jsonl` → Discord P0/P1 alerts
- `recon_daemon.sh` — forever loop, mode-aware, owns PID, auto-cleanup each cycle
- `recon_ctl.sh` — control interface: status/mode/logs/top/health/clean/space

**Infrastructure:**
- Elasticsearch 8.17.4 + Kibana 8.17.4 on Docker Desktop (Windows)
- Index: `recon_alive` — 2.4M+ docs
- Auth: `xpack.security.enabled=true`, credentials in `~/.recon_es_pass`
- Discord webhook alerts: `~/.recon_discord`
- Windows Task Scheduler: `ReconElastic` (Docker), `ReconWatchdog` (daemon)

**Discovery sources:**
- ProjectDiscovery Chaos — ~2300 BB programs, incremental refresh
- subfinder — passive, all sources, 2363 root domains
- assetfinder — passive, per root domain
- Delta-based: only scans hosts not in `known_hosts.txt`

**httpx fingerprinting fields:**
`tech`, `status_code`, `title`, `webserver`, `ip`, `cname`, `cdn_name`, `cdn_type`, `favicon_hash`, `final_url`, `content_length`, `content_type`

**Mode profiles:**
| Setting | Browse | Night |
|---|---|---|
| Jobs | 1 | 2 |
| Threads | 15 | 80 |
| Rate (rps) | 15 | 100 |
| Input cap | 20,000 | 150,000 |
| Cycle sleep | 60 min | 30 min |

**Triage scoring — Phase 1 (74 signal rules):**
- `confirmed` strength: 46 tech rules (Jenkins=9, Confluence=9, GitLab=8, Grafana=8, Spring Actuator=7, K8s=9, MOVEit=9, ManageEngine=9, etc.)
- `status` strength: 403=+3, 401=+2, 500=+2
- `port` strength: Docker API=+9, Redis=+7, MongoDB=+7, ES=+5
- `pattern` strength: hostname patterns +2 to +5
- Negative signals: mail=−3, redirect-no-tech=−2, default-page=−2, CDN-no-tech=−1
- Diversity gate: pattern-only hosts capped below P1 threshold

**Triage scoring — Phase 2 (cluster dedup):**
- Group by root_domain + signal fingerprint
- Hosts 4+ in same cluster: −3 penalty (kills load balancer farms)

**Priority thresholds:** P0≥15, P1≥8, P2≥4, P3 filtered

**Output:** `~/recon/triage/agent_targets.jsonl`, `~/recon/triage/report_<ts>.md`

---

## [repo] — Git repository migration

**Changes:**
- All scripts moved from `~/` flat layout into `~/recon-ctl/` git repository
- Structure: `scripts/`, `docker/`, `CHANGELOG.md`, `RUNBOOK.md`, `.gitignore`, `README.md`
- `ReconWatchdog` Task Scheduler updated to launch from repo: `~/recon-ctl/scripts/recon_daemon.sh`
- `.gitignore` covers: secrets (`~/.recon_es_pass`, `~/.recon_discord`), runtime state, lock/pid/epoch files, `*:Zone.Identifier` files
- Proxychains support added to `recon_daemon.sh`:
  - `USE_PROXYCHAINS=1` env var routes all external scan traffic through proxychains4
  - ES/localhost traffic bypassed via `localnet 127.0.0.0/255.0.0.0` in proxychains4.conf
  - `run_auto_recon()` wrapper handles conditional invocation
  - Graceful fallback if proxychains4 binary not found
- Repo-relative paths in `recon_daemon.sh`: `SCRIPT_DIR`/`REPO_ROOT` derived at runtime, `AUTO_RECON` and `TRIAGE_SCRIPT` resolve from `$REPO_ROOT/scripts/`
- `recon_ctl.sh` `DAEMON` path updated to repo location
- Home directory cleaned: version archives, `.bak`/`.v*` backups, Zone.Identifier files, superseded scripts all removed
- `~/recon/queue/backups/` purged (459MB of old processed batch backups)

# recon-pipeline — standing operating doc

Reference for every session. Established through a full session of manual
verification. Keep it tight; update it when a principle changes.

## THE MOTTO: be UNIQUE, or get duplicated (v3.7)
The operator is part-time (evenings) vs full-time hunters. Running what everyone runs —
`subfinder | httpx | nuclei-defaults` on saturated programs — finds what everyone finds =
**duplicates = 0 reward** (proven: our only submission was a real P2 marked dup). Research
of top earners / XBOW / AI hunters says the edge is: **go where the crowd doesn't, use
Claude's *understanding* where commodity tools are blind, validate with a real PoC, be
first to fresh surface.** Every new lane must answer "how is this not what everyone runs?"
The UNIQUE pillars (all additive — nothing that works was removed):
- **JS-intel** (`recon_jsintel.sh`) — mine each host's JS for the HIDDEN API surface +
  trufflehog `--only-verified` LIVE secrets (kills the 53%-FP token-shaped noise).
- **IDOR/BAC money pillar** (owned by the **2IC routine agent**, not a daemon loop) — Claude
  reasons over the jsintel endpoint surface (`~/recon/js_recon/endpoints.jsonl` + ES) →
  ranked broken-access-control/IDOR worklist with the 2-account test (the most-rewarded
  class; reasoning only, human exploits with their own accounts). (The old `recon_ai_idor.sh`
  daemon loop was retired 2026-06-08 — the routine subsumes it.) The routine/operator now
  start from a **pre-ranked** list: `recon_idor_candidates.py` scores all endpoints.jsonl
  entries for IDOR-likelihood (object-reference resource + ID type: numeric=enumerable,
  uuid=harvestable, id-param; +sensitive/financial, +api/graphql, +upload-download), excludes
  benched/OOS/non-paying + 3rd-party-host endpoints, and **fanout-suppresses product-class-dup
  APIs** (same templated endpoint on >5 hosts = shipped product, e.g. UniFi `/proxy/users/...`).
  Output → `~/recon/briefings/idor_candidates_<date>.md`. Added 2026-06-13; research-grounded
  (IDOR in REST/GraphQL APIs = #1 paid class, the one automation can't confirm — so surface,
  rank, human-test). Still reasoning-only; NEVER enumerate third-party IDs (hard line).
- **XSS/SQLi reflected-param lane** (`recon_xss_sqli_candidates.py` + `recon_params.sh confirm`) —
  rs0n's "all XSS targets from HackerOne" idea made DUP-PROOF and multi-platform. The params catalog
  (~18k XSS / ~3k SQLi in-scope+paying URLs across 5 platforms) is RANKED by param-name injectability
  (the kxss insight — `q`/`redirect`/`callback` reflect; `id`/`cat`/numeric inject), handler/path signal
  (`.php`/`/api/`), freshness + payout tier; deduped by (host, locale/id-normalized path, param-set)
  template; and SPLIT into rare per-app UNIQUE lanes vs high-fan-out PRODUCT-CLASS dup-magnets (the `?q=` /
  `_next/image?url=` everyone fuzzes). Drops wayback attack-capture noise (`%22`/FUZZ-flood paths). Output
  → `~/recon/briefings/{xss,sqli}_candidates_<date>.md`, surfaced in the 6:30 briefing. CONFIRM on-demand
  (`recon-params confirm xss|sqli <host>`): XSS via **dalfox** (context-aware — break-out must EXECUTE,
  reflection≠XSS, killing the old canary-FP) rate-limited + mining-off; SQLi via the SAFE `'` vs `''`
  differential (error + boolean length-diff). HARD LINE: never sqlmap / `--dump` / data-harvest / "large
  traffic"; confirm is manual/on-demand only (never a daemon loop — dalfox fan-out would burn the egress).
  Mass-XSS on saturated programs IS the dup trap (the MOTTO); the uniqueness-split + freshness-first +
  real-PoC confirm is what keeps it an edge, not noise. Added 2026-06-14.
- **n-day racing** (`recon_nday.sh`) — Claude version-reasons KEV/CVE matches to KILL the
  tech-class FP and surface only genuine in-range candidates, in the race window.
- **GitHub leaks** (`recon_ghleaks.sh`) — code-search → trufflehog-verify live leaked
  secrets (off-web surface most ignore).
- **6:30pm briefing** (`recon_briefing.sh`) — one ranked "TONIGHT" card: BAC/IDOR leads to
  test + verified findings to submit. The output that fits a 9-5.
Smart targeting + clone/staging dedup (XBOW) is the next layer; precision over volume.

## RESEARCH MANDATE (operator 2026-06-14, "very very important") — read the source, don't guess
For ANYTHING that needs research — **design, hunting, recon, enumeration, AND building/fixing the
pipeline** — GO READ THE AUTHORITATIVE SOURCE before acting: (1) the **target host's own DOCS**
(API/developer/reference/OpenAPI-Swagger/changelog — for authed targets via Claude-in-Chrome in the
logged-in tab); (2) **top bug-bounty hunters' RESEARCH** (writeups, disclosed H1 reports, rs0n/NahamSec/
jhaddix/XBOW/PortSwigger, CVE/advisory writeups, technique posts) — via WebSearch/WebFetch. This is how
the part-time hunter beats full-timers and how the MOTTO's "use Claude's understanding where tools are
blind" actually works: be informed, not fast-and-blind. Don't act on a hunch when the source is one
fetch away (ties to template-safety: read before you fire). Applies to /hunt AND to me building this engine.
**DEAD-END ⇒ RESEARCH (reinforced 2026-06-15, "very critical"):** research is also THE move whenever we
hit a dead end / need fresh paths / are in a tough spot on ANY class/host/tech/tool/design. When stuck,
STOP grinding and RESEARCH THE INTERNET — it ALWAYS has an answer in some form (writeups, disclosed
reports, CVE analysis, GitHub PoCs, forum threads, talks, framework exploitation guides, threat intel).
Reflected-XSS dead ⇒ research that framework's DOM/postMessage/CVE patterns; tech hardened ⇒ research its
bypasses; out of ideas ⇒ research fresh recon + the program's disclosed bugs. Threat intel + research +
studying are what turn a script kiddie into a real researcher. NEVER declare a dead end before researching
a fresh angle; make web search a reflex at the FIRST sign of stuck, not a last resort.
**ALL SOURCES + RECORD IT (operator 2026-06-15):** research is NOT just the general internet — also the
target web app's OWN docs, the technology/framework docs (security model, config flags, CVEs), and ANY
useful resource (GitHub source, changelogs, standards); don't limit yourself, triangulate. And **RECORD what
you learn** into the repo knowledge base `docs/knowledge/` (`tech-<stack>.md`/`class-<vuln>.md`) — actionable
paths/payloads/CVEs/sinks/bypasses + sources — so future hunts start informed. Documenting everything is what
makes the system sharper over time. READ the matching `docs/knowledge/` file before hunting a tech; APPEND
when you learn something reusable. (Host-specific findings → host_notes; the KB is general reusable knowledge.)
**INTERNET RESEARCH FOR ENUMERATION (operator 2026-06-15, stressed):** when ES is THIN for a class/tech,
do NOT accept it — RESEARCH the internet for HOW TO ENUMERATE that class (the real fingerprints/headers/
error-pages/favicon/paths/dorks), then APPLY them to pull MORE from ES (full-text the crawled data / jsintel
endpoints / titles / headers — NOT just the shallow Wappalyzer `tech:` field) and to widen the surface
(subfinder/CT/permutation + Shodan/FOFA dorks scoped to in-scope domains/orgs/certs). Proven: `tech:Spring`=7
hosts, but real fingerprints (`/actuator` in jsintel + fulltext actuator/Whitelabel/X-Application-Context)=17,
incl. high-value gateway/dev hosts. Record reusable fingerprints/dorks/queries to `docs/knowledge/`.

## TONIGHT'S NEW TOOLS (2026-06-14/15) — every agent (incl. 2IC) should know + use these
- `recon-params crawl-host <host> [url] [--cookie/--header]` — on-demand single-host param crawl (queue
  bypass): find an interesting param-bug host → crawl it NOW (katana+gau+CDX→gf→catalog) → confirm. `--cookie`
  = AUTHED crawl (operator session). Don't wait on the slow pipeline param producer.
- `recon-params confirm xss|sqli <host> [--cookie/--header]` — now takes `--cookie`/`--header` for AUTHED
  XSS/SQLi (operator's own session walks the post-login surface; SAFE primitives; human-in-loop only).
- `recon-mood <param-class>` ALSO emits `<cls>_tech_targets` (vuln-prone-tech hosts to crawl-host).
- `recon-mood CVE-2024-1234 [--tech …]` — specific-CVE lookup: which ES hosts MATCH it / run the affected tech.
- `recon-account create <name> --url <signup> --platform <bc|h1|ywh|gmail> [--label a]` — semi-auto test-account
  provisioner (operator solves CAPTCHA+submit; creds local-only).
- `recon-domxss <host>` — DOM-XSS source→sink miner (the lane dalfox is blind to): fetches JS, flags HTML-sink
  +tainted-source flows; read REVIEW for `dangerouslySetInnerHTML` rendering server data = stored-XSS leads.
- KB at `docs/knowledge/` — READ `tech-<stack>.md`/`class-<vuln>.md` before hunting that tech; APPEND learnings.

## THE HUNT FLOW — keyword `hunt` (operator-locked 2026-06-13)
When the operator says **`hunt`** / "let's hunt" / "keep hunting", run this loop AUTONOMOUSLY until
they say **stop**/**pause** (never self-terminate, never ask "want to wrap?"). Config the operator
locked: trigger=`hunt`, target-picking=fully-autonomous, probes=operator-runs-them (one-at-a-time paste).
**SCOPE = ALL OF ES — every IN-SCOPE + PAYING host — NOT ONE VULN CLASS (doctrine 2026-06-13):** within
the in-scope + paying surface (always gated on `triage_in_scope` + per-asset pays; never the raw index),
anything in `recon_alive` that looks suspicious or could lead to a finding/report is on the table — every
signal, every class. Make sense of all the ES chaos; never tunnel on a single lane/vuln-type. **EXHAUST EACH HOST: dig DEEP until all
suspicion is gone and further investigation won't yield** — don't abandon a host early.
**NO PREMATURE EXHAUSTION (doctrine 2026-06-14, emphatic — cost a real finding):** NEVER declare a host
"burned/dead/exhausted/locked/no-bug" after a SURFACE-level pass, and NEVER push to wrap or pivot. A few
negative probes (auth/WAF/404/SPA-catch-all) is NOT proof of absence — diamonds hide below the surface,
behind the 2nd/3rd/5th angle, on the pre-prod host, in the endpoint/class you didn't try. When tempted to
conclude, instead ENUMERATE the untested angles and go do them, broadly across ALL classes, over hours not
minutes. "Haven't found it yet" ≠ "not there." Only the OPERATOR calls a target done; a host_note saying
"clean" is a provisional checkpoint ("clean so far on X"), never a tombstone. See [[feedback_no_premature_exhaustion]].
**RESUME CURSOR:** `~/recon/state/hunt_cursor.md` tracks the current host + pending actions; READ it on
`hunt`/`/hunt resume` to pick up where we left off, and UPDATE it whenever you switch host / leave a
pending action / the operator steps away (so a comeback never loses the thread).
0. **PREFLIGHT** Mullvad up + no `state/vpn_down` (fail-closed).
1. **PICK (autonomous)** from THREE sources, together: (0) **FRESH BLOOD FIRST — `recon-mood fresh` (race
   the crowd):** newly-CT-surfaced in-scope+paying hosts from the gungnir true_fresh feed (renewals filtered,
   shared-tenant excluded) → `briefings/fresh_<date>.md`. Brand-new surface the crowd hasn't hit = lowest
   dup-risk = the MOTTO's highest-EV; start each session here, work each at full multi-class depth.
   (a) **pre-ranked BRIEFINGS in `~/recon/briefings/`**
   — already scope/pays/dedup-filtered, highest signal-per-minute, START here: `2IC_tonight_<date>.md`,
   `idor_candidates_<date>.md`, `xss_candidates_<date>.md` + `sqli_candidates_<date>.md` (rs0n lane; TOP
   UNIQUE first, skip PRODUCT-CLASS), `tonight_<date>.md` (stale/missing ⇒ regenerate ES-only:
   `recon-params candidates --class both`); (b) **raw ES `recon_alive`**: pays + in-scope + not-ignored
   (`must_not ignore_expires_at>now`) + un-noted, ANY finding-worthy/suspicious signal (not one class),
   ranked by claude_worth/score. Or continue the current host/lane. Out of picks ⇒ re-query/widen/
   regenerate, never stop. **MOOD HUNTING (a mood is a LENS, not a limit):** if the operator names a
   vuln-class/tech/lane/signal (`hunt xss`/`sqli`/`api`/`wordpress`/`php`/`jira`/`graphql`/`cve`/`kev`/
   `nday`/`takeover`/`fresh`/`interesting`/…or ANY keyword — coldfusion/elasticsearch/citrix all work via broad
   match; `fresh`/`blood` = newly-CT-surfaced in-scope hosts to race the crowd (`--hours N`); `interesting` =
   broad/unclassified high-signal hosts Claude flagged worth), run
   `recon-mood <kw>` → a ranked scope+pays+not-benched worklist (`~/recon/briefings/mood_<kw>_<date>.md`);
   `recon-mood --list` shows the curated set. The mood only focuses WHERE you start — it does NOT cap the
   rigor: within it run the FULL hunt at full depth (ENUMERATE subfinder/permutation/CT/jsintel, SCAN,
   CRAWL katana/gau/params, pull as much from ES as needed, ANY tool available, EXHAUST each host across
   every angle + adjacent class). `cve`/`kev` = `triage_kev_signal` matches → VERSION-REASON first (KEV
   tech-class without confirmed in-range version = LEAD, never P0; run `recon-nday`; template-safety).
2. **VERIFY BEFORE INVESTING** (a) PER-ASSET pays from `scope/raw/<platform>.json`, NOT program-level;
   (b) read host_notes + active ignores (don't re-walk); (c) check the program's OUT-OF-SCOPE rules
   (don't chase dir-listing / info-disclosure-without-impact = excludable). The 3 hard lessons.
3. **PROBE** operator runs target traffic — I give ONE copy-paste at a time (lead with my read +
   the decision), they paste, I hand the next. I run recon/scope/ES/notes/jsintel/candidates myself.
   For an XSS/SQLi lead hand the CONFIRM cmd: `recon-params confirm xss <host>` (dalfox — must EXECUTE)
   / `recon-params confirm sqli <host>` (SAFE `'` vs `''` diff). I read the result.
4. **TRIAGE & EXHAUST** CONFIRMED vs LEAD vs FP/dead; honest severity, never overclaim. Keep probing
   the SAME host across every angle until all suspicion is exhausted (more probing won't yield) —
   only then move on.
5. **NOTE EVERYTHING inline** FP/skip/disqualified/noise (clusters ⇒ 2-3 reps + class-reason). Mandatory.
6. **LANE-MINE** fertile lane (actuator/swagger spec; source-maps→cloud-creds; unauth-GraphQL introspection;
   open buckets; n-day; **XSS/SQLi reflected-param**; …) ⇒ keep mining fresh hosts; tapped ⇒ pivot/re-query.
   Lanes are examples, not limits — chase whatever the signal suggests.
   **XSS/SQLi — SMART, not blind:** work the ranked `xss/sqli_candidates` worklist, **TOP UNIQUE LANES first**
   (rare per-app params/deep routes), SKIP PRODUCT-CLASS (`?q=`/`_next/image?url=` dup-magnets), prefer ⚡
   true_fresh (be first). CONFIRM is the gate, not reflection: dalfox must show EXECUTION (reflection ≠ XSS —
   encoded/framework-safe ⇒ `reflected-not-exploitable` LEAD, move on); SQLi needs the `'`vs`''` differential
   (never sqlmap/--dump/harvest). IMPACT-GATE: only a DEMONSTRATED executing XSS / injectable SQLi —
   theoretical/no-impact (CORS, headers, self-XSS, error-only) gets N/A, don't burn the evening on it
   ([[feedback_theoretical_classes_get_declined]]).
7. **ANTI-BURN** respect 429/403/rate-limits; back off; never get the Mullvad exit banned.
8. **AUTHED / ACCOUNT-SIGNUP ⇒ ASK FIRST** when a lead needs account signup / authed testing, ASK the
   operator "work it now or save for later?" (don't auto-proceed or auto-defer). If now: hand a
   Claude-in-Chrome prompt (recon, then scope+safety-gated own-account setup + safe/active prove-impact
   PoC); 2 owned accounts, never third-party IDs, confirm-then-stop. If later: note it to the worklist.
9. **REPORT** confirmed + scope+OOS-verified ⇒ draft a ready-to-paste Claude-in-Chrome fill-the-form
   prompt (operator submits; honest severity; AI-use disclosure where required). Full SOP: memory
   `project_hunt_flow`.

## Core principle: CONFIRMED vs LEAD
Every signal is exactly one of:
- **CONFIRMED** — an exploitable primitive was directly observed.
- **LEAD** — a pattern/class suggests it, but it is unverified.
- **STALE** — was CONFIRMED, now past its freshness TTL → treat as LEAD until re-verified.

**Only CONFIRMED mints P0. LEADs clamp to P1-max. STALE → LEAD.**
The takeover lane is the REFERENCE PATTERN: `takeover:confirmed` (real multi-stage
NXDOMAIN + unclaimed-fingerprint verification, +15, P0) vs `takeover:cname-lead`
(CNAME→provider + 404 heuristic, +3, never P0 on its own). Every other lane should
match this discipline.

## Multi-class confirmation (v3.2): wide net, each catch SAFE + FP-filtered
The net is wide but every class has ONE precise, **SAFE (unauthenticated, non-destructive)**
confirmation primitive. Pattern/catalog match = LEAD; the primitive firing = CONFIRMED.
Claude is the relevance+FP layer at BOTH ends (analysis aims the net; verify adversarially
kills FPs). Confirm primitive per class:
- **XSS** → headless-Chromium marker EXECUTES (not mere reflection). `recon_xss_confirm.sh`.
- **SSTI** → `{{a*b}}` evaluates to the product (math only, never RCE). `recon_param_confirm.sh`.
- **open-redirect** → param drives the `Location:` header to OUR canary host (not followed).
- **SQLi** → error/boolean DIFFERENTIAL (`'` vs `''`) — injectable, **never a data harvest**.
- **GraphQL / Swagger-OpenAPI** → introspection / spec exposure (read-only, nuclei in the gate).
- **SSRF / XXE** → OUT-OF-BAND callback to a canary we control (interactsh). Callback = definitive;
  point entities/fetches at our canary, never `file://` or internal data.
- **IDOR/BOLA, LFI, RCE/file-read** → **operator-LEAD only** (hard line: needs 2 owned accounts /
  is exploitation). Claude detects + prioritises; a human confirms. Never auto-probed.
Any confirmed catch still passes the Claude VERIFY adversarial filter before it reaches #review.

## Claude is the brain (v3.6): owns the verdict, the FP-kill, and the report
Claude is LOAD-BEARING, not a filter. **Nothing reaches a report without its `real` verdict**
— the reporter hard-gates on `ai_verdict='real'`; the old deterministic-confidence bypass is
gone (if Claude is down, confirmed findings just wait). A `real` verdict must survive a
**CONSENSUS PANEL** of independent adversarial lenses — *exploitability* (real unauth primitive
vs cosmetic/version-only), *scope-&-reward* (in-scope, not a dup, severity a program would pay,
not N/A), *evidence-&-repro* (the probe/screenshot actually proves it). Unanimous confirm →
`real`; majority refute → fp; else needs-human. Confident fps die in one cheap pass (the panel
only adjudicates real-candidates). This is the FP-elimination engine — aim it at ~99% of
*reports* being real. For a consensus-`real`, Claude then **AUTHORS the report** (honest
severity, impact, reproducible read-only PoC, dedup — overclaiming is forbidden; it gets
reports closed N/A and dings signal). `formatters` use the authored content; template is fallback.

VERIFY is a **multimodal investigator that can actively test** — but it never *executes*
anything itself. Per finding it gets the asset SCREENSHOT as primary evidence (a
cors-misconfig on a marketing homepage looks nothing like a real exposed panel — vision
kills those FPs) plus ES asset context, Read-scoped to a throwaway per-finding dir
(`--tools Read --add-dir`, path-confined — verified it cannot read outside the dir).

**Active verification (harness-mediated, safe by construction).** When the evidence can't
settle it, Claude sets `verdict="need-probe"` and lists `probe_requests` (url + GET/HEAD/
OPTIONS) in its schema output. The TRUSTED harness — not Claude — runs each through
`recon_safe_probe.sh`, appends the real responses, and re-judges (bounded by `PROBE_ROUNDS`
/ `PROBE_BUDGET`). Claude has **no Bash/exec** — scoped-Bash is NOT confining (`dontAsk`
auto-approves benign commands, so a prompt-injected agent could run anything), therefore the
model only ever requests; the harness mediates every packet. The probe is safe regardless of
args: unauthenticated, GET/HEAD/OPTIONS only, no creds, no redirect-follow, SSRF/metadata
guard (refuses private/loopback/169.254/reserved), live scope+pays gate, rate-limited,
Mullvad-only, audited. **Unauthenticated only** — authenticated testing stays human-in-the-loop.

**Anti-burn (never get banned).** Probing is rate-limited so the Mullvad egress IP isn't
banned: min-gap + jitter, per-host and global rolling-window caps, a host COOLDOWN on a
429/403/503, and a global CIRCUIT-BREAKER that pauses ALL probing after repeated blocks
(`PROBE_*` env). The article's politeness rule, enforced in code.

**MONITOR (Claude's 3rd role) — owned by the 2IC routine agent.** Once per run the 2IC
routine sanity-checks LOCAL telemetry only — burn signals (probe blocks/cooldowns/global-
pause), verdict precision, failures/halts, daemon errors, VPN — and posts an alert to `#ops`
ONLY when something is actually wrong (no hourly health spam). It guides and watches; it
issues NO target traffic. So Claude spans the pipeline: ANALYZE (aim) → VERIFY+probe
(confirm) → MONITOR (oversee). (The standalone `recon_ai_monitor.sh` hourly daemon loop was
retired 2026-06-08 — the routine subsumes it; there is no `ai_monitor_latest.json` anymore.)

Output is **schema-validated** (`--json-schema` → `.structured_output`; no regex scraping;
unparseable ⇒ safe `needs-human`). It **escalates to the big model on genuine ambiguity OR a
low-confidence real/fp**. ANALYZE tiers model by asset value (haiku bulk → sonnet for high
triage_score). And we **measure** it: `state.py ai-accuracy` / `recon-ai accuracy` reports the
human-decided precision of `real` verdicts (accepted vs dismissed) — the only ground truth.
Never pass `--bare` (forces API-key auth, bypasses the Max OAuth login).

## Notification policy (a 9-5 hunter reads ONE card, not a live drip)
Real-time pings are **CONFIRMED only** — a Claude-`real` finding (`#review`) or a confirmed
takeover (`#takeovers`). `fp`/`needs-human` and speculative IDOR/n-day LEADS never interrupt.
Everything speculative is filtered (`tools/brief_filter.py`: product-class-dup + shared-tenant
safety), ranked, and batched into ONE nightly **#digest** card (`recon_briefing.sh`, 6:30pm:
BAC/IDOR to test + n-day CVE candidates + ready-to-submit + needs-human + verified vuln-leads;
absorbs the old 5:30 lead-digest). `#ops` = action-only (VPN / burn / halt / killswitch).
On demand, **`recon-verify list|<#>|<host>`** runs the full Claude verify (multimodal + safe
probes) on any digest lead so the operator can deep-check before spending an evening on it.

## Documented false-positive patterns (never score as CONFIRMED)
- **KEV tech-class match without a confirmed in-range version** (Spring actuator,
  Confluence, Jira, F5, MOVEit, AEM, Magento, Drupal≥8, …) → LEAD, not P0. Verify
  the running version before treating any KEV match as exploitable. (triage:
  `kev_needs_verify` + `kev_unverified_sole` clamp.)
- **Critical port from the recorded port number alone** → must be
  portscan-confirmed-open AND recent AND not CDN-fronted. CDNs
  (Cloudflare/Akamai/Fastly) ACK every port — portscan results behind a CDN are
  meaningless. **>6 "open" critical ports on one host = scan artifact**, not a finding.
- **`js_secret_hit` fires on ~53% of the corpus = noise.** A token-shaped string is
  not a secret. Exclude public-by-design: Supabase anon, Stripe `pk_`, Firebase web
  config, OAuth `client_id`, Google browser API keys.
- **XSS: reflection ≠ XSS.** Plain string reflection (especially inside JSON or
  otherwise encoded contexts) is NOT confirmed XSS. Break-out chars (`"><'/`) must
  survive UNENCODED in an executable context. Encoded reflection →
  `reflected-not-exploitable` (LEAD).
- **Dangling CNAME to a LIVE ELB/CloudFront is not a takeover** — live apps 404 at
  root all the time. Verify unclaimed / NXDOMAIN first.
- **Product-class endpoint = duplicate, not a finding.** The same endpoint appearing on
  many hosts (e.g. the UniFi-OS `/proxy/users/...` routes on 27+ of 4600 consoles) is a
  shipped-product standard API, near-certain dup. `tools/brief_filter.py` measures
  endpoint fan-out and suppresses these. (proven: the first IDOR wave was 88% UniFi noise.)
- **Shared-tenant console = third-party data (HARD LINE, not just an FP).** A host whose
  leftmost label is a high-entropy UUID with thousands of siblings under one wildcard
  (`<uuid>.unifi-hosting.ui.com`) is a per-customer tenant. Any cross-tenant test on one
  you don't own = accessing someone else's data. The idor analyzer skips these at intake;
  only test instances you personally own. SPA-shell 200s (a route returning the app's
  `index.html`, same as `/`) are **not** unauth leaks — probe content-type before claiming.

## Scope discipline (mandatory before any target work)
- `recon-scope` EVERY host before claiming/reporting. Confirm `pays=true`.
- VDP / no-payout (program "dummy", `pays=false`) fails the implied `--pays` filter —
  do not invest effort. Filter on the **per-target authoritative** pays value, not the
  program-level one.
- Internal/corp infrastructure (`*.corp.*`, intranet, `dev-internal`) is out of scope
  even when something is exposed.

## Worked-knowledge: notes vs ignores
**HARD STANDING RULE (any agent): ALWAYS note FPs, skips, disqualifications, and noise — at the
moment you hit them.** "If a target proves to be not valuable it needs to be noted and documented so
we don't waste time" + "always note fps and skips and disqualified and noise this is a doctrine"
(operator, 2026-06-12 / 2026-06-13). This covers EVERY non-finding outcome, not just probed kills:
(a) a probed-and-killed host (note the primitive + the 401/403/version that killed it); (b) a
VERIFIED FALSE POSITIVE (note what made it look real and what disproved it); (c) a target dismissed
by *reasoning alone* (by-design / mis-tag / product-class); (d) NOISE skipped without probing
(product-class / third-party / multi-tenant clusters). All four are re-surfaceable and leave no
trace unless noted. Big cluster ⇒ note 2-3 REPRESENTATIVES with a class-reason, not one-per-host
(that's product-class bloat; the fan-out filter handles the rest). NEVER bench a still-live lead
(staging not-yet-checked, an un-mined JS lead). A skip/FP/dismissal without a note is incomplete
work — if you waved something off as "noise," that judgment MUST be written down.

**HUNT-UNTIL-STOP DOCTRINE (operator, 2026-06-13): never self-terminate a hunt.** Do not ask "want to
wrap?" or offer to stop — keep the probe→triage→note→next loop running continuously until the operator
explicitly says stop. When the current host queue empties, SELF-REPLENISH by re-querying ES
(`recon_alive`, paying + in-scope + not-ignored + un-noted, concrete-class) for the next batch — running
out of hosts is never a reason to stop, it's the trigger to pull more.

`ignored.jsonl` = a TEMPORARY 7-day penalty (a host willingly benched; resurfaces when the
TTL lapses). `host_notes.jsonl` = PERMANENT worked-knowledge keyed to host/root-domain
(`{host,root_domain,program,note,source,created_at}`, deduped on (host,note), NEVER TTL'd).
Every ignore-WITH-reason also persists a note (no reason ⇒ no note); the pipeline's
auto-ignores (`triage_ignored_reason`) backfill as `source:triage`. `recon-inspect` /
`recon-scope` (`has_notes`) / `recon-briefing` (📝) surface notes so a host I've touched
announces itself the moment it resurfaces, and the 2IC routine reads them to stop re-ranking
angles a note already killed. Add/view with `recon-note <host> ["text"]`. Notes never expire;
ignores do.

**ES IS THE SOURCE OF TRUTH (2026-06-13).** The flat files remain the durable write-log, but
every `note_add`/`recon-ignore` now MIRRORS into the `recon_alive` doc(s) for that host
(`recon_ledger_es.sh` → stored scripts `recon_note_push`/`recon_ignore_push`; best-effort,
gate `RECON_ES_WRITEBACK=0`). ES fields: `host_notes[] {note,source,created_at}`,
`host_notes_count`, `host_notes_text`, `ignore_active`, `ignore_reason`, `ignore_added_at`,
`ignore_expires_at`, `ledger_synced_at`. **MANDATORY for ANY agent (incl. Claude) querying ES
directly:** read these and respect them — a raw query does NOT auto-exclude benched hosts
(`triage_ignored` is the *pipeline's* flag, NOT the operator's `recon-ignore`; that gap
resurfaced `railing.meraki.com` off a stale `claude_verdict:real`).
- **Exclude actively-benched**: `must_not` a `{"range":{"ignore_expires_at":{"gt":"now"}}}`
  (self-correcting past the 7-day TTL; `ignore_active` is only the write-time snapshot — trust
  the date range, not the bool).
- **Surface worked-knowledge**: read `host_notes`/`host_notes_text` on every candidate; don't
  re-rank an angle a note already killed. See [[feedback_takeover_claimability_primitive]].

## Submission discipline
- Lead with the most severe **ACCURATE** framing. Don't overclaim — overclaimed
  severity gets reports closed N/A and dings researcher signal. (Real case: an unauth
  metadata exposure was honestly P2-class; "confirmed XSS" on inert reflection would
  have been an N/A.)
- Verify the primitive before reporting. Document with redacted evidence; the
  exposure itself is the report.

## Hard line: recon vs attack (NON-NEGOTIABLE)
- Confirm an exposure exists; do NOT exploit past it. The PoC is "this responds/leaks
  without auth," never a data harvest.
- NEVER: pull other users' data; enumerate account IDs that aren't yours; place/amend/
  cancel orders; initiate transfers/withdrawals/deposits; run RCE primitives (Groovy
  console, file-read CVEs); attempt to bypass a login to get IN.
- IDOR/BOLA testing uses TWO accounts the researcher owns — never guessed/enumerated
  third-party IDs.
- ACTIVE-PoC DOCTRINE (operator, 2026-06-13; ALL agents incl. main Claude, not only CinC prompts):
  a test/PoC need NOT be read-only. An active / state-changing step IS allowed to PROVE IMPACT,
  and agents may complete the SETUP a test needs (create your OWN org, register accounts, complete
  onboarding) — that's authorized own-account setup, not an attack. GATES (all required): (1)
  in-scope + authorized + pays-confirmed; (2) NOT malicious; (3) MINIMAL — only enough to demonstrate,
  then STOP (no exploiting past the PoC). "Non-malicious / prove-impact-only" STILL EXCLUDES the NEVER
  list above and never overrides it: no other users' data, no guessed/third-party IDs, no real money
  movement (transfers/withdrawals/orders that charge), no destruction/DoS, nothing affecting real
  third parties, no login-bypass-to-get-IN, no RCE-for-harm. Prefer reversible/benign demonstrations
  on your OWN scope (read your own 2nd-account object via a swap; `alert()` for XSS; one benign
  authorized action for privesc). The goal is proof, not exploitation. (The autonomous UNATTENDED
  unauth pipeline probes below stay read-only/safe — active PoC is for operator-overseen testing.)
- Autonomous active verification is ALLOWED but only as **SAFE, UNAUTHENTICATED,
  non-destructive** probes via the vetted primitives / `recon_safe_probe.sh` (GET/HEAD/
  OPTIONS, no creds, no redirect-follow, no internal/metadata, scope+pays-gated,
  rate-limited, Mullvad-only, audited). The Claude VERIFY agent may *request* such probes;
  a trusted harness runs them — the model never executes anything itself (it gets no shell).
- Authenticated live-target testing stays human-in-the-loop. The pipeline / any agent
  must NOT autonomously issue **authenticated** requests against live bug-bounty targets.
  DOCTRINE (operator, 2026-06-13): when an authed step is warranted, Claude does NOT walk the
  operator through curl/token-extraction — it hands them a single ready-to-paste **Claude-in-Chrome
  prompt** to run in their logged-in tab (read-only authed recon: map API ops + ID/BOLA params +
  auth-header NAMES + own IDs; redact secret values; NO mutations). The operator owns the session;
  Claude-in-Chrome is the in-browser hands; Claude analyzes the report and builds the 2-account swap.
  Template lives in memory `feedback_authtest_claude_chrome_prompt`. EXTENSION: Claude-in-Chrome may
  also EXECUTE the test (in-browser Burp — replay the actual authed requests, e.g. the BOLA swap)
  GATED on two preconditions stated in the prompt: (1) host confirmed in-scope+PAYING (authoritative
  per-asset), and (2) the test is SAFE + NON-DESTRUCTIVE (read-only queries/GET/HEAD/OPTIONS — never
  mutations/orders/payments/writes/deletes/state-changes). Hard line unchanged: 2 owned accounts,
  swap only owned IDs (never guessed third-party IDs), confirm-then-stop, no harvest.
- Never touch nftables/iptables/VPN config. Mullvad is sole egress; `vpn_down` pauses
  all scanning (and all probing — fail-closed).
- ARCHIVE-EGRESS CARVE-OUT (the ONE sanctioned non-Mullvad path, 2026-06-13): the Internet
  Archive blackholes web.archive.org/CDX (and CommonCrawl) for our Mullvad datacenter ranges,
  killing gau/waybackurls param-URL yield. `recon_params.sh` proxies ONLY the public Wayback-CDX
  lookup through a locked Cloudflare worker (`cdx-proxy.beatmd1.workers.dev`; url+secret in
  ~/.recon_cdx_url / ~/.recon_cdx_key, NOT git) whose egress IA does not block. This NEVER carries
  target traffic — the bug-bounty host is never contacted by the archive call; katana/gau/probes
  stay 100% on Mullvad. Don't burn it: gentle by the per-host 7d cooldown + worker cache; never
  mass-blast or the CF egress gets IA-blocked too. See memory `project_archive_cloudflare_proxy`.

## Self-audit (recon-audit) — the pipeline audits itself on a schedule
`recon-audit` (`scripts/recon_selfaudit.sh` → `engine/selfaudit.py`) is the STANDING, automated
version of the manual `docs/audit_*.md` battery: ~25 named invariant checks (VPN/egress + vpn_down
coherence, scope/feed freshness, ES health + doc-count sanity, findings.db integrity + reporter-feed
sanity + FP-sig/knowledge_base, per-lane silent-zero via `observability.yield_audit`, dangling refs to
deleted scripts, daemon/queue/spool liveness, perm drift, unbounded growth) → a dated report
(`docs/audit_<date>.md`) + `~/recon/state/selfaudit_latest.json`; exits non-zero on any unresolved HIGH.
**It AUTO-FIXES ONLY a narrow, reversible data/state whitelist** (stale validate locks, dead daemon
PID-file, known-good perms, spool retry, log rotation), behind `recon-audit --apply` only, each action
idempotent + logged to `selfaudit_actions.jsonl`. **Everything else is DETECT-ONLY** → a ready-to-paste
Claude-Code fix-prompt (`docs/selfaudit_fixprompt_<date>.md`) + one cooled-down `#ops` alarm. HARD
BOUNDARY (enforced in code): it NEVER edits code/config, touches egress/Mullvad/nftables/gates, clears
`vpn_down`, auto-submits/ignores/fps, or restarts the daemon. The daemon runs it **dry every 6h** (never
`--apply`); `--apply` is operator-only. `recon_watchdog.sh` alarms `#ops` if the auditor's own output
goes stale (it must not silently die).

## Operational notes
- PYTHON IS WSL-ONLY: ALWAYS run python/pip via `wsl.exe -d kali-linux -- python3 …` (or inside a
  WSL shell). NEVER invoke bare `python`/`python3`/`py`/`pip` on the Windows/MINGW side — Windows
  resolves them to the PyManager shim (`C:\Program Files\PyManager`), which, with no managed runtime,
  opens `docs.python.org/dev/using/windows.html` in the default browser (Brave) every time. The whole
  engine runs under WSL python3; there is no reason to touch Windows python.
- WSL: use heredoc form for execution; never `bash -c "..."` (var/escaping breaks).
- ES auth: `-u "elastic:$(cat ~/.recon_es_pass)"`. Field types differ in queries:
  `triage_pays` is a JSON bool; `portscan_critical` is numeric.
- Daemon control: `recon-start` / `start_recon_safe.sh` only. Live-restart safe — the
  daemon stays up; edits take effect next cycle.
- Do NOT touch reconrun-owned `firstblood/` permissions.
- DEBLOAT ALWAYS: when retiring a feature, REMOVE its code/vars/functions/menus/unused scripts — never
  leave commented-out cruft or dead loops. Write temp scripts to `/tmp` (never the data dir) and `rm`
  them after; prefer inline commands. (2026-06-08: the in-daemon Claude loops `ai_idor`/`ai_review`/
  `ai_monitor` were retired — the 2IC routine agent is the sole Claude brain; `ai_analyze` haiku triage
  stays. `recon_ai_review.sh` kept only for the on-demand `recon-verify`.)

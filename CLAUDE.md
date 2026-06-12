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
  daemon loop was retired 2026-06-08 — the routine subsumes it.)
- **n-day racing** (`recon_nday.sh`) — Claude version-reasons KEV/CVE matches to KILL the
  tech-class FP and surface only genuine in-range candidates, in the race window.
- **GitHub leaks** (`recon_ghleaks.sh`) — code-search → trufflehog-verify live leaked
  secrets (off-web surface most ignore).
- **6:30pm briefing** (`recon_briefing.sh`) — one ranked "TONIGHT" card: BAC/IDOR leads to
  test + verified findings to submit. The output that fits a 9-5.
Smart targeting + clone/staging dedup (XBOW) is the next layer; precision over volume.

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
`ignored.jsonl` = a TEMPORARY 7-day penalty (a host willingly benched; resurfaces when the
TTL lapses). `host_notes.jsonl` = PERMANENT worked-knowledge keyed to host/root-domain
(`{host,root_domain,program,note,source,created_at}`, deduped on (host,note), NEVER TTL'd).
Every ignore-WITH-reason also persists a note (no reason ⇒ no note); the pipeline's
auto-ignores (`triage_ignored_reason`) backfill as `source:triage`. `recon-inspect` /
`recon-scope` (`has_notes`) / `recon-briefing` (📝) surface notes so a host I've touched
announces itself the moment it resurfaces, and the 2IC routine reads them to stop re-ranking
angles a note already killed. Add/view with `recon-note <host> ["text"]`. Notes never expire;
ignores do.

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
- Autonomous active verification is ALLOWED but only as **SAFE, UNAUTHENTICATED,
  non-destructive** probes via the vetted primitives / `recon_safe_probe.sh` (GET/HEAD/
  OPTIONS, no creds, no redirect-follow, no internal/metadata, scope+pays-gated,
  rate-limited, Mullvad-only, audited). The Claude VERIFY agent may *request* such probes;
  a trusted harness runs them — the model never executes anything itself (it gets no shell).
- Authenticated live-target testing stays human-in-the-loop. The pipeline / any agent
  must NOT autonomously issue **authenticated** requests against live bug-bounty targets.
- Never touch nftables/iptables/VPN config. Mullvad is sole egress; `vpn_down` pauses
  all scanning (and all probing — fail-closed).

## Operational notes
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

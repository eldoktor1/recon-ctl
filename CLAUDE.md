# recon-pipeline — standing operating doc

Reference for every session. Established through a full session of manual
verification. Keep it tight; update it when a principle changes.

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

## Claude at full capability (v3.4): multimodal, active-verifying, schema-locked, measured
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

**MONITOR (Claude's 3rd role).** `recon_ai_monitor.sh` (hourly daemon loop) reads LOCAL
telemetry only — burn signals (probe blocks/cooldowns/global-pause), verdict precision,
failures/halts, daemon errors, VPN — and emits a skeptical health + burn_risk + guidance
assessment to `#ops` / `recon-ai monitor`. It guides and watches every process; it issues
NO target traffic. So Claude now spans the pipeline: ANALYZE (aim) → VERIFY+probe (confirm)
→ MONITOR (oversee).

Output is **schema-validated** (`--json-schema` → `.structured_output`; no regex scraping;
unparseable ⇒ safe `needs-human`). It **escalates to the big model on genuine ambiguity OR a
low-confidence real/fp**. ANALYZE tiers model by asset value (haiku bulk → sonnet for high
triage_score). And we **measure** it: `state.py ai-accuracy` / `recon-ai accuracy` reports the
human-decided precision of `real` verdicts (accepted vs dismissed) — the only ground truth.
Never pass `--bare` (forces API-key auth, bypasses the Max OAuth login).

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

## Scope discipline (mandatory before any target work)
- `recon-scope` EVERY host before claiming/reporting. Confirm `pays=true`.
- VDP / no-payout (program "dummy", `pays=false`) fails the implied `--pays` filter —
  do not invest effort. Filter on the **per-target authoritative** pays value, not the
  program-level one.
- Internal/corp infrastructure (`*.corp.*`, intranet, `dev-internal`) is out of scope
  even when something is exposed.

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

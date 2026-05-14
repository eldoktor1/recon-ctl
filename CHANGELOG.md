# Changelog — Autonomous Bug Bounty Recon Pipeline

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
- [ ] Verify `recon-start` alias in `~/.zshrc`: `alias recon-start='~/recon-pipeline/tools/start_recon_safe.sh'`
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
- All scripts moved from `~/` flat layout into `~/recon-pipeline/` git repository
- Structure: `scripts/`, `docker/`, `CHANGELOG.md`, `RUNBOOK.md`, `.gitignore`, `README.md`
- `ReconWatchdog` Task Scheduler updated to launch from repo: `~/recon-pipeline/scripts/recon_daemon.sh`
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

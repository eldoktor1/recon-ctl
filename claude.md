# Recon Pipeline — Agent Context

## What This Is

A 24/7 automated bug bounty reconnaissance pipeline running inside WSL2
(kali-linux) on a Windows 11 machine. Its job: discover subdomains across
thousands of programs, fingerprint them, score them for vulnerability signals,
and surface the highest-value leads to the operator via Discord.

This is not a toy. It indexes 30,000+ live hosts in Elasticsearch and runs
continuously as a background daemon. Any change that breaks a running script
must be compatible with a live restart — the daemon stays up.

---

## Environment

| Layer         | Detail |
|---------------|--------|
| Host OS       | Windows 11, Mullvad WireGuard VPN (all WSL2 egress routes through it) |
| WSL2 distro   | kali-linux |
| Pipeline user | `d0k` (interactive), `reconrun` (sandboxed scanner user) |
| Shell         | zsh (interactive), bash (all scripts) |
| ES            | Elasticsearch 8.17.4 in Docker (`es01` container, port 9200, auth enabled) |
| Ollama        | Local LLM inference, port 11434, model `llama3.1:8b-instruct-q4_K_M` |
| Kibana        | `kib01` container, port 5601 |

**Never touch nftables/iptables** — WSL2 uses Windows Mullvad for egress, no local kill-switch needed.

**ES auth** uses `~/.recon_es_netrc` (mode 600). All ES curl calls must use
`--netrc-file "$HOME/.recon_es_netrc"`. Never `-u elastic:PASSWORD` (exposes
creds in `ps aux`). Call `setup_es_netrc` (from `recon_net.sh`) before any
ES curl. When calling from Windows via WSL, use a heredoc:
`wsl -d kali-linux -- bash << 'EOF' ... EOF`

---

## Repository Layout

```
/home/d0k/recon-pipeline/
  scripts/
    recon_daemon.sh          — master daemon, spawns all loops
    recon_validate.sh        — httpx → ES ingest (dual-lane: normal + fast)
    recon_discovery.sh       — subfinder/assetfinder → inbox batches
    recon_scope_watch.sh     — polls new scope from platforms → inbox
    recon_scope_db.sh        — fetches program list + payout tiers from H1/BC/etc.
    recon_scope_check.sh     — host-level in/out-of-scope check (batch mode)
    recon_cve_intel.sh       — CISA KEV + NVD fetch, tech→CVE map, kev_targets
    recon_vuln_feed.sh       — EPSS/Vulnrichment/GHSA normalize → vuln_targets
    recon_brain.sh           — manual/scheduled full refresh (scope+KEV+vuln+triage)
    triage.sh                — 6-phase scoring engine (tech signals, scope, KEV,
                               true_fresh, vuln, cluster dedup → agent_targets.jsonl)
    recon_ai_review.sh       — Claude-Max VALIDATION agent (headless `claude -p`,
                               no API): adversarially judges evidence-gate-CONFIRMED
                               findings → ai_verdict in v3/findings.db (accuracy layer)
    recon_evidence_gate.sh   — Phase A: probes P0-CANDIDATEs, promotes only real fires
    recon_takeover_hunter.sh — CNAME/NXDOMAIN takeover first-blood detection
    recon_true_fresh.sh      — certstream CT-log listener → true_fresh.jsonl
    recon_fresh_modules.sh   — post-true_fresh enrichment modules
    recon_nuclei.sh          — targeted nuclei runs on triage output
    recon_discord_bot.sh     — Discord polling bot (outbound only, single whitelisted UID)
    recon_net.sh             — thin network wrappers (run_net, curl_net, curl_direct)
    recon_ctl.sh             — control script: start/stop/status/health/queue/top/ai/etc.
    recon_es_bootstrap.sh    — ES index setup
    recon_inspect.sh         — query/inspect tool
    recon_killswitch.sh      — kill-switch management (WSL2: no-op)
    recon_hot_seed.sh        — flushes CT/true_fresh results to fast-lane inbox
  tools/
    start_recon_safe.sh      — runs preflight then recon_ctl.sh start
    check_recon_killswitch.sh
    enable_recon_killswitch.sh
    sync_bounty_templates.sh
  docs/
    RUNBOOK.md
    PROXY_KILLSWITCH.md
    VULN_INTEL.md
```

---

## Data Directories (inside WSL at `/home/d0k/recon/`)

```
queue/
  inbox/        — discovery batches waiting for httpx (*.txt, one host per line)
  processing/   — atomically claimed by validate
  done/         — post-httpx evidence (*.jsonl) + processed markers
spool/
  pending/      — normalized jsonl pre-ES-ingest
  sent/         — successfully ingested
  failed/       — ES ingest failures (retried on next cycle)
state/
  recon_daemon.pid
  validate.*.lock        — per-lane validate locks
  known_hosts.txt        — all probed hosts (dedup)
  alive_hosts.txt        — httpx-confirmed live
  hot_seed_seen.txt      — CT-log dedup
  root_domains.txt       — 2363 root domains for discovery
  true_fresh.jsonl       — CT-log first-seen records (from certstream)
  ignored.jsonl          — operator ignore list (TTL 7d)
  kill/v2_*              — kill-switch flags per module
logs/
  recon_daemon.log       — main log (all daemon loops write here)
  discord_bot.log
triage/
  agent_targets.jsonl    — final scored+sorted output (JSONL, one record/line)
  report_*.md            — per-run markdown reports
  .seen_high.txt         — Discord dedup watermark
scope/
  programs.json          — all programs with payout_tier
  inscope_patterns.tsv   — host pattern → program mapping
cve/
  kev.json               — CISA KEV catalog
  kev_targets.jsonl      — ES hosts matching KEV tech signals
  nvd_recent.json        — NVD recent CVEs
vuln/
  vuln_feed.jsonl        — normalized multi-source vuln records
  vuln_targets.jsonl     — vuln_feed matched to ES assets
  summary.json           — feed stats
firstblood/
  takeovers_to_claim.tsv
  takeovers_watching.tsv
v3/
  findings.db            — SQLite finding-state store (WAL). Lifecycle states +
                           Claude-Max validation verdicts (ai_verdict/ai_confidence/
                           ai_reason). Source of truth for confirmed→reported flow.
  reports/review_queue.jsonl — human review/submit queue (never auto-submitted)
```

---

## Daemon Architecture

```
recon_daemon.sh (PID in state/recon_daemon.pid)
  ├── vpnguard          20s — pauses every other loop on Mullvad egress failure
  ├── discovery         30m — subfinder + assetfinder → inbox batches
  ├── validate          2m  — httpx → ES → takeover → triage (normal lane)
  ├── validate-fast     2m  — same but --prefix 00_ (true-fresh fast lane)
  ├── scope-watch       90m — polls platforms for new scope → inbox
  ├── takeover-watch    5m  — background NXDOMAIN/CNAME re-sweep
  ├── hot-seed          5m  — flushes CT results to fast-lane batches
  ├── true-fresh        2m  — gungnir CT listener + enrichment
  ├── scope-db          24h — refreshes programs.json
  ├── cve-kev           1h  — CISA KEV refresh
  ├── cve-nvd           24h — NVD recent CVEs
  ├── vuln-feed         1h  — EPSS/Vulnrichment/GHSA normalize
  ├── nuclei-v21        6h  — targeted nuclei on triage output (bounty templates)
  ├── bounty-scan       30m — fresh_modules smart-scan
  ├── deep-scan         24h — fresh_modules deep-scan
  ├── active-checks     10m — fresh_modules active-checks
  ├── js-scanner        30m — fresh_modules js-scan
  ├── cloudrecon        1h  — Caduceus cert neighbor enumeration
  ├── dast              30m — DAST param-fuzz on fresh hosts
  ├── params            30m — sus_params catalog (gf classification)
  ├── portscan          90m — targeted ~120-port sweep on P1+ non-CDN
  ├── bypass            1h  — WAF-aware 401/403 access-control bypass
  ├── restale           8h  — re-queue stale P0/P1 (>14d) into inbox
  ├── digest            24h — daily Discord summary to #health
  ├── exposure          8h  — nuclei exposure templates (P0/P1)
  ├── screenshot        2h  — Playwright + stealth, 200x150 thumb to ES
  └── discord-bot       5s  — operator-facing slash commands
```

Target-facing loops run via `run_scanner()` → `sudo -n -u reconrun env ...`.
Non-target-facing loops (digest, restale) run as `d0k` directly.
Edge case: `screenshot` is target-facing but runs as `d0k` because Playwright
lives in `$HOME` — the supervise_loop VPN gate still pauses it on egress
failure, so the real IP is never exposed.

AC power = 150 threads / 100 rate (default). Battery = halved. Override per-
session with `recon-rate light|easy|medium|full` or a custom `<t> <r>` pair.

---

## Triage Score System

Phase 1 — `score_raw()` (jq, parallel workers):
- Tech signals: +2 to +9 pts (Jenkins=9, Confluence=9, GitLab=8, WordPress=5, etc.)
- Port signals: +2 to +9 pts
- Status signals: 401=+2, 403=+3, 500=+2
- Title signals: dir listing=+6, phpinfo=+6, debug errors=+4
- Host pattern signals: admin/dev/internal/ci/scm = +3 to +5 (LOW confidence)
- Negative signals: CDN+no-tech=-1, redirect+no-tech=-2, mail server=-3, generic-www=-2

Phase 1.5 — `apply_scope_kev_enrichment()`:
- pays: +2, tier low+1/mid+3/high+5/elite+8, KEV match: +5
- Hard-excluded or confirmed-OOS: dropped entirely

Phase 1.6 — `apply_extra_enrichment()`:
- true_fresh (CT-log): +10 (confirmed tech) or +3 (pattern-only)
- Breaking vuln (true_fresh + vuln_feed match): T0+12 / T1+8 / T2+5 / T3+2
- JS secret: +10 / endpoint: +5 (both gated to true_fresh)
- Ignore list: -50

Phase 2 — `apply_cluster_and_submission()`:
- cluster dedup (>3 same root+signals): -3/host
- already-submitted: -5
- pattern_only hard cap: score clamped to P0_THRESHOLD-1 (=14)

Priority bands: P0 ≥15, P1 ≥8, P2 ≥4, P3 ≥3

---

## Shell Aliases (in ~/.recon_aliases, auto-sourced by zsh + bash)

```bash
# Daemon lifecycle
recon-up               # start ES + daemon
recon-start            # preflight + daemon
recon-stop             # graceful stop (covers all module loops)
recon-restart          # stop + start
recon-status           # daemon + queue + ES summary
recon-health           # full health check (worker dup detection)
recon-logs             # tail daemon log
recon-rate             # show / set effective rate (presets: light/easy/medium/full)
recon-boost            # full rate
recon-browse           # light rate

# Lead viewers (all read ES)
recon-top              # top scored
recon-fresh / -new     # true-fresh P0/P1
recon-kev              # KEV-matched
recon-confirmed        # nuclei-confirmed
recon-vuln             # vuln feed hits
recon-tech             # tech-fingerprint search
recon-js               # JS secrets + endpoints
recon-takeovers        # claim list (ES + raw)
recon-watching         # pending takeover rechecks
recon-ports / -exposed # port scanner hits
recon-bypass           # 401/403 bypass confirmations
recon-screenshots      # screenshotted hosts table
recon-gallery          # rebuild HTML gallery
recon-gallery-open     # open the gallery in Windows Explorer
recon-ai-*             # AI layer (top/now/high/watch/p0)

# Manual triggers
recon-portscan         # one cycle now (as reconrun)
recon-bypass-now       # one cycle now (as reconrun)
recon-screenshot       # one cycle now (as d0k)
recon-screenshot-backfill [N]   # one-shot, hosts with NO screenshot_at yet
recon-screenshot-test <host>    # capture + render gallery
recon-screenshot-install        # idempotent venv + chromium setup
recon-revalidate       # re-queue stale P0/P1 into inbox
recon-digest-now       # send digest now

# Actions
recon-submit / -ignore / -fp / -inspect / -dupes
```

---

## Security Constraints

- `reconrun` runs scanners. It has no shell login, no sudo to root.
- `d0k ALL=(reconrun) NOPASSWD: ALL` in `/etc/sudoers.d/recon-reconrun`
- `/usr/local/sbin/recon-safe-preflight` (root-owned) handles startup checks
- No proxychains. No Tor. No local VPN kill-switch in WSL2.
- Discord per-channel webhooks in `~/.recon_discord_{takeovers,fresh,vulns,cve,health}` (read at call time by `discord_hook()` in `recon_net.sh`; old single `~/.recon_discord` is retired); bot token in `~/.recon_discord_bot`
- API keys: `WPSCAN_API_TOKEN` and `SECURITYTRAILS_API_KEY` in `~/.zshrc`

---

## Key Gotchas

1. **Running commands in WSL from Windows**: Always use heredoc form:
   `wsl -d kali-linux -- bash << 'EOF' ... EOF`
   NOT: `wsl -d kali-linux -- bash -c "..."` (escaping breaks `$VAR` and `[:space:]`)

2. **Git from Windows path**: The Bash tool runs in MINGW64 (Git Bash). Paths
   like `/home/d0k/` don't exist from MINGW64. Use `//wsl.localhost/kali-linux/home/d0k/`
   for file reads/edits, and `wsl -d kali-linux -- bash << 'EOF'` for execution.

3. **WSL restart kills the daemon**: The daemon does NOT auto-restart on WSL
   boot. After any reboot you must: clear the stale PID file, confirm ES/Docker
   are up, then run `recon-start`.

4. **ES auth**: All ES requests need `--netrc-file "$HOME/.recon_es_netrc"`.
   The cluster returns 401 without it, not connection refused.
   Never use `-u elastic:PASSWORD` — it exposes credentials in `ps aux`.

5. **Daemon log path**: `/home/d0k/recon/logs/recon_daemon.log` — all loops
   redirect stderr there. This is the single source of truth for what's happening.

6. **`triage.sh` is not at `scripts/triage.sh`**: It IS at `scripts/triage.sh`
   but called from daemon/brain as `"$SCRIPT_DIR/triage.sh"`.

7. **validate processed=0**: Normal when inbox is empty. Discovery feeds inbox.
   If discovery has no live subfinder/assetfinder processes AND hot-seed finds
   nothing, the pipeline is stalled — not broken, just starved of new hosts.

8. **`IFS=$'\n\t'` + space-joining arrays**: Every script sets that IFS. With
   it set, `${arr[*]}` joins on newline (the first IFS char), NOT space —
   silently breaks every membership test built from the join. Always:
   `printf '%s ' "${arr[@]}"`. This bit the port scanner and is the easiest
   regression to reintroduce.

9. **Apostrophes inside single-quoted jq/bash strings**: An apostrophe in a
   comment or string inside a single-quoted heredoc terminates the bash string
   mid-script and produces a runtime syntax error. Use "do not" not "don't",
   "it is" not "it's". This caused a critical `triage.sh` regression once.
   Also applies to git commit messages — always use the heredoc form
   `git commit -m "$(cat <<'GITMSG' ... GITMSG)"`.

10. **`exists` on a `binary` ES field with `doc_values: false` matches zero**.
    The `screenshot_thumb_b64` mapping has `doc_values: false` to keep the
    index small; filtering by `{"exists":{"field":"screenshot_thumb_b64"}}`
    silently returns no documents. Filter on the companion `screenshot_status`
    keyword instead. Same trap applies to any other field added with
    `doc_values: false`.

---

## Module-specific Notes

### Bypass (`recon_bypass.sh`)
- WAF fingerprint is HEAD-then-GET so CDNs that hide headers on HEAD still get
  classified. Used purely to reorder the technique queue; never gates a probe.
- The technique catalog is emitted as one text stream with `\x1f` (US) between
  header values inside one technique line. `_unpack_technique` un-splits and
  prepends `-H` per value. `_techniques_for_waf_dedup` strips duplicates
  introduced by the per-WAF priority head.
- Per-host wall-clock budget (`BYPASS_HOST_BUDGET`, default 180s) protects the
  daemon loop. Burning the whole budget on one host is fine; the next cycle
  picks up where we left off because of the 7d cooldown bookkeeping.
- Stores an **array** of bypass records in ES (`bypass_paths`). Each is
  `{path, technique, code, size, confidence}`. The `bypass_technique` /
  `bypass_top_confidence` top-level fields and the Discord embed pull the
  highest-confidence entry from this array.

### Screenshot (`recon_screenshot.sh` + `tools/screenshot_worker.py`)
- Python lives in `~/recon/venv/screenshot/` (Kali's PEP 668 blocks system
  pip). Install via `recon-screenshot-install` — idempotent.
- Chromium is the **headless shell** build (~120MB, downloaded into
  `~/.cache/ms-playwright/`). Do not install `--with-deps` from WSL2 — apt
  deps are large and Playwright runs fine without them on Kali.
- `playwright_stealth` has two API generations (`stealth_sync` in 1.x,
  `Stealth` class in 2.x). The worker autodetects.
- Block detection downscales the screenshot to 10×10 RGB and checks per-
  channel spread. <15 = essentially solid colour = WAF interstitial. Block
  hits store `screenshot_status: "blocked"` and do not show in the gallery.
- ES binary field `screenshot_thumb_b64` stores the 200×150 JPEG at ~5-8KB
  base64. `doc_values: false, store: false` keeps the index small; you can
  only read the field via `_source` (which is fine — that is exactly how the
  gallery renderer consumes it).
- Gallery is a single static HTML file with inline `data:image/jpeg;base64,…`
  thumbs and a JS filter box. Opens in Windows Explorer via
  `recon-gallery-open` (wslpath translates the path).
- Runs as `d0k` even though it is target-facing. Playwright cache lives in
  `$HOME` and shuffling through sudo for every cycle is brittle. The
  supervise_loop VPN gate still pauses this loop on `vpn_down`, so traffic
  cannot leave with the real IP.

### Restale / Digest
- Both run as `d0k`, not `run_scanner`. Restale only writes to `queue/inbox/`;
  digest only reads ES + POSTs to Discord. Neither egresses to a target.
- Digest uses `_count` with multiple filter clauses; the helper originally had
  a missing closing brace and returned 0 for every metric. If a digest shows
  every number as 0, check `_count()` braces first.

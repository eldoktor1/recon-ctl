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
    recon_ai_score.sh        — Ollama review of top triage leads
    recon_ai_pack.sh         — packages AI results for operator
    recon_takeover_hunter.sh — CNAME/NXDOMAIN takeover first-blood detection
    recon_true_fresh.sh      — certstream CT-log listener → true_fresh.jsonl
    recon_fresh_modules.sh   — post-true_fresh enrichment modules
    recon_nuclei.sh          — targeted nuclei runs on triage output
    recon_discord_bot.sh     — Discord polling bot (outbound only, single whitelisted UID)
    recon_net.sh             — thin network wrappers (run_net, curl_net, curl_direct)
    recon_ctl.sh             — control script: start/stop/status/health/queue/top/ai/etc.
    recon_es_bootstrap.sh    — ES index setup
    recon_ollama.sh          — Ollama API call wrapper
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
ai_review/
  ai_scored.jsonl        — Ollama-reviewed leads
  rejected/              — raw Ollama output that failed JSON parse
```

---

## Daemon Architecture

```
recon_daemon.sh (PID in state/recon_daemon.pid)
  ├── discovery          subfinder + assetfinder → inbox batches
  ├── validate           httpx → ES ingest → takeover-hunter → triage (normal lane)
  ├── validate-fast      same but --prefix 00_ (true-fresh hot-seed priority)
  ├── scope-watch        polls platforms for new scope → inbox
  ├── takeover-hunter    background NXDOMAIN/CNAME sweep
  ├── hot-seed           flushes CT results to 00_-prefixed fast-lane batches
  ├── true-fresh         certstream CT listener + enrichment
  ├── scope-db           refreshes programs.json every 4h
  ├── cve-intel          KEV+NVD refresh every 6h
  ├── vuln-feed          vuln intelligence refresh every 1h
  ├── nuclei             targeted nuclei on triage output
  └── discord-bot        polling bot (5s interval)
```

All loops run `run_scanner()` which executes as `reconrun` via `sudo -n -u reconrun env ...`.
AC power = 80 threads / 100 rate. Battery = 40 threads / 50 rate.

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

## Shell Aliases (in ~/.zshrc)

```bash
recon-start    # run preflight + start daemon
recon-stop     # graceful stop
recon-status   # daemon + queue + ES summary
recon-health   # full health check
recon-clean    # archive stale queue files
recon-logs     # tail daemon log
recon-boost    # enable boost mode
recon-browse   # enable browse mode
recon-ai       # AI review status
recon-queue    # queue file counts
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

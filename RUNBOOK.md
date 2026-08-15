# Recon Pipeline Runbook

## Current Setup

Running on WSL2 (Kali) with Windows Mullvad VPN. All egress from WSL2 goes
through Mullvad on the host — no local proxy or nftables rules needed.

Features:

- true-fresh engine (`recon_true_fresh.sh`) — certstream + crt.sh
- dual-lane validator (fast lane `--prefix 00_` for hot-seed batches)
- **Claude ANALYZE** (Haiku) — aims the net: which in-scope assets are worth testing + class
- **multi-class CONFIRM** (SAFE primitives): evidence-gate (nuclei + interactsh OOB for SSRF/XXE),
  `xss-confirm` (browser marker-exec), `param-confirm` (SSTI/redirect/SQLi differential)
- **Claude VERIFY** (Sonnet→Opus) — adversarial FP filter on every confirmed finding → `#review`
- every lane's confirmation routes through `findings.db` → Claude verify (universal FP gate)
- hidden Windows autostart via `ReconWatchdog` → `start_recon_safe.sh`
- local Elasticsearch at `http://127.0.0.1:9200` (index `recon_alive` alias → `recon_alive_v3`)
- target-facing scanners running under `reconrun`; Claude agents under `d0k` (Max auth)
- preflight + Mullvad VPN gate before each start; `recon-maintenance on` rebuild lock
- passive vuln intelligence (KEV + NVD + vuln feeds) with ES matching
- `browser_curl` / random real-browser UA helpers in `recon_net.sh`

> v3.2 architecture, restore-from-clone, and daily commands: see `README.md`.
> Operating doctrine (CONFIRMED-vs-LEAD, per-class SAFE primitives, hard line): `CLAUDE.md`.
> The legacy Ollama AI-review layer was retired in v3.1 — Claude (Max, headless, no API) is the AI layer.

## Core Architecture

    Windows ReconElastic
        -> starts local Elasticsearch Docker stack

    Windows ReconWatchdog
        -> runs hidden through wscript.exe
        -> calls C:\recon\start_recon_hidden.vbs
        -> starts WSL as d0k
        -> runs /home/d0k/recon-ctl/tools/start_recon_safe.sh
        -> runs /usr/local/sbin/recon-safe-preflight
        -> verifies VPN egress and local ES
        -> starts recon daemon safely

    recon_daemon.sh
        -> supervises discovery, validation, scope-watch, hot-seed, takeover-watch, nuclei, schedule loops

    scanner-heavy paths
        -> run under reconrun
        -> protected by nftables fail-closed kill switch

    local Elasticsearch
        -> http://127.0.0.1:9200
        -> index: recon_alive

## Golden Rule

Do not start target-facing recon without preflight. Only use:

    recon-start

or:

    ~/recon-ctl/tools/start_recon_safe.sh

or let the hidden Windows task `ReconWatchdog` start it.

Never call `recon_daemon.sh` or `recon_ctl.sh start` directly without
verifying the kill switch first.

## Safe Startup

Preferred manual startup:

    recon-start

The `recon-start` alias should point to:

    alias recon-start='~/recon-ctl/tools/start_recon_safe.sh'

The safe startup script does this:

    sudo -n /usr/local/sbin/recon-safe-preflight
    SCANNER_USER=reconrun ~/recon-ctl/scripts/recon_ctl.sh start

The preflight script:

- detects WSL2 and removes any stale nftables rules
- verifies reconrun can reach the internet via Mullvad
- verifies local Elasticsearch works on `127.0.0.1:9200`
- refuses to start recon if any safety check fails

## Noninteractive Sudo

The root-owned preflight script is installed at:

    /usr/local/sbin/recon-safe-preflight

Two sudoers rules are required. Both are auto-installed by preflight on every startup:

    # Run the root-owned preflight without a password (allows Windows Task Scheduler)
    d0k ALL=(root) NOPASSWD: /usr/local/sbin/recon-safe-preflight

    # Allow d0k to launch scanner processes as the locked reconrun user
    d0k ALL=(reconrun) NOPASSWD: ALL

Files:

    /etc/sudoers.d/recon-safe-preflight   — preflight rule
    /etc/sudoers.d/recon-reconrun         — scanner user rule (auto-created by preflight)

The reconrun rule grants privilege *down* to a locked, shell-less user — not up to root.
The nftables kill switch on uid 996 is the real security boundary.

General sudo to root still requires a password.

## IP Protection Model

Target-facing scanner work runs under `reconrun`.

On WSL2, Mullvad runs on the Windows host and protects all egress via the
virtual `eth0` adapter — no local nftables kill-switch is applied. See
`docs/PROXY_KILLSWITCH.md` for the full model.

## VPN stability

On WSL2, if Mullvad on Windows drops, all WSL2 egress loses VPN protection.
The supervised loops will back off on network failures and resume when
connectivity returns.

To verify reconrun egress is going through Mullvad:

    sudo -u reconrun curl -s --max-time 8 https://ifconfig.me  # should be VPN IP

If it shows your home IP, Mullvad on Windows is disconnected — reconnect from
the Windows Mullvad app.

## Killswitch Check

`tools/check_recon_killswitch.sh` is intentionally non-interactive. It requires
passwordless sudo for nftables inspection and for running curl as `reconrun`.
If that sudo path is not available, the check exits immediately with a clear
error instead of waiting for a password prompt.

## Windows Scheduled Tasks

### ReconElastic

Safe to keep enabled.

Purpose:

    Starts local Elasticsearch Docker stack

Expected action:

    docker.exe compose -f C:\recon\recon_database\docker-compose.yml up -d

### ReconWatchdog

Safe final version.

Purpose:

    Hourly + on-logon health check and auto-restart (NOT a one-shot startup)

Expected action:

    wscript.exe C:\recon\recon_watchdog.vbs

The VBS wrapper runs:

    C:\Windows\System32\wsl.exe -d kali-linux -u d0k bash /home/d0k/recon-ctl/tools/recon_watchdog.sh

`recon_watchdog.sh` checks daemon/VPN/ES/queue/disk health and, if the daemon is
DOWN and VPN+ES are both OK, restarts it via `tools/start_recon_safe.sh`. The VBS
wrapper uses hidden mode (window style 0), so no console box should appear.

(`C:\recon\start_recon_hidden.vbs` → `start_recon_safe.sh` exists for a manual
hidden one-shot start, but it is NOT the action of any active scheduled task.)

Check from PowerShell:

    schtasks /Query /TN "ReconWatchdog" /V /FO LIST | findstr /I "TaskName Task To Run Last Result Status"

Expected:

    Last Result: 0
    Task To Run: wscript.exe C:\recon\recon_watchdog.vbs
    Scheduled Task State: Ready

Do not configure `ReconWatchdog` to call `recon_daemon.sh` directly.

## Daily Commands

Safe start:

    recon-start

Health and status:

    ~/recon-ctl/scripts/recon_ctl.sh health
    ~/recon-ctl/scripts/recon_ctl.sh status
    ~/recon-ctl/scripts/recon_ctl.sh queue
    ~/recon-ctl/scripts/recon_ctl.sh vuln status
    ~/recon-ctl/scripts/recon_ctl.sh vuln top
    ~/recon-ctl/scripts/recon_ctl.sh ai
    ~/recon-ctl/scripts/recon_ctl.sh top 20
    ~/recon-ctl/scripts/recon_ctl.sh takeovers
    ~/recon-ctl/scripts/recon_ctl.sh watching
    ~/recon-ctl/scripts/recon_ctl.sh logs 100
    ~/recon-ctl/scripts/recon_ctl.sh space

Stop:

    ~/recon-ctl/scripts/recon_ctl.sh stop

Clean:

    ~/recon-ctl/scripts/recon_ctl.sh clean

## Passive Vuln Intelligence

The transcript-driven CVE change is handled by `recon_vuln_feed.sh`.

Purpose:

    Do not wait for complete NVD enrichment.
    Normalize public vuln/advisory/template signals.
    Match them against already-indexed assets in local Elasticsearch.
    Produce a passive race queue for safe review.

Outputs:

    ~/recon/vuln/vuln_feed.jsonl      normalized vuln records
    ~/recon/vuln/summary.json         feed counts by tier/source
    ~/recon/vuln/vuln_targets.jsonl   local ES asset matches

Commands:

    ~/recon-ctl/scripts/recon_ctl.sh vuln status
    ~/recon-ctl/scripts/recon_ctl.sh vuln top
    ~/recon-ctl/scripts/recon_ctl.sh v2 refresh-vuln

Daemon behavior:

    The daemon runs the vuln-feed loop automatically every hour by default.
    The worker runs as reconrun. It does not execute nuclei and does not probe targets.

Risk tiers:

    T0  CISA KEV
    T1  fresh/public template or high-confidence public check exists
    T2  fresh or high-risk advisory before complete enrichment
    T3  weak signal, report-only until stronger evidence

Safety rule:

    AI may summarize why a target matters and draft safe verification plans,
    but AI output must not create or auto-run nuclei templates.

## Discord Bot

Useful commands:

    !status
    !health
    !queue
    !top 10
    !takeovers
    !watching
    !logs 20
    !clean
    !start
    !stop
    !rescue
    !help

## Manual Sanity Check

Run:

    cd ~/recon-ctl
    git status --short
    tools/check_recon_killswitch.sh
    ~/recon-ctl/scripts/recon_ctl.sh health

Confirm no scanner-heavy processes are owned by `d0k`:

    ps -eo user,pid,ppid,cmd | grep -E 'httpx|subfinder|assetfinder|nuclei|recon_validate|recon_discovery|recon_scope_watch|recon_nuclei' | grep -v grep | grep '^d0k' || echo "OK: no d0k-owned scanner processes"

Check reconrun scanner sockets:

    for p in $(pgrep -u reconrun -f 'httpx|subfinder|assetfinder|nuclei'); do
      echo "---- PID $p ----"
      ps -p "$p" -o user,pid,ppid,cmd
      ss -tnp 2>/dev/null | grep "pid=$p," || echo "no active TCP connection"
    done

Expected:

- git status clean
- direct outbound from reconrun (outside VPN iface) blocked
- system VPN (Mullvad WG) up and routing
- local ES works
- daemon running
- ES green
- no d0k-owned scanner processes

## Local Elasticsearch

Local ES is expected at:

    http://127.0.0.1:9200

Password file:

    ~/.recon_es_pass

Health check:

    curl -u elastic:$(cat ~/.recon_es_pass) http://127.0.0.1:9200/_cluster/health

If ES is down:

    cd /mnt/c/recon/recon_database
    docker compose up -d

Then wait about 60 seconds and re-check health.

## Queue Behavior

Queue paths:

    ~/recon/queue/inbox/
    ~/recon/queue/processing/
    ~/recon/queue/done/

Priority prefixes:

    00_ = hot
    01_ = scope
    10_ = normal

Check queue:

    ~/recon-ctl/scripts/recon_ctl.sh queue

If inbox reaches the cap, discovery may pause. That is expected behavior.

If processing is stuck for a long time:

    ~/recon-ctl/scripts/recon_ctl.sh stop
    recon-start

Nuclear reset:

    ~/recon-ctl/scripts/recon_ctl.sh stop
    ~/recon-ctl/scripts/recon_ctl.sh reset-queue
    recon-start

## Takeover Hunter

The takeover hunter is the first-blood path.

It runs in two modes:

1. Streaming mode

    Called by validator on completed batches.

2. Watch mode

    Rechecks medium-confidence candidates.

Manual check:

    ~/recon-ctl/scripts/recon_takeover_hunter.sh check api.example.com

Files:

    ~/recon/firstblood/takeovers_to_claim.tsv
    ~/recon/firstblood/takeovers_watching.tsv
    ~/recon/firstblood/takeovers.log

When HIGH or CRITICAL appears:

1. Check Discord embed.
2. Verify CNAME manually.
3. Verify HTTP behavior manually.
4. Check known disclosures.
5. Submit quickly.
6. Mark submission:

    ~/recon-ctl/scripts/recon_ctl.sh submit <host> takeover pending

## Submission Dedup

After submitting a finding:

    ~/recon-ctl/scripts/recon_ctl.sh submit www.example.com xss accepted
    ~/recon-ctl/scripts/recon_ctl.sh submit api.foo.com sqli pending
    ~/recon-ctl/scripts/recon_ctl.sh submit grafana.bar.io rce duplicate

This appends to:

    ~/.recon_submissions.jsonl

Effects:

- exact host gets dampened
- related root domain gets dampened
- Discord avoids re-notifying on known submissions

Inspect:

    ~/recon-ctl/scripts/recon_ctl.sh dupes
    ~/recon-ctl/scripts/recon_ctl.sh dupes example.com

## Files and Locations

| Path | Purpose |
|---|---|
| `~/recon-ctl/scripts/` | Repo-managed scripts (single source of truth) |
| `~/recon-ctl/tools/start_recon_safe.sh` | Safe manual/Windows startup wrapper |
| `~/recon-ctl/tools/enable_recon_killswitch.sh` | Manual nft kill switch restore helper |
| `~/recon-ctl/tools/check_recon_killswitch.sh` | Manual kill switch sanity check |
| `/usr/local/sbin/recon-safe-preflight` | Root-owned secure startup preflight |
| `/etc/sudoers.d/recon-safe-preflight` | Narrow NOPASSWD rule for preflight only |
| `C:\recon\start_recon_hidden.vbs` | Hidden Windows WSL startup wrapper |
| `~/.recon_es_pass` | ES password |
| `~/recon/state/discord/review` | Webhook → #review (Claude `real`/`needs-human` → APPROVE/DISMISS/INVESTIGATE) |
| `~/recon/state/discord/takeovers` | Webhook → #takeovers (first-blood candidates) |
| `~/recon/state/discord/ops` | Webhook → #ops (halts / vpn / nuclei auto-disable) |
| `~/recon/state/discord/digest` | Webhook → #digest (daily brief) |
| `~/.recon_discord_bot` | Discord bot token (optional inbound command bot) |
| `~/.recon_discord_allowed_uid` | Allowed Discord user ID (inbound bot) |
| `~/.recon_discord_channel_id` | Allowed Discord channel ID (inbound bot) |
| `~/.recon_es_netrc` | ES credentials (netrc) |
| `~/.recon_submissions.jsonl` | Submission history |
| `~/recon/queue/inbox/` | Pending batches |
| `~/recon/queue/processing/` | In-flight batches |
| `~/recon/queue/done/` | Completed httpx jsonl files |
| `~/recon/firstblood/` | Takeover candidates and logs |
| `~/recon/triage/` | Reports and agent targets |
| `~/recon/state/` | Known hosts, alive hosts, locks, pids |
| `~/recon/spool/` | ES bulk retry spool |
| `~/recon/logs/` | Daemon and child logs |

## Troubleshooting

### Daemon will not start

Check:

    ~/recon-ctl/scripts/recon_ctl.sh logs 200

Look for:

    ES unreachable
    ES password not set
    preflight failure (VPN or ES check failed)

### Safe startup fails

Run:

    cd ~/recon-ctl
    tools/check_recon_killswitch.sh

Then start safely:

    recon-start

### VPN is not working

On WSL2, Mullvad runs on Windows. Check the Windows Mullvad app — reconnect if disconnected.

Then verify reconrun egress is through Mullvad (should NOT show your home IP):

    sudo -u reconrun curl -s --max-time 8 https://ifconfig.me

### ES is not working

Start local ES:

    cd /mnt/c/recon/recon_database
    docker compose up -d

Check:

    curl -u elastic:$(cat ~/.recon_es_pass) http://127.0.0.1:9200/_cluster/health

### Windows task did not work

Check in PowerShell:

    schtasks /Query /TN "ReconWatchdog" /V /FO LIST | findstr /I "TaskName Task To Run Last Result Status"

Expected:

    Last Result: 0
    Task To Run: wscript.exe C:\recon\start_recon_hidden.vbs

If the task path is wrong, fix the action to:

    wscript.exe C:\recon\start_recon_hidden.vbs

### Scanner shows as d0k

This is bad for target-facing scanner-heavy processes.

Stop recon:

    ~/recon-ctl/scripts/recon_ctl.sh stop

Kill leftovers:

    sudo pkill -KILL -u reconrun 2>/dev/null || true
    pkill -KILL -f 'recon_daemon.sh|recon_validate.sh|recon_discovery.sh|recon_scope_watch.sh|recon_takeover_hunter.sh|recon_nuclei.sh|httpx|subfinder|assetfinder|nuclei' 2>/dev/null || true

Start safely:

    recon-start

Verify:

    ps -eo user,pid,ppid,cmd | grep -E 'httpx|subfinder|assetfinder|nuclei|recon_validate|recon_discovery|recon_scope_watch|recon_nuclei' | grep -v grep | grep '^d0k' || echo "OK: no d0k-owned scanner processes"

## Architecture Notes

- All scripts resolved from repo; no home-directory fallbacks
- Scanner-heavy paths run as `reconrun` via `run_scanner` in daemon
- Egress protected by Windows Mullvad (WSL2); preflight verifies at startup
- No Tor, no proxychains, no local nftables kill-switch in WSL2
- Mode toggling removed (v2.5.2); daemon auto-throttles on battery via `acpi`
- Queue priority: `00_` hot-seed → `01_` scope-watch → `10_` normal discovery

# Recon Pipeline Runbook

## Current Stable Checkpoint

    v2.1.6-killswitch

This is the current stable recovery/hardening checkpoint.

This version includes:

- restored repo-managed recon scripts
- restored daemon and Discord bot wiring
- safe hidden Windows autostart
- local Elasticsearch support
- target-facing scanners running under `reconrun`
- nftables kill switch for IP leak prevention
- noninteractive safe startup through preflight
- documented recovery and sanity checks

## Core Architecture

    Windows ReconElastic
        -> starts local Elasticsearch Docker stack

    Windows ReconWatchdog
        -> runs hidden through wscript.exe
        -> calls C:\recon\start_recon_hidden.vbs
        -> starts WSL as d0k
        -> runs /home/d0k/recon-pipeline/tools/start_recon_safe.sh
        -> runs /usr/local/sbin/recon-safe-preflight
        -> verifies kill switch, Tor, and local ES
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

Do not start target-facing recon with plain:

    ~/recon_ctl.sh start

unless the kill switch has already been verified.

Use only:

    recon-start

or:

    cd ~/recon-pipeline
    tools/start_recon_safe.sh

or let the hidden Windows task `ReconWatchdog` start it.

## Safe Startup

Preferred manual startup:

    recon-start

The `recon-start` alias points to:

    cd ~/recon-pipeline && tools/start_recon_safe.sh

The safe startup script does this:

    sudo -n /usr/local/sbin/recon-safe-preflight
    SCANNER_USER=reconrun USE_PROXYCHAINS=1 PROXY_URL=socks5h://127.0.0.1:9050 ~/recon_ctl.sh start

The preflight script:

- reapplies the nftables kill switch
- verifies direct outbound from `reconrun` is blocked
- verifies Tor SOCKS works on `127.0.0.1:9050`
- verifies local Elasticsearch works on `127.0.0.1:9200`
- refuses to start recon if any safety check fails

## Noninteractive Sudo

The root-owned preflight script is installed at:

    /usr/local/sbin/recon-safe-preflight

A narrow sudoers rule allows `d0k` to run only this script without a password:

    d0k ALL=(root) NOPASSWD: /usr/local/sbin/recon-safe-preflight

This prevents Windows Task Scheduler from hanging on a sudo password prompt.

General sudo still requires a password.

## IP Protection Model

Target-facing scanner work runs under:

    reconrun

The `reconrun` user is locked down by nftables.

Allowed:

    127.0.0.1/8
    ::1
    127.0.0.1:9050  Tor SOCKS
    127.0.0.1:9200  local Elasticsearch

Blocked:

    Any direct public outbound traffic from reconrun

Expected nftables rule:

    table inet recon_killswitch {
        chain output {
            type filter hook output priority filter - 10; policy accept;
            meta skuid 996 ip daddr 127.0.0.0/8 accept
            meta skuid 996 ip6 daddr ::1 accept
            meta skuid 996 reject
        }
    }

The kill switch is the real fail-closed protection.

Proxychains and native proxy flags are still used, but they are not the only security control.

## Native Proxy Flags

Tools with native proxy support are launched with SOCKS proxy flags:

    httpx -http-proxy socks5h://127.0.0.1:9050
    subfinder -proxy socks5h://127.0.0.1:9050
    nuclei -proxy socks5h://127.0.0.1:9050

`assetfinder` is skipped in proxy-safe mode because it does not provide a trusted native proxy flag.

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

    Hidden safe recon startup

Expected action:

    wscript.exe C:\recon\start_recon_hidden.vbs

The VBS wrapper runs:

    C:\Windows\System32\wsl.exe -d kali-linux -u d0k -- bash -lc "/home/d0k/recon-pipeline/tools/start_recon_safe.sh"

The VBS wrapper uses hidden mode, so no console box should appear.

Check from PowerShell:

    schtasks /Query /TN "ReconWatchdog" /V /FO LIST | findstr /I "TaskName Task To Run Last Result Status"

Expected:

    Last Result: 0
    Task To Run: wscript.exe C:\recon\start_recon_hidden.vbs
    Scheduled Task State: Enabled

Do not configure `ReconWatchdog` to call `recon_daemon.sh` directly.

## Daily Commands

Safe start:

    recon-start

Health and status:

    ~/recon_ctl.sh health
    ~/recon_ctl.sh status
    ~/recon_ctl.sh queue
    ~/recon_ctl.sh top 20
    ~/recon_ctl.sh takeovers
    ~/recon_ctl.sh watching
    ~/recon_ctl.sh logs 100
    ~/recon_ctl.sh space

Stop:

    ~/recon_ctl.sh stop

Clean:

    ~/recon_ctl.sh clean

## Mode Switching

Mode source of truth:

    ~/.recon_mode

Used by:

- Discord `!mode`
- CLI `~/recon_ctl.sh mode`
- scheduler `recon_schedule.sh`
- daemon cycles

CLI:

    ~/recon_ctl.sh mode browse
    ~/recon_ctl.sh mode night

Discord:

    !mode
    !mode browse
    !mode night

Schedule:

    Browse mode: 5:30 PM to 11:30 PM Pacific
    Night mode: all other scheduled hours
    Scheduler check interval: 5 minutes

Already-running batches may finish with the mode they started with. New cycles use the updated mode.

## Discord Bot

The Discord bot is restored and should show/use the same mode file:

    ~/.recon_mode

Useful commands:

    !status
    !health
    !queue
    !top 10
    !takeovers
    !watching
    !logs 20
    !mode
    !mode browse
    !mode night
    !start
    !stop
    !rescue
    !help

Important:

- `!mode` should match `cat ~/.recon_mode`
- Discord should not have separate scheduling logic
- scheduler, CLI, Discord, and daemon all use the same source of truth

## Manual Sanity Check

Run:

    cd ~/recon-pipeline
    git status --short
    tools/check_recon_killswitch.sh
    ~/recon_ctl.sh health

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
- direct outbound from reconrun blocked
- Tor SOCKS works
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

    ~/recon_ctl.sh queue

If inbox reaches the cap, discovery may pause. That is expected behavior.

If processing is stuck for a long time:

    ~/recon_ctl.sh stop
    recon-start

Nuclear reset:

    ~/recon_ctl.sh stop
    ~/recon_ctl.sh reset-queue
    recon-start

## Takeover Hunter

The takeover hunter is the first-blood path.

It runs in two modes:

1. Streaming mode

    Called by validator on completed batches.

2. Watch mode

    Rechecks medium-confidence candidates.

Manual check:

    ~/recon_takeover_hunter.sh check api.example.com

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

    ~/recon_ctl.sh submit <host> takeover pending

## Submission Dedup

After submitting a finding:

    ~/recon_ctl.sh submit www.example.com xss accepted
    ~/recon_ctl.sh submit api.foo.com sqli pending
    ~/recon_ctl.sh submit grafana.bar.io rce duplicate

This appends to:

    ~/.recon_submissions.jsonl

Effects:

- exact host gets dampened
- related root domain gets dampened
- Discord avoids re-notifying on known submissions

Inspect:

    ~/recon_ctl.sh dupes
    ~/recon_ctl.sh dupes example.com

## Files and Locations

| Path | Purpose |
|---|---|
| `~/recon-pipeline/scripts/` | Repo-managed scripts |
| `~/recon_*.sh`, `~/triage.sh` | Compatibility symlinks to repo scripts |
| `~/recon-pipeline/tools/start_recon_safe.sh` | Safe manual/Windows startup wrapper |
| `~/recon-pipeline/tools/enable_recon_killswitch.sh` | Manual nft kill switch restore helper |
| `~/recon-pipeline/tools/check_recon_killswitch.sh` | Manual kill switch sanity check |
| `/usr/local/sbin/recon-safe-preflight` | Root-owned secure startup preflight |
| `/etc/sudoers.d/recon-safe-preflight` | Narrow NOPASSWD rule for preflight only |
| `C:\recon\start_recon_hidden.vbs` | Hidden Windows WSL startup wrapper |
| `~/.recon_es_pass` | ES password |
| `~/.recon_discord` | Discord webhook URL |
| `~/.recon_discord_bot` | Discord bot token |
| `~/.recon_discord_allowed_uid` | Allowed Discord user ID |
| `~/.recon_discord_channel_id` | Allowed Discord channel ID |
| `~/.recon_submissions.jsonl` | Submission history |
| `~/.recon_mode` | browse or night |
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

    ~/recon_ctl.sh logs 200

Look for:

    ES unreachable
    ES password not set
    kill switch/preflight failure
    Tor unavailable

### Safe startup fails

Run:

    cd ~/recon-pipeline
    tools/check_recon_killswitch.sh

If direct outbound from reconrun is not blocked, reapply:

    sudo tools/enable_recon_killswitch.sh

Then start safely:

    recon-start

### Tor is not working

Check listener:

    ss -ltnp | grep ':9050'

Start Tor:

    sudo service tor start

Then test:

    sudo -u reconrun curl -s --socks5-hostname 127.0.0.1:9050 --max-time 20 https://ifconfig.me

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

    ~/recon_ctl.sh stop

Kill leftovers:

    sudo pkill -KILL -u reconrun 2>/dev/null || true
    pkill -KILL -f 'recon_daemon.sh|recon_validate.sh|recon_discovery.sh|recon_scope_watch.sh|recon_takeover_hunter.sh|recon_nuclei.sh|httpx|subfinder|assetfinder|nuclei' 2>/dev/null || true

Start safely:

    recon-start

Verify:

    ps -eo user,pid,ppid,cmd | grep -E 'httpx|subfinder|assetfinder|nuclei|recon_validate|recon_discovery|recon_scope_watch|recon_nuclei' | grep -v grep | grep '^d0k' || echo "OK: no d0k-owned scanner processes"

## What Changed From Prior Builds

- removed direct Windows startup of `recon_daemon.sh`
- added hidden Windows `ReconWatchdog` through VBS
- added safe startup wrapper `tools/start_recon_safe.sh`
- added root-owned preflight `/usr/local/sbin/recon-safe-preflight`
- added locked scanner user `reconrun`
- added nftables fail-closed kill switch for `reconrun`
- moved scanner-heavy execution under `run_scanner`
- added native proxy flags for httpx, subfinder, and nuclei
- skipped assetfinder in proxy-safe mode
- restored Discord bot and command set
- restored missing daemon/live recon loop scripts
- documented IP leak testing and final protection model
- deleted `git_tag_versions.sh`
- kept annotated Git tag `v2.1.6-killswitch` as current stable checkpoint

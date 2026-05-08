# Recon Proxy / IP Exposure Kill Switch

## Purpose

This recon system uses a locked service user named `reconrun` for target-facing scanner activity.

The goal is to prevent accidental real-IP exposure from scanner tools such as:

- httpx
- subfinder
- nuclei
- assetfinder

Earlier testing showed that proxychains and native proxy flags alone were not enough because some tools could still create direct outbound sockets. The final protection model uses a kernel-level nftables kill switch.

## Security Model

Scanner-heavy processes run as `reconrun`.

The Discord/control layer may remain under `d0k`.

The `reconrun` user is blocked from all non-loopback outbound traffic.

Allowed:
- 127.0.0.1/8
- ::1
- 127.0.0.1:9050 for Tor SOCKS
- 127.0.0.1:9200 for local Elasticsearch

Blocked:
- Any direct outbound public IP connection from `reconrun`

## Expected nftables Rule

Expected rule:

    table inet recon_killswitch {
      chain output {
        type filter hook output priority filter - 10; policy accept;
        meta skuid 996 ip daddr 127.0.0.0/8 accept
        meta skuid 996 ip6 daddr ::1 accept
        meta skuid 996 reject
      }
    }

## Verified Behavior

Sanity check passed:

- Daemon is running.
- Elasticsearch is green.
- Queue is moving.
- No scanner processes are owned by `d0k`.
- Scanner processes run under `reconrun`.
- Direct outbound from `reconrun` is blocked.
- Tor SOCKS through `127.0.0.1:9050` works.
- Local Elasticsearch through `127.0.0.1:9200` works.

## Scanner Ownership

Expected scanner processes:

    reconrun ... recon_validate.sh
    reconrun ... httpx -http-proxy socks5://127.0.0.1:9050
    reconrun ... recon_discovery.sh
    reconrun ... subfinder -proxy socks5://127.0.0.1:9050

There should be no target-facing scanner processes owned by `d0k`.

## Daemon Behavior

The daemon uses `run_scanner` to launch scanner-heavy paths under `reconrun`.

Protected paths include:

- validation / httpx
- discovery / subfinder
- scope-watch enrichment
- takeover-watch
- nuclei v2.1 path when conditions trigger

The nuclei path was verified in code:

    run_scanner bash "$V21_NUCLEI"

## Native Proxy Flags

Native proxy flags are still used where available:

    httpx -http-proxy socks5://127.0.0.1:9050
    subfinder -proxy socks5://127.0.0.1:9050
    nuclei -proxy socks5://127.0.0.1:9050

However, the nftables kill switch is the real fail-closed protection.

## Assetfinder

`assetfinder` is skipped when proxy-safe mode is enabled because it does not provide a trusted native proxy flag.

## Required Startup

Use:

    SCANNER_USER=reconrun USE_PROXYCHAINS=1 PROXY_URL=socks5://127.0.0.1:9050 ~/recon_ctl.sh start

## Sanity Check Commands

    ~/recon_ctl.sh health

    ps -eo user,pid,ppid,cmd \
      | grep -E 'httpx|subfinder|assetfinder|nuclei|recon_validate|recon_discovery|recon_scope_watch|recon_nuclei' \
      | grep -v grep \
      | grep '^d0k' || echo "OK: no d0k-owned scanner processes"

    sudo nft list chain inet recon_killswitch output

    sudo -u reconrun curl -s --max-time 5 https://ifconfig.me || echo "OK direct blocked"

    sudo -u reconrun curl -s --socks5-hostname 127.0.0.1:9050 --max-time 20 https://ifconfig.me; echo

    sudo -u reconrun curl -s --max-time 5 -u "elastic:$(tr -d '[:space:]' < ~/.recon_es_pass)" http://127.0.0.1:9200 | jq -r '.cluster_name // .name'

## Important Warning

nftables rules may not survive a WSL shutdown or reboot unless restored manually or via a startup script.

Before running target-facing recon, always confirm:

    sudo nft list chain inet recon_killswitch output

and confirm direct outbound from `reconrun` is blocked.

## Shell Alias

A convenience alias was added to `~/.zshrc`:

    alias recon-start='cd ~/recon-pipeline && tools/start_recon_safe.sh'

This alias is not stored directly in Git because it lives in the user's shell config, but the script it runs is stored in Git:

    tools/start_recon_safe.sh

Use this command after opening Kali/WSL:

    recon-start

This command enables the nftables kill switch, verifies direct outbound from `reconrun` is blocked, verifies Tor SOCKS and local Elasticsearch, then starts recon safely.

Do not use plain `~/recon_ctl.sh start` for target-facing recon unless the kill switch has already been verified.

## Final Noninteractive Startup

Final reliable startup flow:

    Windows ReconWatchdog task
    -> wsl.exe -d kali-linux -u d0k -- zsh -lc "source ~/.zshrc; recon-start"
    -> recon-start alias
    -> tools/start_recon_safe.sh
    -> sudo -n /usr/local/sbin/recon-safe-preflight
    -> ~/recon_ctl.sh start

A root-owned preflight script was installed at:

    /usr/local/sbin/recon-safe-preflight

The preflight script:
- reapplies the nftables kill switch for `reconrun`
- verifies direct outbound from `reconrun` is blocked
- verifies Tor SOCKS on `127.0.0.1:9050`
- verifies local Elasticsearch on `127.0.0.1:9200`
- exits before recon starts if any safety check fails

A narrow sudoers rule was added:

    d0k ALL=(root) NOPASSWD: /usr/local/sbin/recon-safe-preflight

This allows the Windows scheduled task to run safely without hanging on a sudo password prompt.

Only this fixed root-owned preflight script is passwordless. General sudo access still requires a password.

Verified:
- `sudo -k && recon-start` completed without a sudo password prompt.
- Preflight enabled the kill switch.
- Direct outbound from `reconrun` was blocked.
- Tor SOCKS worked.
- Local Elasticsearch worked.
- Recon started safely or reported the daemon was already running.

Important:
- The Windows task must call `recon-start`.
- Do not configure Windows Task Scheduler to call `recon_daemon.sh` directly.

## Hidden Windows ReconWatchdog Final Setup

`ReconWatchdog` now runs hidden through a Windows Script Host wrapper.

Windows task action:

    wscript.exe C:\recon\start_recon_hidden.vbs

The wrapper file is stored on Windows at:

    C:\recon\start_recon_hidden.vbs

The wrapper runs:

    C:\Windows\System32\wsl.exe -d kali-linux -u d0k -- bash -lc "/home/d0k/recon-pipeline/tools/start_recon_safe.sh"

This keeps the task hidden while still using the safe startup path.

Validated:
- `ReconWatchdog` runs with LastTaskResult 0.
- No visible console/window is shown.
- The task does not call `recon_daemon.sh` directly.
- Startup still goes through `tools/start_recon_safe.sh`.
- The safe preflight verifies the kill switch, Tor SOCKS, and local Elasticsearch before recon starts.

## Final Sanity Log

Final validated state:

- Git checkpoint: `v2.1.6-killswitch`
- Windows task `ReconWatchdog` runs hidden through `wscript.exe C:\recon\start_recon_hidden.vbs`
- Hidden wrapper calls WSL and runs `tools/start_recon_safe.sh`
- `tools/start_recon_safe.sh` runs `/usr/local/sbin/recon-safe-preflight`
- Preflight reapplies the nftables kill switch before recon starts
- Direct outbound from `reconrun` is blocked
- Tor SOCKS on `127.0.0.1:9050` works
- Local Elasticsearch on `127.0.0.1:9200` works
- Scanner-heavy processes run under `reconrun`
- No scanner-heavy processes should run under `d0k`
- `ReconElastic` remains responsible for local Elasticsearch Docker startup
- `ReconWatchdog` must not call `recon_daemon.sh` directly

Mode switching:

- Source of truth: `~/.recon_mode`
- Discord `!mode`, CLI `recon_ctl mode`, and scheduler all use the same mode file
- Schedule uses Pacific Time
- Browse mode: 5:30 PM to 11:30 PM PT
- Night mode: all other scheduled hours
- Scheduler loop checks mode regularly through the daemon
- Already-running batches may finish with the mode they started with; new cycles use the updated mode

Operational rule:

Use either the hidden Windows task or:

    recon-start

Do not start target-facing recon with plain `~/recon_ctl.sh start` unless the kill switch has already been verified.

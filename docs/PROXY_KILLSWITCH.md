# IP Exposure Protection Model

## How It Works (WSL2 + Windows Mullvad)

Scanner-heavy processes (`httpx`, `subfinder`, `assetfinder`, `nuclei`) run as the locked
service user `reconrun`. All target-facing work goes through this user.

On WSL2, **Mullvad runs on the Windows host** and protects all egress via the virtual `eth0`
adapter. Every packet leaving WSL2 — regardless of which uid sends it — exits through Mullvad.
There is no local WireGuard interface inside WSL2, and no local nftables kill-switch is needed
or applied.

The preflight script (`/usr/local/sbin/recon-safe-preflight`) detects WSL2 at startup,
removes any stale nftables rules, and verifies that reconrun can reach the internet via the VPN:

```bash
if grep -qi "microsoft\|WSL" /proc/version; then
    # WSL2: Windows Mullvad covers all egress — no local nft rules needed
    nft delete table inet recon_killswitch 2>/dev/null || true
fi
# Verify egress works (should return a Mullvad IP, not your home IP)
sudo -u reconrun curl -s --max-time 5 https://ifconfig.me
```

## Verifying Protection

```bash
# Should return a Mullvad/VPN IP, NOT your home IP
sudo -u reconrun curl -s --max-time 8 https://ifconfig.me

# Kill-switch tool (WSL2-aware — skips nft check, runs egress test)
tools/check_recon_killswitch.sh
```

## What Runs as reconrun

| Process | Why |
|---|---|
| `httpx` | live host validation |
| `subfinder` / `assetfinder` | subdomain discovery |
| `nuclei` | vulnerability scanning |
| `recon_validate.sh` | queue drain orchestrator |
| `recon_discovery.sh` | discovery orchestrator |
| `recon_scope_watch.sh` | scope change watcher |
| `recon_takeover_hunter.sh` | takeover detection |
| `recon_nuclei.sh` | nuclei orchestrator |

The Discord/control layer and passive feeds (certstream, crt.sh, ES queries)
run as `d0k` — they do not touch targets.

## Native Linux (non-WSL2)

If running on bare Linux with a local WireGuard interface, the preflight and
`tools/enable_recon_killswitch.sh` apply an nftables rule that restricts reconrun
to the VPN interface only:

```
meta skuid <reconrun-uid> oif "wg-mullvad" accept
meta skuid <reconrun-uid> reject
```

This ensures that if the VPN drops, reconrun traffic is blocked rather than leaking
through the default route.

## Startup

Always start via the safe wrapper which runs preflight first:

```bash
recon-start          # alias → tools/start_recon_safe.sh
```

Never call `recon_ctl.sh start` or `recon_daemon.sh` without running preflight first.

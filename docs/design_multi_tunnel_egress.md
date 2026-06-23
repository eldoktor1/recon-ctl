# DESIGN — multi-tunnel Mullvad egress (parallel exit IPs to scale throughput)

Goal: raise scan throughput without getting any single Mullvad exit IP rate-banned.
N tunnels to N different relays = N exit IPs; one scanner worker per IP, each polite
per-IP => ~Nx aggregate, none banned. EGRESS/ROUTING is a hard-line zone — built and
verified operator-aware, with fail-closed proven before any live cutover.

## STATUS — gluetun proxy approach: BUILT + TESTED 2026-06-22 ✅ (cutover pending)
Chose **gluetun proxy containers** over raw netns+nftables (see "Alternative" below) because
it keeps the VPN churn OUT of the fragile Kali netstack and away from host nftables surgery.

Tool: `scripts/recon_multitunnel.sh {build|up|down|test|status|proxies}`.
- One `gluetun` container per `~/.config/mullvad-tunnels/*.conf` (operator's 3 Mullvad WireGuard
  configs, chmod 600, **never committed**). Each exposes an HTTP proxy on `127.0.0.1:888N` with
  gluetun `FIREWALL=on` = **fail-closed killswitch** (tunnel down ⇒ no traffic, never the real IP).
- Proxy list written to `~/recon/state/egress_proxies.txt` (one `http://127.0.0.1:PORT` per line).
- **Tested:** 3/3 tunnels healthy, 3 distinct Mullvad exits verified via `am.i.mullvad.net`:
  `us-lax-wg-407` → 146.70.172.126 · `us-sjc-wg-402` → 79.127.217.55 · `us-sjc-wg-504` → 23.234.93.187
  (all distinct from the live pipeline exit `us-sjc-wg-501`).
- **Gotcha handled:** Mullvad `.conf` `Address` carries IPv4+IPv6; gluetun rejects the IPv6 unless
  IPv6 is enabled in-container, so the tool passes the **IPv4 `/32` only**.

### Isolation guarantee (why this was safe to build unattended)
The containers are an **additive, isolated** capability. They do NOT touch host nftables/iptables,
the Kali netns, or the live Mullvad egress — the running pipeline still egresses via the Windows
Mullvad app, unchanged. Container traffic currently double-tunnels (gluetun WG over the host's
Windows-Mullvad) — fine for correctness (target sees the gluetun exit); can be optimized at cutover.

## CUTOVER — IMPLEMENTED 2026-06-22 (flag-gated, off by default), operator-present
Validated before enabling: **fail-closed proven** (stopped tunnel ⇒ proxy refuses, no leak; and the
containers sit behind the host Mullvad, so worst case is a Mullvad IP, never the real ISP), and the
**exact runtime path verified** — `reconrun` via the proxy exits `us-sjc-wg-504`; httpx honors `HTTPS_PROXY` env.
- `run_scanner` (recon_daemon.sh) round-robins `state/egress_proxies.txt` per invocation **when
  `MULTITUNNEL=1`**, setting `HTTP(S)_PROXY` for the child and `NO_PROXY=localhost,127.0.0.1,::1` so ES
  ingest stays direct. Flag off ⇒ behaviour completely unchanged.
- **Enable:** `recon-multitunnel on` (writes `state/multitunnel_on`); `recon-ctl start` exports
  `MULTITUNNEL=1` when that toggle exists (persists across restarts). `recon-multitunnel off` reverts.
  Restart the pipeline to apply. `recon-multitunnel status` shows the toggle + proxy count.
- Tools that honor `HTTP(S)_PROXY` env (httpx/nuclei/katana/gau/curl) load-balance across the IPs;
  any that don't fall back to the host Mullvad exit (still safe). DNS (puredns) stays direct on public
  resolvers — not ban-risk traffic, not proxied.

### Remaining tuning (optional, when more throughput is wanted)
1. **Per-IP rate bump:** with load spread over N IPs, `HTTPX_RATE` can rise (each IP still polite).
2. **Concurrent validate workers:** for true Nx *simultaneous* drain, run N validate workers each pinned
   to a distinct proxy (today's round-robin spreads across invocations/loops, not one loop in parallel).
3. **Per-proxy health → vpn_down:** add a periodic `recon-multitunnel test`; degrade to fewer workers if
   a tunnel drops; only a FULL loss pauses scanning.
Keep the hard line unchanged (2 owned accounts for authed tests, etc.).

## Operate
```
scripts/recon_multitunnel.sh build     # (re)generate compose+env from ~/.config/mullvad-tunnels/*.conf
scripts/recon_multitunnel.sh up        # start the tunnel containers
scripts/recon_multitunnel.sh test      # verify each proxy's Mullvad exit IP
scripts/recon_multitunnel.sh status    # container health
scripts/recon_multitunnel.sh down      # stop them (frees the Mullvad device slots)
```
Configs live in `~/.config/mullvad-tunnels/*.conf` (chmod 600). Each consumes one Mullvad device slot.
Generate more on a DIFFERENT relay/city for more distinct IPs (same relay = same IP = no gain).

## Alternative (rejected for now): netns-per-tunnel + nftables
Cleaner isolation in theory but touches host nftables (hard-line zone) and adds wg interfaces +
namespaces INSIDE the fragile WSL2 netstack (the relay-drop history). Revisit only if the gluetun
proxy model proves insufficient. Keep per-netns fail-closed (default-drop) if ever built.

## WSL caveat
Multiple tunnels + Docker add load; gluetun runs in Docker Desktop's own WSL distro (isolated from
kali), and double-tunnels through the host Mullvad so it adds NO new Windows host adapter (not the
churn class that was dropping terminals — that was the user@1000 flap + WSLCorePort, fixed by linger
+ WSL 2.7.8). Still: bring the stack `down` if the box shows any instability.

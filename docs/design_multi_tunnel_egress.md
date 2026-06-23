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

## CUTOVER (NOT done — operator-reviewed, the only remaining step)
Pointing the pipeline's scanners at these proxies changes egress, so it stays operator-present:
1. **Fail-closed re-proof per tunnel:** with a container up, kill its WG (`docker exec <c> wg-quick down wg0`
   or stop the tunnel), then `curl -x http://127.0.0.1:PORT am.i.mullvad.net` — it MUST fail (no response),
   never return the real IP. Confirm for each before trusting.
2. **Worker→proxy assignment:** `run_scanner` reads `state/egress_proxies.txt` and assigns a proxy
   round-robin per spawned worker (export `HTTP_PROXY`/`HTTPS_PROXY` for the child, or pass the tool's
   `-proxy`/`-http-proxy` flag — httpx/nuclei/katana all support it). Gate behind `MULTITUNNEL=1`
   (default off) so it's a deliberate switch, not silent.
3. **Per-IP anti-burn:** the existing per-host + global rolling-window caps become per-egress-IP
   (each proxy is its own IP); keep the polite per-IP rate.
4. **vpn_down logic:** `vpnguard` already guards the host Mullvad. Add per-proxy health (the gluetun
   `/v1/openvpn/status` or a periodic `test`); degrade to fewer workers if a tunnel drops; only a FULL
   loss pauses scanning. DNS (puredns) stays direct on public resolvers — not ban-risk traffic, not proxied.
5. Keep the hard line: 2 owned accounts for authed tests, etc. — unchanged.

The proposed `run_scanner` change touches the egress gate — do it with the operator, not autonomously.

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

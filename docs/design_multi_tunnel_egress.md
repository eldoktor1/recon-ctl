# DESIGN — multi-tunnel Mullvad egress (parallel exit IPs to scale throughput)

Status: **PROPOSED — not built.** Drafted 2026-06-22. Operator has 3 spare Mullvad devices
(5/account max; 2 in use). Goal: raise aggregate scan/validate throughput without getting any
single exit IP rate-banned. This is an EGRESS/ROUTING change — the one area the doctrine says
not to touch autonomously. Build it **operator-at-keyboard + verify fail-closed**, never overnight.

## Why it works (and the hard constraint it respects)
Today the pipeline egresses through ONE Mullvad tunnel; anti-burn caps aggregate ≈30 req/s so
that single IP is never banned. With N tunnels to N DIFFERENT relays you get N exit IPs; run one
scanner worker per tunnel, each at the same polite per-IP rate → ≈N× aggregate while every
individual IP stays under its ban threshold. The politeness rule is unchanged — it just applies
per-IP instead of globally.

**Key detail:** different exit IPs require different RELAYS (cities/servers). Generate each
WireGuard config against a distinct relay; same-relay configs share one exit IP (no gain).

## The non-negotiable: per-tunnel FAIL-CLOSED
The current invariant is "Mullvad sole egress; tunnel down ⇒ `vpn_down` ⇒ all scanning pauses;
never leak to the real ISP IP." That invariant must hold PER TUNNEL. If wg2 drops, the worker
bound to wg2 must drop its packets, NOT fall back to the host default route (= the real IP or
another tunnel, corrupting attribution + leaking). Re-proving this for every tunnel is the whole
job; nothing ships until each is verified.

## Recommended architecture: one network namespace per tunnel
Cleanest isolation; each netns has its own routing table + default route + killswitch, so a dead
tunnel simply has no route (fails closed by construction).

1. Generate N WireGuard configs from Mullvad (distinct relays) → `wg0..wgN-1`.
2. For each: create a netns, move/!create the wg interface inside it, set the tunnel as the
   netns default route, and add a default-DROP rule in that netns so a tunnel-down state has no
   fallback route (per-netns killswitch).
3. Run each scanner worker as `ip netns exec ns_k bash recon_validate.sh ...`. validate's
   **atomic `mv inbox→processing` claim already makes concurrent workers safe** sharing one
   inbox — no partitioning needed; two workers can never claim the same batch.
4. VERIFY before trusting: in each netns, `curl https://am.i.mullvad.net/json` → `mullvad_exit_ip:true`
   with the EXPECTED distinct IP; then take a tunnel down and confirm that worker's traffic stops
   (no leak), the others keep running.

Alternative (simpler, weaker): fwmark + `ip rule` policy routing, one table per tunnel, bind each
worker with `SO_MARK`. Avoids netns but the killswitch is easier to get subtly wrong (a missing
rule leaks). Prefer netns.

## Pipeline wiring (after the netns layer exists)
- `run_scanner` gains a tunnel-selector: round-robin or least-loaded netns per spawned worker.
- Spawn K validate workers (K = number of healthy tunnels) instead of one; `vpnguard` tracks
  per-tunnel health and writes `vpn_down` only when ALL tunnels are down (partial degrade = fewer
  workers, not a full stop).
- Anti-burn caps become PER-IP (they already are per-host + global; add per-egress-IP windows).
- Self-audit `vpn.egress` check extended to assert every active netns egresses via its own
  Mullvad IP.

## Strategic note (read before building)
More IPs ≠ "drain the bulk_ backlog faster." That backlog is stale mass-discovery volume
(precision-over-volume MOTTO says archive it, see archive/). Spend the extra capacity on the
lanes that pay — fresh-blood racing, params/XSS-SQLi confirm, permute/uncover/kr/blindxss — not
on grinding commodity volume.

## Build checklist (operator-at-keyboard)
- [ ] Generate 3 configs, distinct relays, store keys chmod-600 outside the repo.
- [ ] Stand up netns + per-netns default-drop killswitch for each.
- [ ] Verify each: distinct `mullvad_exit_ip:true`; tunnel-down ⇒ no leak (fail-closed).
- [ ] Teach `run_scanner` + `vpnguard` about N tunnels; per-IP anti-burn windows.
- [ ] Extend `recon-audit vpn.egress` to all netns.
- [ ] WSL caveat: multiple wg interfaces + netns inside WSL2 — test against the known netstack
      fragility (see memory project_wsl_netstack_wedge_vpn_latch) before relying on it.

# recon-pipeline

Autonomous bug bounty recon pipeline.

## Structure
```
scripts/
  auto_recon.sh     — one recon cycle (Chaos + subfinder + httpx + ES ingest)
  triage.sh         — scoring engine → agent_targets.jsonl + Discord
  recon_daemon.sh   — forever loop, mode-aware, proxychains support
  recon_ctl.sh      — control interface (status/mode/logs/top/health/clean)
  recon_vuln_feed.sh — passive CVE/advisory/template intelligence normalization
docker/
  docker-compose.yml — ES 8.17.4 + Kibana 8.17.4
```

## Quick start
```bash
~/recon_ctl.sh status
~/recon_ctl.sh mode night
~/recon_ctl.sh logs
```

## Passive fresh-vuln intelligence
`recon_vuln_feed.sh` builds the transcript-driven "fresh vuln race queue"
without scanning targets. It normalizes local KEV/NVD data and optional public
feeds such as EPSS, CISA Vulnrichment, and ProjectDiscovery nuclei-template
signals, then matches those records against local Elasticsearch assets.

```bash
~/recon-pipeline/scripts/recon_ctl.sh vuln status
~/recon-pipeline/scripts/recon_ctl.sh vuln top
~/recon-pipeline/scripts/recon_ctl.sh v2 refresh-vuln
```

The daemon refreshes this layer automatically. Nuclei remains separately gated
and will not run from AI-generated or raw advisory data.

## Clean active views safely
Routine cleanup now archives stale runtime files instead of deleting useful
evidence:

```bash
~/recon_ctl.sh clean
```

For a clean active dashboard without losing useful findings, stop the daemon and
archive the current active result/log views:

```bash
~/recon_ctl.sh stop
~/recon_ctl.sh clean-start --yes
```

## Proxy / IP safety
Default startup is fail-closed. Use `tools/start_recon_safe.sh`, which requires the
root preflight, Tor SOCKS on `127.0.0.1:9050`, and the `reconrun` nftables kill
switch before target-facing recon starts.

Elasticsearch is expected to be Windows-local at `http://127.0.0.1:9200`; the
Docker compose file binds ES/Kibana to localhost only.

## True-freshness engine (v2.5)
`recon_true_fresh.sh` runs from the daemon and feeds the pipeline with
domains that are genuinely new (≤24h old) by listening to the certstream
WSS feed and polling crt.sh every 6h. Hits are scope-filtered to in-scope
paying programs only and dropped into `queue/inbox/00_truefresh_*.txt`
batches for the fast-lane validator. Durable feed:
`~/recon/state/true_fresh.jsonl`. Discord alerts are gated to
`true_fresh && in_scope && pays && (P0||P1)`.

Bounty-first scanning runs on these fresh hosts only:

- `recon_smart_scan.sh` (30 min): top 10 fresh + P0 hosts → curated
  bounty nuclei templates.
- `recon_deep_scan.sh` (daily): tech-aware nuclei against every fresh
  host in ES with detected tech.
- `recon_active_checks.sh` (10 min): browser-headered HTTP-only safe
  confirmations for Docker API / Jenkins / k8s / Grafana / GitLab /
  Confluence on top 5 fresh P0 hosts.
- `recon_js_scanner.sh` (30 min): fetches `<script src>` from fresh
  hosts and scans for AWS / Google / private-key / JWT / connection-
  string disclosure (with a strict ignore list). Per-host dumps are
  deleted immediately after scan.

To suppress a noisy host for 7 days:

```bash
~/recon-pipeline/scripts/recon_ctl.sh ignore <host> [reason]
```

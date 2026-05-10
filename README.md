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

## Fresh paid findings
`recon_fresh_confirm.sh` runs from the daemon and only queues high-signal,
in-scope assets where the scope database says the program pays. Check it with:

```bash
~/recon_ctl.sh fresh
```

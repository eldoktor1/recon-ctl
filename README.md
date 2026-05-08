# recon-pipeline

Autonomous bug bounty recon pipeline.

## Structure
```
scripts/
  auto_recon.sh     — one recon cycle (Chaos + subfinder + httpx + ES ingest)
  triage.sh         — scoring engine → agent_targets.jsonl + Discord
  recon_daemon.sh   — forever loop, mode-aware, proxychains support
  recon_ctl.sh      — control interface (status/mode/logs/top/health/clean)
docker/
  docker-compose.yml — ES 8.17.4 + Kibana 8.17.4
```

## Quick start
```bash
~/recon_ctl.sh status
~/recon_ctl.sh mode night
~/recon_ctl.sh logs
```

## Proxy
Set `USE_PROXYCHAINS=1` in environment to route scan traffic via proxychains4.
Requires `/etc/proxychains4.conf` to contain: `localnet 127.0.0.0/255.0.0.0`

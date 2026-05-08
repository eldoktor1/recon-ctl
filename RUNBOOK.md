# Recon Pipeline — Runbook

## Architecture (one-page)

```
                             ┌──────────────┐
                             │  recon_ctl   │  ← single CLI
                             └──────┬───────┘
                                    │
                                    ▼
                             ┌──────────────┐
                             │ recon_daemon │  ← single supervisor
                             └──────┬───────┘
                                    │ supervises
       ┌────────────────────┬───────┴──────┬──────────────────┐
       ▼                    ▼              ▼                  ▼
 discovery loop      hot-seed loop   scope-watch loop    validate loop
 (chaos+subfinder)   (taps live      (arkadiyt scope     (drains queue,
       │             subfinder)      diff)               runs httpx,
       │                  │              │               ingests ES)
       └──────────────────┴──────────────┘                       │
                          │                                      │
                          ▼                                      ▼
                  queue/inbox/                          takeover_hunter (stream)
              (00_=hot, 01_=scope,                            │
               10_=normal — sorted)                           ▼
                                                      Discord URGENT
                                                              │
                                                              ▼
                                                       ~/recon/firstblood/
                                                         takeovers_to_claim.tsv
```

## Daily commands

```bash
~/recon_ctl.sh start            # launch daemon
~/recon_ctl.sh status           # health check + queue + ES + FB summary
~/recon_ctl.sh top 20           # top triage targets right now
~/recon_ctl.sh takeovers        # CLAIM file — claim THESE first
~/recon_ctl.sh watching         # MEDIUM-confidence takeovers
~/recon_ctl.sh logs 100         # tail daemon log
~/recon_ctl.sh space            # disk usage
```

## Mode toggle

```bash
~/recon_ctl.sh mode browse      # 15 threads, 15rps — polite, daytime
~/recon_ctl.sh mode night       # 120 threads, 200rps/worker — overnight
```

The daemon picks up the new mode at the start of each cycle. **No restart needed.**

If on battery, night auto-downgrades to browse (saves laptop, requires `acpi`).

## Submission workflow (the dedup story)

After you submit a finding:

```bash
~/recon_ctl.sh submit www.example.com xss accepted
~/recon_ctl.sh submit api.foo.com sqli pending
~/recon_ctl.sh submit grafana.bar.io rce duplicate   # if H1 marked it dup
```

This appends to `~/.recon_submissions.jsonl`. On the next triage cycle:
- That exact host gets `-5` score (drops out of P0/P1)
- Other hosts on that root_domain get `-2` (cluster damper)
- Discord won't re-notify on it

To inspect:

```bash
~/recon_ctl.sh dupes                  # all submissions
~/recon_ctl.sh dupes example.com      # just example.com
```

## Takeover hunter — the first-blood path

The takeover hunter is the headline feature. It runs in two modes:

1. **Streaming** — automatically called by the validator on every batch. New CNAMEs hit the fingerprint DB → 5-stage verify → URGENT Discord if HIGH/CRITICAL.

2. **Watching** — long-running daemon that re-checks WATCH file every 30 minutes (MEDIUM-confidence candidates that didn't pass all 5 stages first time but might later).

Manual single-host probe:

```bash
~/recon_takeover_hunter.sh check api.example.com
```

Look at results:

```bash
cat ~/recon/firstblood/takeovers_to_claim.tsv
cat ~/recon/firstblood/takeovers_watching.tsv
tail -50 ~/recon/firstblood/takeovers.log
```

### When you see a CRITICAL/HIGH:

1. Check the embed in Discord — claim instructions are right there
2. Verify with `dig CNAME <host>` and `curl -v https://<host>/` yourself
3. Check H1 disclosed reports for that exact provider/host
4. Move FAST — these get claimed by other hunters in minutes
5. After claiming and submitting: `recon_ctl submit <host> takeover pending`

## Troubleshooting

### Daemon won't start

```bash
~/recon_ctl.sh logs 200
# Look for: "ES unreachable" → check docker
# Look for: "ES password not set" → check ~/.recon_es_pass
```

### ES is down

```bash
docker ps | grep elasticsearch
# If not running:
cd /mnt/c/recon/recon_database && docker compose up -d
# Wait 60s, then:
curl -u elastic:$(cat ~/.recon_es_pass) http://localhost:9200/_cluster/health
```

### Queue stuck (validator falling behind discovery)

```bash
~/recon_ctl.sh queue
# inbox=200 means cap reached — discovery paused (this is correct behaviour)
# processing > 0 for >30min = something hung
~/recon_ctl.sh stop
~/recon_ctl.sh start
```

### Reset the queue completely (nuclear)

```bash
~/recon_ctl.sh stop
~/recon_ctl.sh reset-queue   # asks confirmation
~/recon_ctl.sh start
```

### Disk filling up

```bash
~/recon_ctl.sh space
~/recon_ctl.sh clean         # prunes archive, sent spool, old done/
```

### Takeover false positives

If the hunter is firing on hosts that are clearly fine:
- Check `~/recon/firstblood/takeovers.log` for the stages it passed
- Mostly LOW/MEDIUM = pattern match without HTTP confirmation = acceptable noise
- HIGH/CRITICAL false positives → that provider's fingerprint regex needs tightening; edit `recon_takeover_hunter.sh` FINGERPRINT_DB heredoc

## Files & locations

| Path | Purpose |
|---|---|
| `~/recon_*.sh`, `~/triage.sh` | Scripts |
| `~/.recon_es_pass` | ES password |
| `~/.recon_discord` | Discord webhook URL |
| `~/.recon_submissions.jsonl` | Submission history (dedup source) |
| `~/.recon_mode` | `browse` or `night` |
| `~/recon/queue/inbox/` | Pending batches (00_/01_/10_ priority) |
| `~/recon/queue/processing/` | In-flight batches |
| `~/recon/queue/done/` | Completed (httpx jsonl kept 24h) |
| `~/recon/firstblood/` | Takeover candidates + log |
| `~/recon/triage/` | Reports + agent_targets.jsonl |
| `~/recon/state/` | known_hosts, alive_hosts, locks, pids |
| `~/recon/spool/` | ES bulk retry spool |
| `~/recon/logs/` | Daemon + child logs |

## What changed from the prior build

- ❌ `recon_validation_guard.sh` — gone. Error isolation is in `recon_validate.sh` (subshell + `||`).
- ❌ `recon_httpx_watchdog.sh` — gone. Hard `timeout --kill-after=30` on every httpx invocation.
- ❌ `recon_firstblood_ctl.sh` — merged into `recon_ctl.sh` (`takeovers`, `watching`).
- ❌ Mega-file pending.txt (29M lines) — gone. Directory queue with priority prefixes.
- ❌ Night mode at 4000rps — gone. Capped at ~600-800rps total.
- ✅ Single supervisor (`recon_daemon.sh`) replaces 4 separate guards.
- ✅ Takeover hunter as a first-class component with embedded ~75-provider fingerprint DB.
- ✅ Triage writes scores back to ES so subsequent cycles skip unchanged docs.
- ✅ Submission dampening prevents duplicate vuln reporting.
- ✅ Novelty bonus (+3 if first-seen <24h, +1 if <7d) for first-blood priority.

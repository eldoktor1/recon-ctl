# recon-pipeline

Autonomous bug-bounty recon pipeline with a **Claude-driven accuracy layer**. It
discovers assets, scores them deterministically, lets Claude decide what's worth
testing, gathers **safe non-destructive evidence**, has Claude adversarially verify
every confirmed finding, and hands you a vetted, in-scope, human-decidable queue —
**it never submits anything itself**.

> Detection ≠ exploitation. Pattern-match = LEAD; an observed safe primitive = CONFIRMED;
> and only Claude-verified `real` findings reach you. See `CLAUDE.md` for the full doctrine.

## Architecture (v3.2)
```
DETECTION (cast a wide net)        →  triage (deterministic score; detection-only P0 → P0-CANDIDATE)
 discovery · validate · scope · true-fresh · cve-kev/nvd · vuln-feed ·
 js-scanner · params(4-wide) · portscan · bypass · takeover · cloudrecon
        │
CLAUDE ANALYZE (Haiku)             →  reads in-scope+paying assets, decides worth / vuln-class,
        │                             flags evidence-gate candidates (conscious surface selection)
CONFIRM (SAFE, unauth, non-destructive)
   evidence-gate (nuclei): version · unauth-surface · content-leak · graphql · swagger ;
                           SSRF/XXE via interactsh OOB
   xss-confirm:   headless-Chromium marker EXECUTION
   param-confirm: SSTI ({{a*b}}→prod) · open-redirect (→canary) · SQLi (error-diff)
   takeover/bypass/portscan: their own multi-stage primitives
        │  every confirmation → SQLite findings.db
CLAUDE VERIFY (Sonnet → Opus on hard calls)  →  adversarial FP filter: real / fp / needs-human
        │                                        fp → dismissed + signature learned
REPORTER (real only; dup + freshness gates; NEVER auto-submits) → review queue + #review
```
IDOR / LFI / RCE stay **operator-leads** (hard line — never auto-exploited). Claude runs on the
**Max plan, headless (`claude -p`), no API key**. Two layers: ANALYZE aims the net, VERIFY kills FPs.
Deep detail: `v3/README.md`. Daily audit: `python3 v3/observability.py`.

## Security model (non-negotiable)
- **Mullvad is sole egress, fail-closed.** Startup runs a root preflight + VPN gate; the
  `vpnguard` loop pauses every target-facing loop the instant egress isn't a Mullvad exit.
- **Scope-gated.** Only `in_scope && pays && !out_of_scope`, re-checked live at probe time.
- **Recon, not attack.** Confirm an exposure exists; never exploit past it. Never touch
  fund-moving/state-changing endpoints. No autonomous authenticated requests.
- **Human-gated submission.** Claude prepares; you APPROVE/DISMISS/INVESTIGATE in `#review`.

## Layout
```
scripts/    detection, confirm, Claude agents, control (recon_ctl.sh), net/safety
v3/         detection→validation→report layer (state.py, reporter.py, orchestrator.py,
            observability.py, tier.py, db/schema.sql)  ·  SQLite findings.db = finding-state truth
tools/      Playwright workers (screenshot, xss_confirm), param_confirm worker, startup
agent/      operator brief for "Claude as second man" in the terminal
docker/     Elasticsearch 8.17.4 + Kibana (localhost-only)
docs/       supporting notes  ·  CLAUDE.md = doctrine  ·  CHANGELOG.md = history
```
- **ES** is local at `http://127.0.0.1:9200`; index `recon_alive` (alias → clean `recon_alive_v3`),
  param catalog `recon_params`. Auth via `~/.recon_es_netrc`.

## Restore from this backup (clone → running)
This repo is **code only** — no secrets, no data (both live outside it). To rebuild on a fresh box:
```bash
git clone <this-repo> ~/recon-pipeline && cd ~/recon-pipeline
# 1. Elasticsearch
cp docker/.env.example docker/.env && $EDITOR docker/.env        # set ELASTIC/KIBANA passwords
recon-es-start                                                   # (alias) or docker compose up -d
bash scripts/recon_es_bootstrap.sh                              # create index + mappings
# 2. Secrets (NONE are in the repo — recreate them)
#    ~/.recon_es_netrc            ES creds (machine 127.0.0.1 login elastic password <pw>)
#    ~/recon/state/discord/{review,takeovers,ops,digest}   Discord webhook URLs (one per file)
#    ~/.recon_discord_bot / _allowed_uid / _channel_id     (optional inbound bot)
#    ~/.claude/.credentials.json  Claude Code auth (run: claude   then /login, on the box)
# 3. Tooling: nuclei, httpx, katana, gau, subfinder on PATH; Playwright venv for screenshots/xss:
#    recon-ctl screenshot install
# 4. Go live
recon-maintenance off        # clear the rebuild lock
recon-start                  # runs preflight + VPN gate, then the daemon
```
Re-seeding ES asset data is done by the discovery/validate loops over time (or restore an ES snapshot).

## Daily driver
```bash
recon-status                 # daemon, loops, ES, VPN, queue
recon-logs                   # live stream  ·  recon-logs | grep --line-buffered '🧠\|💥'  (Claude + confirms)
recon-ai status              # Claude verdict breakdown (real / needs-human / fp / pending)
recon-ai real | analysis     # reportable findings  ·  Claude analysis leads
recon-fresh | recon-top      # true-fresh queue  ·  top triage targets
recon-maintenance on [why]   # rebuild lock (fail-closed: blocks start until `off`)
```

## Models (match-to-task, all on Max, no API)
Haiku = bulk analysis · Sonnet = verification · Opus = ambiguous `needs-human` escalation.
Override via `CLAUDE_ANALYZE_MODEL` / `CLAUDE_MODEL` / `CLAUDE_ESCALATE_MODEL`.

See **`CHANGELOG.md`** for version history (current: v3.2.0) and **`CLAUDE.md`** for the operating doctrine.

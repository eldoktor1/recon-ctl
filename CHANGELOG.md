# Changelog — Autonomous Bug Bounty Recon Pipeline

## v2.1.6-killswitch final hardening notes

### Added
- Hidden Windows `ReconWatchdog` startup through `wscript.exe C:\recon\start_recon_hidden.vbs`.
- Noninteractive safe startup through `tools/start_recon_safe.sh`.
- Root-owned preflight script `/usr/local/sbin/recon-safe-preflight`.
- Narrow sudoers rule allowing only the root-owned preflight script without a password.
- Final sanity documentation for IP leak prevention and startup safety.

### Changed
- Windows startup now uses the safe preflight path instead of calling `recon_daemon.sh` directly.
- Target-facing scanner paths run under the locked `reconrun` user.

### Verified
- Windows `ReconWatchdog` returns `Last Result: 0`.
- Task runs hidden through `wscript.exe`.
- `reconrun` direct outbound traffic is blocked.
- Tor SOCKS on `127.0.0.1:9050` works.
- Local Elasticsearch on `127.0.0.1:9200` works.
- No scanner-heavy processes are owned by `d0k`.
- Discord `!mode`, CLI mode, and scheduler all use `~/.recon_mode`.

### Operational Rule
Use the hidden Windows task or `recon-start`. Do not start target-facing recon with plain `~/recon_ctl.sh start` unless the kill switch has already been verified.


## v2.1.6-killswitch - 2026-05-07

### Fixed
- Added `run_scanner` daemon path to launch target-facing scanner tasks under locked user `reconrun`.
- Hardened scanner execution against IP exposure using an nftables kill switch.
- Added native SOCKS proxy flags for httpx, subfinder, and nuclei.
- Skipped assetfinder in proxy-safe mode because it lacks a trusted native proxy flag.

### Verified
- Direct outbound traffic from `reconrun` is blocked.
- Tor SOCKS via `127.0.0.1:9050` works.
- Local Elasticsearch via `127.0.0.1:9200` works.
- No scanner processes are owned by `d0k`.
- httpx and subfinder run under `reconrun`.
- nuclei daemon path uses `run_scanner` when triggered.

### Notes
- nftables rules may need to be restored after WSL restart.
- The kill switch, not proxychains alone, is the fail-closed control.


## v2.1.6-proxy-safe - 2026-05-07

### Fixed
- Enforced proxychains wrapping for target-facing recon tools when USE_PROXYCHAINS=1.
- Added fail-closed proxy checks for proxychains4 and Tor SOCKS listener on 127.0.0.1:9050.
- Wrapped httpx, subfinder, assetfinder, nuclei, and external scope/feed fetches through the network wrapper.

### Verified
- Direct and proxychains outbound IPs differed.
- Live httpx, subfinder, and nuclei child processes showed LD_PRELOAD with libproxychains mapped.

### Notes
- Parent shell processes may not show libproxychains; verify the actual scanner child processes.


## v2.1.5-recovered - 2026-05-07

### Fixed
- Restored missing runtime scripts after repo migration:
  - recon_discord_bot.sh
  - recon_discovery.sh
  - recon_validate.sh
  - recon_hot_seed.sh
  - recon_scope_watch.sh
  - recon_takeover_hunter.sh
- Restored functional supervisor daemon wiring.
- Restored Discord bot command handling for health, queue, status, logs, mode, and control commands.
- Restored live recon loops for validation, discovery, hot-seed, scope-watch, takeover-watch, CVE, nuclei, and schedule tasks.
- Recreated home-directory compatibility symlinks for scripts still expecting ~/recon_*.sh paths.

### Verified
- Bash syntax checks passed for restored scripts.
- Daemon started successfully.
- Discord bot responded to !help, !queue, !status, and !health.
- Elasticsearch health returned green.
- Repo tagged as v2.1.5-recovered.

### Notes
- Root cause was an incomplete repo migration where newer helper scripts were present, but required runtime scripts and Discord bot wiring were missing.
- Do not remove compatibility symlinks yet because some scripts still call the old flat ~/recon_*.sh paths.


---

## [v2.1.4] — Schedule-based mode switching + stop fix

**Scripts changed:**
- `recon_daemon.sh` — patched: schedule sub-loop added
- `recon_ctl.sh` — patched: stop pkill fixed + schedule commands added
- `recon_scope_db.sh` — patched: cosmetic stderr warnings suppressed
- `recon_schedule.sh` — **NEW**

**Changes:**
1. `recon_schedule.sh` — time-based automatic mode switcher integrated as daemon sub-loop
   - Weekdays 5:30pm–11:30pm PT → browse mode (low rate, won't impact browsing)
   - All other times → night mode (aggressive)
   - Weekends: manual mode preserved, no auto-switching
   - Runs as supervised sub-loop inside daemon, checks every 5 minutes
2. Stop command (`recon_ctl.sh stop`) — pkill pattern extended to include `discord_bot` and `nuclei` processes that were being left as orphans
3. `recon_scope_db.sh` — Intigriti/YesWeHack/Federacy normalizer stderr warnings suppressed (data was correct, warnings were cosmetic)
4. NVD health-check command added to `recon_ctl.sh`
5. `recon_ctl.sh` new commands: `schedule`, `schedule-check`, `schedule-status`

---

## [v2.1.3] — Hard exclusions + inspect helper

**Scripts changed:**
- `recon_scope_check.sh` — patched: `.mil` hard exclusion
- `recon_ctl.sh` — patched: `inspect` command added
- `recon_inspect.sh` — **NEW**

**Changes:**
1. `.mil` hard exclusion in `recon_scope_check.sh`
   - Hosts matching `.mil`, `.smil.mil`, `.nipr.mil`, `.sipr.mil` return `in_scope=false, hard_excluded=true`
   - Hard exclusion overrides any matching scope DB pattern
   - Protection against accidental DoD/classified network scanning
2. `recon_inspect.sh` — single-host manual triage helper
   - Full ES record: status, title, tech, IP, CNAME, CDN
   - Scope verdict: in scope / paying / VDP / out-of-scope / hard-excluded
   - KEV match details: which signal, which CVEs, max CVSS score
   - Live HTTP probe: current status code, redirect chain
   - Tech-specific suggested manual probes (Jenkins → `/script`, Confluence → CVE-2023-22527 paths, etc.)
   - Probe suggestions suppressed for hard-excluded hosts
3. `recon_ctl.sh` extended with `inspect <host>` command

---

## [v2.1.2] — Scope check performance + nuclei tier filter

**Scripts changed:**
- `recon_scope_check.sh` — full rewrite
- `recon_nuclei.sh` — patched: batch scope check + tier filter

**Changes:**
1. `recon_scope_check.sh` full rewrite — in-memory awk, single-pass batch mode
   - Was: O(n × forks), timing out at 200 hosts
   - Now: ~270,000 hosts/sec, entire kev_targets list processed in one call
   - Bug fix: out-of-scope now correctly overrides in-scope (host matching both `*.example.com` in-scope and `*.beta.example.com` out-of-scope was incorrectly marked in-scope)
2. `recon_nuclei.sh` — target build rewritten to use batch scope check (eliminated O(n) per-host fork loop)
3. `NUCLEI_TIER` env var added to `recon_nuclei.sh`
   - `high-value` (default): scans only proven KEV-vulnerable tech (moveit, confluence, jenkins, magento, exchange, fortinet, citrix, ivanti, vmware, weblogic, manageengine, gitlab, solr, zabbix, kibana, jira, nexus, phpmyadmin, argocd, rancher, portainer, thinkphp, coldfusion, airflow, joomla)
   - `all`: scans every signal in kev_targets including WP/Drupal/Spring/Tomcat noise
   - `kev_targets.jsonl` itself unchanged — tier filter only affects what nuclei fires on

---

## [v2.1.1] — Platform normalizer fixes + KEV match fix

**Scripts changed:**
- `recon_scope_db.sh` — replaced
- `recon_cve_intel.sh` — replaced

**Changes:**
1. Platform normalizers fixed — Intigriti, YesWeHack, Federacy now produce programs (was 0)
   - Intigriti: correct fields `targets.in_scope[].endpoint`, `max_bounty.value`
   - YesWeHack: correct fields `targets.in_scope[].target` with type filter, `max_bounty` as number
   - Federacy: correct fields `targets.in_scope[].target`, `offers_awards`
2. KEV → ES match fixed — critical bug: was returning 0 hosts
   - Root cause: ES stores tech as `"Jenkins"` (capitalized), wildcard query was case-sensitive on keyword field
   - Fix: ES `case_insensitive: true` flag (supported ES 7.10+, running 8.17)
   - Result: from 0 KEV-matched hosts to dozens/hundreds depending on ES contents
3. NVD curl `200000` bug fixed
   - `-w '%{http_code}'` was returning concatenated HTTP codes when curl reused connections
   - Fix: isolate final code via `tail -n1 | tr -dc '0-9' | head -c 3`
4. `kev_targets.jsonl` dedup — multiple `SIG_TO_TECH` terms matching same host now deduped by host

---

## [v2.1.0] — V2 integrated build (scope DB + CVE intel + nuclei)

**Scripts added (NEW):**
- `recon_scope_db.sh` — arkadiyt BB scope feed → `programs.json` pattern tables
- `recon_scope_check.sh` — per-host scope lookup against programs.json
- `recon_cve_intel.sh` — KEV catalog + NVD recent CVEs + tech match → `kev_targets.jsonl`
- `recon_nuclei.sh` — KEV-only, scope-gated nuclei scanning (6h cycle)
- `recon_killswitch.sh` — per-module enable/disable helper

**Scripts patched:**
- `recon_daemon.sh` — V2.1 sub-loops added (scope-db, cve-kev, cve-nvd, nuclei-v21)
- `recon_ctl.sh` — V2 commands added (kev, scope, programs, confirmed, fp, v2)
- `triage.sh` — V2 hook removed (cleaned from v2.0)

**Architecture — one daemon, one PID:**
```
recon_daemon.sh (master)
├── validate-loop      queue → httpx → ES → triage
├── discovery-loop     chaos + subfinder + assetfinder
├── hot-seed-loop      live subfinder
├── scope-watch-loop   new program detection
├── takeover-watch     takeover hunter
├── discord-bot        outbound-poll remote control
├── scope-db           arkadiyt scope DB (24h refresh)
├── cve-kev            KEV catalog + match (1h)
├── cve-nvd            NVD recent (24h)
└── nuclei-v21         KEV-only, scope-gated nuclei (6h)
```

**New data directories:**
- `~/recon/scope/` — `programs.json`, pattern tables (~3000 BB programs)
- `~/recon/cve/` — `kev.json`, `nvd_recent.json`, `tech_cve_map.json`, `kev_targets.jsonl`
- `~/recon/nuclei/` — results, `confirmed.jsonl`, `fp/` (false positives)
- `~/recon/state/kill/` — per-module killswitches

**New `recon_ctl.sh` commands:**
```
kev                    KEV-matched targets in ES
scope <host>           Scope check single host
programs               Programs by platform + paying count
confirmed              Latest nuclei-confirmed findings
fp <host> <template>   Mark false positive
v2 status              Killswitches + data ages
v2 enable <module>     Re-enable killed module
v2 disable <module>    Disable module with reason
v2 refresh-scope       One-shot scope DB refresh
v2 refresh-cve         One-shot KEV+NVD+map+match
v2 scan-now            One-shot nuclei pass
```

**Auto-disable triggers:**
| Condition | Action |
|---|---|
| 3 consecutive failures (supervise_loop) | Disable the failing module |
| RAM > 90% | Skip nuclei (not killed) |
| Disk free < 5GB | Skip nuclei (not killed) |
| > 10 nuclei confirms in 1 run | Disable nuclei in-script |
| `recon_ctl v2 disable <mod>` | Disable that module |

**Issues fixed from v2.0:**
- Separate V2 daemon removed — folded into V1 daemon as sub-loops
- `jq: Argument list too long` building tech_cve_map — now pure Python, file-based
- NVD page 0 failure — retry with exponential backoff, longer initial delay, 30-page cap
- Intigriti normalized to 0 programs — schema-tolerant jq filters
- HackEnProof 404 — removed (no longer in arkadiyt feed)
- `recon_ctl stop` left orphans — pkill pattern extended to catch all V1+V2 modules

---

## [v1.0] — Core pipeline baseline

**Scripts:**
- `auto_recon.sh` — one recon cycle: Chaos + subfinder + assetfinder → httpx → ES ingest
- `triage.sh` — 2-phase scoring engine → `agent_targets.jsonl` → Discord P0/P1 alerts
- `recon_daemon.sh` — forever loop, mode-aware, owns PID, auto-cleanup each cycle
- `recon_ctl.sh` — control interface: status/mode/logs/top/health/clean/space

**Infrastructure:**
- Elasticsearch 8.17.4 + Kibana 8.17.4 on Docker Desktop (Windows)
- Index: `recon_alive` — 2.4M+ docs
- Auth: `xpack.security.enabled=true`, credentials in `~/.recon_es_pass`
- Discord webhook alerts: `~/.recon_discord`
- Windows Task Scheduler: `ReconElastic` (Docker), `ReconWatchdog` (daemon)

**Discovery sources:**
- ProjectDiscovery Chaos — ~2300 BB programs, incremental refresh
- subfinder — passive, all sources, 2363 root domains
- assetfinder — passive, per root domain
- Delta-based: only scans hosts not in `known_hosts.txt`

**httpx fingerprinting fields:**
`tech`, `status_code`, `title`, `webserver`, `ip`, `cname`, `cdn_name`, `cdn_type`, `favicon_hash`, `final_url`, `content_length`, `content_type`

**Mode profiles:**
| Setting | Browse | Night |
|---|---|---|
| Jobs | 1 | 2 |
| Threads | 15 | 80 |
| Rate (rps) | 15 | 100 |
| Input cap | 20,000 | 150,000 |
| Cycle sleep | 60 min | 30 min |

**Triage scoring — Phase 1 (74 signal rules):**
- `confirmed` strength: 46 tech rules (Jenkins=9, Confluence=9, GitLab=8, Grafana=8, Spring Actuator=7, K8s=9, MOVEit=9, ManageEngine=9, etc.)
- `status` strength: 403=+3, 401=+2, 500=+2
- `port` strength: Docker API=+9, Redis=+7, MongoDB=+7, ES=+5
- `pattern` strength: hostname patterns +2 to +5
- Negative signals: mail=−3, redirect-no-tech=−2, default-page=−2, CDN-no-tech=−1
- Diversity gate: pattern-only hosts capped below P1 threshold

**Triage scoring — Phase 2 (cluster dedup):**
- Group by root_domain + signal fingerprint
- Hosts 4+ in same cluster: −3 penalty (kills load balancer farms)

**Priority thresholds:** P0≥15, P1≥8, P2≥4, P3 filtered

**Output:** `~/recon/triage/agent_targets.jsonl`, `~/recon/triage/report_<ts>.md`

---

## [repo] — Git repository migration

**Changes:**
- All scripts moved from `~/` flat layout into `~/recon-pipeline/` git repository
- Structure: `scripts/`, `docker/`, `CHANGELOG.md`, `RUNBOOK.md`, `.gitignore`, `README.md`
- `ReconWatchdog` Task Scheduler updated to launch from repo: `~/recon-pipeline/scripts/recon_daemon.sh`
- `.gitignore` covers: secrets (`~/.recon_es_pass`, `~/.recon_discord`), runtime state, lock/pid/epoch files, `*:Zone.Identifier` files
- Proxychains support added to `recon_daemon.sh`:
  - `USE_PROXYCHAINS=1` env var routes all external scan traffic through proxychains4
  - ES/localhost traffic bypassed via `localnet 127.0.0.0/255.0.0.0` in proxychains4.conf
  - `run_auto_recon()` wrapper handles conditional invocation
  - Graceful fallback if proxychains4 binary not found
- Repo-relative paths in `recon_daemon.sh`: `SCRIPT_DIR`/`REPO_ROOT` derived at runtime, `AUTO_RECON` and `TRIAGE_SCRIPT` resolve from `$REPO_ROOT/scripts/`
- `recon_ctl.sh` `DAEMON` path updated to repo location
- Home directory cleaned: version archives, `.bak`/`.v*` backups, Zone.Identifier files, superseded scripts all removed
- `~/recon/queue/backups/` purged (459MB of old processed batch backups)

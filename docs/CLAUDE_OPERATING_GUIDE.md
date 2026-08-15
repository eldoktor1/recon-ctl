# CLAUDE_OPERATING_GUIDE — how the assistant works this pipeline without friction

This is the assistant's own operating manual for the recon-ctl. It exists so a session
never has to re-derive how to invoke things, what's safe to run, what's currently running, or
which shell gotchas waste time. Keep it current; it is the single source of truth for *mechanics*
(CLAUDE.md remains the source of truth for *doctrine/strategy*).

Last verified: 2026-07-11.

---

## 0. TL;DR — the three things that remove all friction

1. **Run any pipeline feature via** `recon <sub> [args]` — a wrapper at `~/.cargo/bin/recon` (on the
   login-shell PATH) that `exec`s `bash /home/d0k/recon-ctl/scripts/recon_ctl.sh "$@"`. The
   `recon-<x>` aliases are **zsh-interactive-only** (defined in `~/.recon_aliases`) and 404 in the
   non-interactive `bash -lc` the Bash tool uses. Fallback that always works: `bash
   /home/d0k/recon-ctl/scripts/recon_ctl.sh <sub>`.
2. **For any non-trivial shell, write a script file, don't inline it.** The `wsl.exe … bash -lc '…'`
   double-hop eats `$@`, mangles quotes, converts `/tmp`→`C:\…`, and the script's global
   `IFS=$'\n\t'` breaks space-splitting. Reliable recipe:
   - `Write` the script to `\\wsl.localhost\kali-linux\tmp\x.sh` (exact bytes, no hop).
   - Run it: `MSYS_NO_PATHCONV=1 wsl.exe -d kali-linux -- bash /tmp/x.sh`.
3. **Check system health with the built-ins first:** `recon status`, `recon health`, `recon-audit`,
   and the one-shot diagnostic in §2 below. Don't hand-roll probes when these exist.

---

## 1. Invocation cheatsheet

| Need | Command |
|---|---|
| Any feature | `recon <sub> [args]` (wrapper) or `bash …/recon_ctl.sh <sub>` (raw) |
| Full alias→sub map | `zsh -ic 'alias \| grep recon_ctl'` (aliases live in `~/.recon_aliases`) |
| Python | ALWAYS `wsl.exe -d kali-linux -- python3 …` — never Windows `python` (PyManager shim opens a browser) |
| ES query | `curl --netrc-file ~/.recon_es_netrc http://127.0.0.1:9200/recon_alive/_search …` (pass rotated; old `-u elastic:$(cat)` 401s) |
| Notes lib direct | `source …/recon_notes.sh && note_add <host> <note> [source]` (prefer `recon note`) |

ES lives on **Windows Docker** at `127.0.0.1:9200` (index `recon_alive`), not WSL. `recon scope` works
offline; raw ES queries need the kali→localhost hop up.

---

## 2. Health-at-a-glance — one read-only diagnostic

`recon status` + `recon health` cover most of it. For a full "is everything alive" sweep, the signals are:

- **Daemon:** `pgrep -af recon_daemon.sh` (expect ~55–60 procs: main + supervised lane loops);
  `systemctl is-active recon-daemon.service`; PID at `state/recon_daemon.pid`.
- **VPN gate:** `state/vpn_down` present ⇒ all scanning paused (fail-closed). Absent ⇒ egress ok.
- **Killswitches:** `ls state/kill/` — any `v2_<lane>` file disables that lane. Empty ⇒ all enabled.
- **Lane liveness:** each lane drops a `state/<lane>.lock` and logs to `logs/`; compare mtime to cadence (§4).
- **Notifications:** finding alerts go via **webhooks** (`discord_hook`/`discord_post`, channels
  `#takeovers #review #ops #digest`) — NOT the `recon_discord_bot.sh` remote-control bot (that bot has
  been dead since 2026-06-07; it only lets the operator send commands to the pipeline, so its death does
  not affect alerts).
- **Self-audit:** `recon-audit` (dry) → `docs/audit_<date>.md` + `state/selfaudit_latest.json`.

---

## 3. Command surface (recon_ctl.sh) — safety-classed

**Legend:** **R** read-only/safe (query ES/SQLite/state — run freely). **N** non-target egress (public
resolvers / 3rd-party APIs / web research — runs as d0k, safe). **T** target-facing traffic
(probes/crawls/confirms/screenshots — operator-gated, reconrun+Mullvad). **C** control/mutating local state.

⚠️ **Bare lane subcommands DEFAULT to their scan and send target traffic:** `recon-buckets`,
`recon-graphql`, `recon-wcd` → `scan` (T); `recon-uncover` → `cycle`; `recon-hunter`/`recon-blindxss`/
`recon-bulk`/`recon-vuln`/`recon-ai`/`recon-v2` → `status` (R). Know the default before running bare.

### Querying / ES viewers (all R — free to run)
`recon status`·`health`·`queue`·`logs`·`space` · `top [N]` · `fetch [-p PRI -t tech -c class -P prog
--kev --js --fresh --pays --ignored --takeover --hosts -o f] [N]` · `kev` · `js` · `ignored` ·
`confirmed` · `ports` · `exposed` · `bypass` · `programs` · `scope <host>` · `dupes [pat]` ·
`inspect <host>` · `view`/`dashboard` · `mood <kw> [--top N --list]` · `targets` · `fresh [--new
--save --all N]` · `tech <name[,name2]> [--apex --pays N]` · `ai [status\|real\|human\|pending\|fp\|top
N\|accuracy\|detail <host>]` · `takeovers` · `watching` · `takeover-dedup` · `screenshots` · `gallery` ·
`leads` · `bulk [status]` · `vuln [status\|top]` · `note <host>` (no text = read).

### Hunting lanes
| Cmd | Class | Note |
|---|---|---|
| `buckets [scan\|check <b>\|writecheck <b>\|results\|seed]` | T | S3Scanner read-only; default scan |
| `graphql [scan\|check <url>\|results]` | T | introspection→schema; default scan |
| `wcd [scan\|confirm <host>\|purge\|results]` | T | cache-decep, cache-busted; default scan |
| `blindxss [status\|test <host>\|collector\|correlate\|plant]` | mixed | status/test/collector safe; correlate=mint; plant=T |
| `kr`/`kiterunner` | T | API-route brute on bare-API hosts |
| `permute` | N | permutation-DNS via public resolvers (not target) |
| `uncover [cycle\|query "<dork>" [engine]]` | N | Shodan/Censys dorks, budget-capped |
| `hunter [status\|…]` | T(safe-probe) | Claude IDOR/BAC hunter; GET/HEAD/OPTIONS only |
| `domxss <host>` | T | DOM-XSS source→sink miner |
| `research [vulns\|tooling\|kb-enrich\|detect-tune\|all]` | N | Claude web-research |
| `verify <list\|#\|host>` | T(safe-probe) | Claude-verify a digest lead |
| `takeover-check <host>` | T | manual single-host takeover probe |
| `portscan` · `bypass-now` · `screenshot[-backfill\|-test\|-install]` | T/C | trigger cycles |
| `bulk run [--all --dry-run --threads N --batch N]` | T | subfinder all paying wildcards |

### Params / vuln confirm (`recon params …`)
`params [list]` (R) · `params <class> [N]` (R; class aliases sqli/xss/ssrf/lfi/ssti/rce/cmdi/redirect/idor)
· `params candidates [--class xss\|sqli\|both]` (R) · `enqueue` (C) · `crawl` (T) · `crawl-host <host>
[url] [--cookie/--header]` (T) · `arjun <host>` (T) · `collect` (T) · `confirm <xss\|sqli> [host] [N]
[--cookie/--header]` (T; xss=dalfox-execute, sqli=`'`vs`''`).

### Notes / scope / submit (C — mutating)
`submit <host> <class> [status]` · `ignore <host> [reason]` (7-day + note + ES mirror) ·
`note <host> "text"` (add) · `fp <host> <template_id>` · `outcome <finding_id> <accepted\|dup\|na\|info>
[bounty]`.

### Daemon / maintenance (C)
`start`·`stop`·`restart`·`status`·`maintenance {on [reason]\|off\|status}`·`rate [light\|easy\|medium\|
full\|reset\|<threads> <rps>]`·`clean`·`clean-start [--yes]`·`reset-queue`·`revalidate`·`v2 <status\|
enable/disable <mod>\|refresh-scope\|scan-now>`·`account create …`·`leads-post`·`digest-now`.

---

## 4. Daemon lane map (~55 supervised loops)

Supervisor: `recon_daemon.sh` runs one `supervise_loop <name> <INTERVAL_VAR> <run_fn> &` per lane
(stagger + exponential backoff). Every loop except `vpnguard` pauses while `state/vpn_down` exists.
Killswitch: `touch state/kill/v2_<name>`. Gating: **scanner** = reconrun+Mullvad; **d0k+gate** = d0k but
pauses on vpn_down; **d0k always** = runs even VPN-down (blindxss collector, to catch late OOB fires).

High-frequency (cycling every 1–10 min): `vpnguard`(20s) · `validate`/`validate-fast`(120s) ·
`true-fresh`(120s) · `params`/`params-live`(120–300s) · `params-enqueue`(300s) · `hot-seed`(300s) ·
`blindxss-correlate`(300s).

Hourly-ish: `ai-analyze`(haiku triage 3600s) · `ai-vision`(3600) · `xss-confirm`/`param-confirm`(3600) ·
`jsintel`(3600) · `vuln-feed`(3600) · `cve-kev`(3600) · `unauth-expose`(3600) · `exposed-files`(3600) ·
`bypass`(3600) · `briefing`(3600) · `reporter`(1800) · `evidence-gate`(1800) · **`ai-hunter`(1800,
killswitch `v2_ai_hunter`)** · `discovery`(1800) · `js-scanner`(1800).

Multi-hour → daily: `nday`(2h) · `ssrf-oob`(2h) · `domxss-confirm`(2h) · `kr`(2h) · `screenshot`(2h) ·
`ghleaks`(3h) · `graphql`(3h) · `blindxss-plant`(3h) · `buckets`(4h) · `baddns`(4h) · `cloudrecon`(1h) ·
`wcd`(6h) · `dangling-dns`(6h) · `uncover`(6h) · `self-audit`(6h) · `restale`(8h) · `portscan`(90m) ·
`scope-watch`(90m) · `scope-db`/`cve-nvd`/`targets`/`research-vulns`/`v3-digest`(daily) ·
`research-{tooling,kb,detect}`/`nuclei-update`(weekly).

3 non-supervise long-lived loops: `takeover-watch` (5-min retry; PID `state/takeover_hunter.pid`) ·
`discord-bot` (60s; **currently dead — poll HTTP=000000 since 06-07**) · `blindxss-collector` (persistent
interactsh, not vpn-gated).

**Offensive engine vs curator:** `ai-hunter` (`recon_ai_hunter.sh cycle`) is the finding engine — Opus
reasons over one in-scope+pays target's jsintel endpoint surface → ranked BAC/IDOR/SSRF hypotheses →
`recon_safe_probe.sh` (GET/HEAD/OPTIONS) → adjudicates → mints CONFIRMED (rare, → verify gate → #review)
or writes a 2-account operator plan to `briefings/hunter_<date>.md`. It rarely auto-confirms because its
money classes (IDOR/BFLA) require 2 owned accounts by design; its output is worklists, not finished bugs.
The **2IC nightly routine** consumes that output for the tonight card + does the burn/verdict/VPN monitor.

---

## 5. Gotchas that waste time (each cost real minutes this session)

- **jq `//` swallows boolean `false`:** `jq -r '.x // empty'` returns "" when `.x` is `false` — so
  `in_scope:false` / `nameAvailable:false` parse as absent and you make the wrong call. Read the raw
  value: `jq -r '.x'` (prints `true`/`false`/`null`) and branch explicitly.
- **Global `IFS=$'\n\t'`** (in `recon_takeover_hunter.sh` and others) breaks `for x in $space_list` — it
  won't split on spaces. Force `local IFS=$' \n\t'` in any helper that iterates a space-separated list.
- **WSL double-hop** eats `$@`/loop vars, mangles nested quotes, and MSYS converts `/tmp`→`C:\…`. Fix:
  Write the script to a `\\wsl.localhost\…` UNC path; run with `MSYS_NO_PATHCONV=1 wsl.exe … bash /tmp/x.sh`.
- **`az` cold-token:** the first `az` call in a fresh process can be slow; use `timeout 30` and a fallback
  (`az account list --query '[?isDefault].id|[0]'`). Warm, it's instant. `az` is authed as the operator.
- **known_hosts / large ledgers have NUL bytes** → `grep` silently matches nothing without `-g`/`-a`.
- **Discord: bot ≠ webhook.** Alerts = webhooks (healthy). The remote-control bot is a separate,
  currently-dead convenience feature.

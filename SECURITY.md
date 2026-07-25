# Security & responsible use

This document covers two things: the **operational-security model** of running this pipeline (it is
offensive tooling — the way you deploy it *is* the security), and how to **report a vulnerability in
this tool**.

## Trust boundary — read this first

**The web control plane's entire perimeter is: a loopback bind + a token.** There is no second wall.

- The UI binds `127.0.0.1:8787` only. The in-UI Claude co-pilot runs with
  `--permission-mode bypassPermissions` and no `--allowedTools` restriction — meaning **an
  authenticated UI user has full RCE by design** (Bash + Burp/Brave MCP), running as the operator
  user, able to `sudo` to the scanner user. That is intentional (it's the operator's co-pilot).
- Consequently the **UI token (`~/recon/state/ui_token`) is effectively a root password.** Treat it
  like one: never paste it anywhere but the local SPA; if a browser profile holding it is ever
  synced or shared, delete the token file and restart to rotate it.

If you expose that port to a network, or leak that token, you have handed someone a shell. Don't.

## Egress model — VPN, fail-closed

Target-facing scanning runs only when **Mullvad is the sole egress** and there is no
`~/recon/state/vpn_down` flag. The VPN guard pauses every target-facing loop the instant egress
isn't a Mullvad exit. A small set of **sanctioned non-target** egress paths (archive-CDX proxy,
Claude web-research, Discord notifier, the UI co-pilot) run off that gate by design — they never
touch bug-bounty targets. Never edit nftables/iptables/VPN config to work around the gate.

## Secrets

- **No secrets live in the git tree or history** — all credentials live in `~/.recon_*` and
  `~/recon/state/` (gitignored). Keep it that way: never commit tokens, webhooks, API keys, `.env`,
  `.mcp.json`, or `~/recon` runtime state.
- **`chmod 600` every secret file.** Several API-token files ship world-readable (0644) inside WSL —
  fix them: `chmod 600 ~/.recon_github_token ~/.recon_shodan_key ~/.recon_securitytrails_key
  ~/.recon_blindxss.conf ~/.recon_submissions.jsonl`.
- Rotate the ES password and the UI token on principle before/after making a deployment public.

## Hardening checklist

- [ ] **UI bound to loopback** (`RECON_UI_HOST=127.0.0.1`) and never overridden to a routable host.
- [ ] **UI token treated as a root password** — chmod 600, never shared, rotated on any exposure.
- [ ] **`chmod 600` all `~/.recon_*` secret files** (several default to 0644 — see above).
- [ ] **Re-pin ES/Kibana to `127.0.0.1`** in the running containers (they can drift to a `0.0.0.0`
      publish; re-create from `docker/docker-compose.yml` so the bind — not just a firewall rule —
      is loopback).
- [ ] **Keep WSL in `nat` networking mode.** A `mirrored`-mode relapse turns "safe because localhost"
      binds into LAN exposure; if you must use mirrored, re-audit 8787/9200/5601 and add explicit
      firewall denies from non-loopback.
- [ ] **Isolate the recon Brave profile** — it runs with `--acceptInsecureCerts`; never sign into
      anything sensitive in it.
- [ ] **Confirm only the operator user can write the hunt job spool** (`~/recon/state/ui_hunt/queue/`)
      — a file dropped there executes as the operator, bypassing the token.
- [ ] **Mullvad up + fail-closed** before any target-facing run.

## Responsible use

Use this pipeline **only against assets you are explicitly authorized to test** — bug-bounty
programs whose scope and rules of engagement permit it, or systems you own. Confirm an exposure
exists; never exploit past it. IDOR/BAC/RCE testing is human-gated and uses only accounts and IDs
you own. Unauthorized access to computer systems is a crime in most jurisdictions, and you are solely
responsible for staying within the law and within program scope.

## Reporting a vulnerability in this tool

Found a security issue in **this software** (not in a target you scanned with it)?

- **Do not** open a public issue for anything exploitable.
- Report it privately to the maintainer (see the repository owner's contact / GitHub security
  advisories for this repo). Include a description, affected files/versions, and a minimal repro.
- Please give a reasonable disclosure window before any public write-up.

Because the deliberate design has an authenticated UI == RCE, reports about "the co-pilot can run
commands" are **known and by design** — the meaningful reports are about *breaking the perimeter*
(bypassing the token, the host-header/Origin/CSP defenses, the loopback bind, the VPN fail-closed
gate, the safe-probe mediation, or the scope gate).

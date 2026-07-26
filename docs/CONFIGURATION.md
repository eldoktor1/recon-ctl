# Configuration guide — tools, MCP, plugins & the AI model

Everything you need to configure after `./install.sh`. Most of it is also surfaced in the UI
(**Settings → AI models · wizard**, **Daemon / Ops**, **Lanes**).

## 1. AI model — the brain

The pipeline's brain is **Claude** (primary) with a **local model** fallback when Claude is
rate-limited. Configure both from **Settings → AI models · wizard**, or on the CLI:

### Claude (primary)
- Runs on your **Claude Max subscription** (headless `claude -p`, **no API key**). Connect once:
  ```bash
  claude        # then: /login
  ```
- For full offensive-security capability, enroll in **Anthropic's Cyber Verification Program (CVP)**:
  <https://portal.anthropic.com/programs/cvp>. Without it, capability on cyber tasks is throttled.
- Never pass `--bare` (that forces API-key auth and bypasses the Max OAuth login).

### Local fallback agent (when Claude is limited)
- Needs **Ollama** running (`systemctl --user start ollama`, or `ollama serve`).
- The fallback is a **full-capability agent** (not a chat box): it drives `bash` (the whole
  recon-ctl pipeline, `curl -x 127.0.0.1:8080` through Burp, Brave, files) + `web_search`, and
  emits the same stream-json the co-pilot renders.
- **Pick the model in the wizard** (dropdown of installed models + a "pull" box), or:
  ```bash
  ollama pull hermes3:8b                      # the recommended, tool-driving model
  echo 'hermes3:8b' > ~/recon/state/ai_agent_model   # what the wizard writes
  ```
- **Model choice matters for tool-use.** Of the models tested, only ones that expose Ollama's
  `tools` capability drive tools reliably (e.g. `hermes3:8b`). Uncensored/pentest-tuned 8B builds
  (mythos-sec, dolphin3, notmythos, qwen3.5-uncensored) were either completion-only or had broken
  tool-calling — the agent falls back to a ReAct text protocol for those, which is less reliable.
- Override per-run with env: `AI_AGENT_MODEL`, `OLLAMA_URL`, `AI_AGENT_MAX_ROUNDS`, `AI_AGENT_BASH_TIMEOUT`.

## 2. MCP servers (Burp + Brave)

The co-pilot and the local agent drive tools; two MCP servers extend Claude's reach. They live in
the repo `.mcp.json` (Burp auto-loads; Brave is passed at runtime when its debug port is up).

- **Burp Pro** — proxy on `127.0.0.1:8080` (replay), MCP on `127.0.0.1:9876`. Start Burp Pro on
  Windows with its MCP extension; the co-pilot auto-loads the `burp` tools when :9876 is listening.
  Config-dump tools are deliberately denied (they'd leak saved creds into the transcript).
- **Brave (logged-in) over CDP** — launch debug-Brave once so the co-pilot can drive your authed
  session:
  ```bash
  powershell.exe -ExecutionPolicy Bypass -File scripts/launch_brave_debug.ps1
  ```
  It binds `--remote-debugging-port 9222` on a dedicated profile; log into your targets in that
  window once. The `brave` MCP tools arm on the co-pilot's next turn.

## 3. Egress — Mullvad (required, fail-closed)

Mullvad VPN must be the **sole egress** (OS-level killswitch). All traffic — WSL and Windows —
exits through it. `~/recon/state/vpn_down` pauses **all** scanning and probing (fail-closed).
Never touch nftables/iptables/VPN config. Confirm: `am.i.mullvad` → `mullvad_exit_ip == true`.

## 4. Elasticsearch + secrets

```bash
cp docker/.env.example docker/.env && $EDITOR docker/.env
docker compose -f docker/docker-compose.yml up -d      # ES 8.17.4 + Kibana (loopback only)
bash scripts/recon_es_bootstrap.sh
```
Then (chmod `600` each, keep OUT of git):
- `~/.recon_es_netrc` — ES auth (`machine 127.0.0.1 login elastic password <pass>`).
- `~/recon/state/private_programs/email_aliases.json` — your per-platform signup aliases
  (recon-account reads it; the repo ships `you@example.com` placeholders).
- Optional API keys: Discord webhook, Shodan/Censys/PDCP/Chaos (see `docs/knowledge/reference_api_credit_budget`).

## 5. Plugins / lanes

Each recon lane has a killswitch under `~/recon/state/kill/<lane>` and is controlled from
**Lanes** in the UI (or `recon-start` / `start_recon_safe.sh`). Standing research routines
(`recon-research`) keep CVE/tool/KB knowledge fresh. See [`CLAUDE.md`](../CLAUDE.md) for the full
lane map and the operating doctrine.

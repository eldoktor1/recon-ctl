# Quickstart — first run on a fresh box

Step-by-step from `git clone` to a running pipeline. For the one-command version see the README
[Quickstart](../README.md#quickstart); this is the annotated walkthrough.

> **Target platform:** Kali (or Debian/Ubuntu) on **WSL2**. Native Linux mostly works; the daemon,
> the ES stack, and the VPN gate assume the WSL-on-Windows deployment.

## 0. Prerequisites (install these first)

- **Go**, **Node ≥18 + npm**, **Python 3**, **Docker**, `git`, `jq`, `curl`.
- **Mullvad VPN** on the host, configured as the sole egress.
- **Claude Max subscription** — you'll log in on the box in step 4.

`install.sh` reports which of these are missing but does not install the base toolchains themselves
(Go, Node, Docker) — grab those from your package manager first.

## 1. Clone + bootstrap

```bash
git clone <this-repo> ~/recon-pipeline && cd ~/recon-pipeline
./install.sh
```

`install.sh` is **idempotent** — re-run it any time; it skips whatever's already in place. It:

- installs the go-based recon tools (`subfinder`, `httpx`, `katana`, `nuclei`, `dalfox`, `gau`,
  `alterx`, `uncover`, `interactsh-client`, `tlsx`, `dnsx`, `notify`, …) and notes the apt/manual ones
  (`sqlmap`, `trufflehog`, `puredns`);
- clones + venv-installs **Autoswagger** to `~/tools/autoswagger` (pulls presidio + spaCy
  `en_core_web_lg`, ~400MB — slow first run; skip with `./install.sh --no-swagger`);
- creates the engine venv with **Playwright + Pillow** and downloads Chromium (for screenshots /
  xss-confirm);
- installs the **UI backend** deps and builds the **React frontend** (`--no-ui` to skip);
- creates `~/recon/{state,logs,briefings}` without clobbering existing data.

Missing tools don't fail the install — each lane no-ops gracefully until its tool is present.

## 2. Secrets (none are in the repo — create them; chmod 600)

```bash
# Elasticsearch creds (used by every ES query)
printf 'machine 127.0.0.1 login elastic password <YOUR_ES_PW>\n' > ~/.recon_es_netrc

# Optional: Discord notifications (one webhook URL per file)
mkdir -p ~/recon/state/discord
# echo 'https://discord.com/api/webhooks/...' > ~/recon/state/discord/review
# ...ops, digest, takeovers

# Optional per-lane API keys (lanes no-op without them)
# echo '<key>' > ~/.recon_shodan_key
# echo '<token>' > ~/.recon_github_token

chmod 600 ~/.recon_* 2>/dev/null || true
```

## 3. Elasticsearch (local, loopback-only)

```bash
cp docker/.env.example docker/.env && $EDITOR docker/.env   # set ELASTIC/KIBANA passwords
docker compose -f docker/docker-compose.yml up -d
bash scripts/recon_es_bootstrap.sh                          # create index + mappings
```

ES lives at `http://127.0.0.1:9200`, index `recon_alive`. Verify the running containers publish on
`127.0.0.1` (not `0.0.0.0`) — see the [SECURITY.md](../SECURITY.md) hardening checklist.

## 4. Claude — log in + CVP

```bash
claude        # then: /login   (uses your Max subscription; no API key)
```

For **full capability on offensive-security tasks**, enroll in Anthropic's **Cyber Verification
Program**: <https://portal.anthropic.com/programs/cvp>. Without it, Claude's safeguards limit the
exploitation-reasoning the pipeline depends on. See [ai-providers.md](knowledge/ai-providers.md).

## 5. VPN check

Mullvad must be up and the sole egress. The daemon runs a preflight + VPN gate and refuses to scan
otherwise (fail-closed). If you see `~/recon/state/vpn_down`, scanning is paused until egress is a
Mullvad exit again.

## 6. Go live

```bash
./tools/start_ui.sh    # web control plane → http://127.0.0.1:8787 (token-gated)
recon-start            # the daemon: preflight + VPN gate, then the loops
```

The UI prints/serves a token on first start — treat it like a root password (see SECURITY.md). Then:

```bash
recon-status           # daemon, loops, ES, VPN, queue
recon-logs             # live stream
recon-ai status        # Claude verdict breakdown
```

## Troubleshooting

- **A lane produces nothing** — its tool is probably missing. Re-run `./install.sh` or install the
  binary; the lane no-ops until then.
- **ES queries 401** — check `~/.recon_es_netrc` matches the password in `docker/.env`.
- **Screenshots/xss-confirm no-op** — Playwright Chromium didn't download; re-run
  `~/recon/.venv/bin/python -m playwright install chromium`.
- **No scanning happens** — VPN gate. Confirm Mullvad is up and `~/recon/state/vpn_down` is absent.

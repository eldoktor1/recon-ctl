# Contributing

Thanks for looking. This is offensive-security tooling — see [`SECURITY.md`](SECURITY.md) for the
responsible-use boundary and the trust model before you run anything.

> **License:** this project is [MIT-licensed](LICENSE). By contributing you agree your contributions are
> licensed under the same MIT terms. It is dual-use offensive-security tooling — the no-warranty /
> responsible-use terms in [`LICENSE`](LICENSE) and [`SECURITY.md`](SECURITY.md) apply.

## Getting set up

```bash
git clone <this-repo> ~/recon-pipeline && cd ~/recon-pipeline
./install.sh            # idempotent bootstrap — safe to re-run
```

See [`docs/QUICKSTART.md`](docs/QUICKSTART.md) for the full first-run walkthrough (secrets, ES, VPN,
Claude login).

## Rules of the road

- **Python is WSL-only.** Always run `python3`/`pip` inside WSL (the whole engine runs under WSL
  `python3`). Never invoke bare `python`/`pip` on the Windows side.
- **No secrets, ever.** Nothing under `~/.recon_*`, `~/recon/` runtime state, `.env`, `.mcp.json`,
  webhooks, tokens, or API keys goes into git. The tree is code-only. Double-check `git diff` before
  committing; `.gitignore` is the backstop, not the plan.
- **No personal/identifying data.** Don't hardcode emails, handles, home paths (`/home/<user>`,
  `C:\Users\<user>`), or private infra hostnames — parameterize to `$HOME` / `${RECON_HOME}` / env.
- **Commit AND push every change** with an honest message; keep `origin/main` a full mirror of code
  (never of secrets or local state). Sign your work with a `Co-Authored-By:` trailer where relevant.
- **Debloat.** When you retire a feature, remove its code/vars/menus/unused scripts — no commented-out
  cruft or dead loops. Temp scripts go to `/tmp` and get removed, never the data dir.

## Where things live

- [`CLAUDE.md`](CLAUDE.md) — the operating doctrine (read it; it's the source of truth for *why* the
  lanes are shaped the way they are).
- [`docs/knowledge/`](docs/knowledge/) — reusable KB: `class-<vuln>.md`, `tech-<stack>.md`,
  `tool-<name>.md`, `process-<flow>.md`. **Read the matching doc before working a tech/class; append
  what you learn.** Host-specific findings go to `host_notes`, not the KB.
- `scripts/` — detection, confirm, Claude agents, control plane. `engine/` — the finding-state
  machine + reporter + observability. `ui/` — FastAPI backend + React/Vite frontend.

## Adding a lane

Every new lane has to answer the motto: **"how is this not what everyone runs?"** Pattern-match =
LEAD; a directly-observed safe primitive = CONFIRMED. Keep confirmation **safe (unauthenticated,
non-destructive)**, respect the VPN fail-closed gate, and route speculative output to the nightly
briefing — never an interrupt. See the existing lanes in `CLAUDE.md` for the shape.

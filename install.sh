#!/usr/bin/env bash
#
# install.sh — one-shot, idempotent bootstrap for the recon·ctl pipeline.
#
# Safe to re-run: every step guards on "already present" and skips.
# Does NOT need root; uses sudo only for apt, and only if apt packages are missing.
# Does NOT touch your secrets (~/.recon_*), your VPN, or existing ~/recon data.
#
# Usage:   ./install.sh            # full bootstrap
#          ./install.sh --no-apt   # skip apt (offline / non-Debian)
#          ./install.sh --no-ui    # skip the web UI build (npm)
#          ./install.sh --no-swagger  # skip Autoswagger (~400MB spaCy model)
#
set -euo pipefail

# ---------------------------------------------------------------------------
# flags + helpers
# ---------------------------------------------------------------------------
DO_APT=1 DO_UI=1 DO_SWAGGER=1
for a in "$@"; do
  case "$a" in
    --no-apt)     DO_APT=0 ;;
    --no-ui)      DO_UI=0 ;;
    --no-swagger) DO_SWAGGER=0 ;;
    -h|--help)    grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown flag: $a (see --help)"; exit 2 ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECON_HOME="${RECON_HOME:-$HOME/recon}"
TOOLS_HOME="${TOOLS_HOME:-$HOME/tools}"
GOBIN="${GOBIN:-$HOME/go/bin}"

c_hdr()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
c_ok()   { printf '  \033[1;32m[ok]\033[0m %s\n'   "$*"; }
c_skip() { printf '  \033[0;90m[skip]\033[0m %s\n' "$*"; }
c_warn() { printf '  \033[1;33m[warn]\033[0m %s\n' "$*"; }
c_add()  { printf '  \033[1;35m[+]\033[0m %s\n'    "$*"; }
have()   { command -v "$1" >/dev/null 2>&1; }

MISSING_REQUIRED=() MISSING_OPTIONAL=()

# ---------------------------------------------------------------------------
# 0. environment detection
# ---------------------------------------------------------------------------
c_hdr "Environment"
if grep -qiE 'kali|debian|ubuntu' /etc/os-release 2>/dev/null; then
  c_ok "Debian-family OS detected ($(. /etc/os-release; echo "$PRETTY_NAME"))"
else
  c_warn "Not a Debian/Kali system — apt steps may not apply; continuing anyway."
  DO_APT=0
fi
if grep -qi microsoft /proc/version 2>/dev/null; then
  c_ok "Running under WSL (expected deployment target)"
else
  c_warn "Not WSL — the pipeline is developed on Kali-on-WSL2; native Linux mostly works."
fi
c_ok "Repo root: $REPO_ROOT"

# ---------------------------------------------------------------------------
# 1. base toolchains (go / python / node / jq) — reported, not force-installed
# ---------------------------------------------------------------------------
c_hdr "Base toolchains"
for t in go python3 pip3 node npm jq git curl docker; do
  if have "$t"; then c_ok "$t present ($( "$t" --version 2>/dev/null | head -n1 || echo present))"
  else c_warn "$t NOT found — install it before the dependent steps below can run"; fi
done
if ! have go; then
  c_warn "Go is required for the recon binaries. Install: sudo apt install -y golang-go  (or from go.dev/dl)"
fi
# make sure freshly-go-installed tools are visible in THIS shell
export PATH="$GOBIN:$PATH"

# ---------------------------------------------------------------------------
# 2. Go-based recon tools (go install) — the ProjectDiscovery / tomnomnom set
# ---------------------------------------------------------------------------
c_hdr "Go recon tools (go install)"
# name<TAB>go-package  — required set
GO_REQUIRED=(
  "subfinder|github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "httpx|github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "katana|github.com/projectdiscovery/katana/cmd/katana@latest"
  "nuclei|github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  "dnsx|github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  "tlsx|github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
  "gau|github.com/lc/gau/v2/cmd/gau@latest"
  "dalfox|github.com/hahwul/dalfox/v2@latest"
)
# optional / lane-specific set
GO_OPTIONAL=(
  "alterx|github.com/projectdiscovery/alterx/cmd/alterx@latest"
  "uncover|github.com/projectdiscovery/uncover/cmd/uncover@latest"
  "interactsh-client|github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
  "notify|github.com/projectdiscovery/notify/cmd/notify@latest"
  "naabu|github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  "gf|github.com/tomnomnom/gf@latest"
  "qsreplace|github.com/tomnomnom/qsreplace@latest"
  "anew|github.com/tomnomnom/anew@latest"
  "waybackurls|github.com/tomnomnom/waybackurls@latest"
  "assetfinder|github.com/tomnomnom/assetfinder@latest"
)

go_install_set() {
  local kind="$1"; shift
  for entry in "$@"; do
    local name="${entry%%|*}" pkg="${entry#*|}"
    if have "$name"; then
      c_skip "$name already on PATH"
    elif have go; then
      c_add "go install $name ..."
      if go install "$pkg" >/dev/null 2>&1; then
        c_ok "$name installed → $GOBIN"
      else
        c_warn "go install failed for $name ($pkg)"
        [ "$kind" = req ] && MISSING_REQUIRED+=("$name") || MISSING_OPTIONAL+=("$name")
      fi
    else
      [ "$kind" = req ] && MISSING_REQUIRED+=("$name") || MISSING_OPTIONAL+=("$name")
    fi
  done
}
go_install_set req  "${GO_REQUIRED[@]}"
go_install_set opt  "${GO_OPTIONAL[@]}"

# ---------------------------------------------------------------------------
# 3. apt / pipx tools (not go-installable): sqlmap, trufflehog, puredns, etc.
# ---------------------------------------------------------------------------
c_hdr "System / apt tools"
# name<TAB>apt-package
APT_TOOLS=(
  "sqlmap|sqlmap"
  "massdns|massdns"
  "sqlite3|sqlite3"
  "dig|dnsutils"
  "xvfb-run|xvfb"
)
if [ "$DO_APT" = 1 ]; then
  APT_TO_GET=()
  for entry in "${APT_TOOLS[@]}"; do
    name="${entry%%|*}" pkg="${entry#*|}"
    if have "$name"; then c_skip "$name present"; else APT_TO_GET+=("$pkg"); fi
  done
  if [ "${#APT_TO_GET[@]}" -gt 0 ]; then
    c_add "apt-get install: ${APT_TO_GET[*]}"
    sudo apt-get update -qq || c_warn "apt-get update failed (continuing)"
    sudo apt-get install -y "${APT_TO_GET[@]}" || c_warn "some apt packages failed to install"
  else
    c_ok "all apt tools already present"
  fi
else
  c_skip "apt step disabled (--no-apt / non-Debian)"
fi
# tools that are neither go nor a clean apt package — note them, don't fail
for t in trufflehog puredns arjun s3scanner nomore403 gungnir; do
  have "$t" && c_ok "$t present" || {
    c_warn "$t missing — install manually (see README Prerequisites)"
    MISSING_OPTIONAL+=("$t")
  }
done

# ---------------------------------------------------------------------------
# 4. Autoswagger — install-by-default (clone + venv + requirements)
# ---------------------------------------------------------------------------
c_hdr "Autoswagger (unauth Swagger/OpenAPI BOLA scanner)"
AS_HOME="${AS_HOME:-$TOOLS_HOME/autoswagger}"
if [ "$DO_SWAGGER" = 0 ]; then
  c_skip "Autoswagger disabled (--no-swagger)"
elif [ -x "$AS_HOME/venv/bin/python" ]; then
  c_skip "Autoswagger already installed at $AS_HOME"
elif ! have git || ! have python3; then
  c_warn "git + python3 required for Autoswagger — skipping"
  MISSING_OPTIONAL+=("autoswagger")
else
  mkdir -p "$TOOLS_HOME"
  if [ ! -d "$AS_HOME/.git" ]; then
    c_add "git clone intruder-io/autoswagger → $AS_HOME"
    git clone --depth 1 https://github.com/intruder-io/autoswagger.git "$AS_HOME" \
      || { c_warn "clone failed"; MISSING_OPTIONAL+=("autoswagger"); }
  fi
  if [ -d "$AS_HOME/.git" ] && [ ! -x "$AS_HOME/venv/bin/python" ]; then
    c_add "creating venv + installing requirements (pulls presidio + spaCy en_core_web_lg, ~400MB — slow first run)"
    python3 -m venv "$AS_HOME/venv"
    "$AS_HOME/venv/bin/pip" install -q --upgrade pip
    if "$AS_HOME/venv/bin/pip" install -q -r "$AS_HOME/requirements.txt"; then
      c_ok "Autoswagger ready — lane recon_autoswagger.sh will detect it at $AS_HOME"
    else
      c_warn "Autoswagger requirements install failed (the ~400MB spaCy model may need a retry)"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 5. Python engine deps (screenshots / confirm workers) — venv-preferred
# ---------------------------------------------------------------------------
c_hdr "Python engine deps (Playwright + Pillow)"
ENGINE_VENV="${ENGINE_VENV:-$RECON_HOME/.venv}"
if have python3; then
  if [ ! -x "$ENGINE_VENV/bin/python" ]; then
    c_add "creating engine venv at $ENGINE_VENV"
    mkdir -p "$RECON_HOME"
    python3 -m venv "$ENGINE_VENV"
  else
    c_skip "engine venv present ($ENGINE_VENV)"
  fi
  "$ENGINE_VENV/bin/pip" install -q --upgrade pip
  c_add "pip install playwright Pillow"
  "$ENGINE_VENV/bin/pip" install -q playwright Pillow || c_warn "playwright/Pillow install failed"
  if "$ENGINE_VENV/bin/python" -c 'import playwright' 2>/dev/null; then
    c_add "playwright install chromium (browser download)"
    "$ENGINE_VENV/bin/python" -m playwright install chromium || c_warn "chromium download failed — screenshots/xss-confirm will no-op"
    c_ok "Playwright ready"
  fi
else
  c_warn "python3 missing — engine screenshot/confirm workers unavailable"
fi

# ---------------------------------------------------------------------------
# 6. UI backend (FastAPI) + frontend (Vite/React build)
# ---------------------------------------------------------------------------
c_hdr "Web UI / control plane"
UI_BE="$REPO_ROOT/ui/backend" UI_FE="$REPO_ROOT/ui/frontend"
if have python3 && [ -f "$UI_BE/requirements.txt" ]; then
  UI_VENV="${UI_VENV:-$UI_BE/.venv}"
  [ -x "$UI_VENV/bin/python" ] || { c_add "creating UI backend venv"; python3 -m venv "$UI_VENV"; }
  c_add "pip install -r ui/backend/requirements.txt"
  "$UI_VENV/bin/pip" install -q -r "$UI_BE/requirements.txt" || c_warn "UI backend deps failed"
  c_ok "UI backend deps installed ($UI_VENV)"
else
  c_skip "UI backend skipped (python3 or requirements.txt missing)"
fi
if [ "$DO_UI" = 1 ] && have npm && [ -f "$UI_FE/package.json" ]; then
  if [ -d "$UI_FE/dist" ]; then
    c_skip "frontend already built (ui/frontend/dist present — delete to rebuild)"
  else
    c_add "npm ci && npm run build (ui/frontend)"
    ( cd "$UI_FE" && npm ci && npm run build ) \
      && c_ok "frontend built → ui/frontend/dist" \
      || c_warn "frontend build failed (check Node version ≥18)"
  fi
elif [ "$DO_UI" = 0 ]; then
  c_skip "UI build disabled (--no-ui)"
else
  c_warn "npm not found — skipping frontend build"
fi

# ---------------------------------------------------------------------------
# 7. runtime dirs (never clobber existing data)
# ---------------------------------------------------------------------------
c_hdr "Runtime directories under $RECON_HOME"
for d in state logs briefings state/kill; do
  if [ -d "$RECON_HOME/$d" ]; then c_skip "$RECON_HOME/$d exists"
  else mkdir -p "$RECON_HOME/$d" && c_ok "created $RECON_HOME/$d"; fi
done

# ---------------------------------------------------------------------------
# NEXT STEPS
# ---------------------------------------------------------------------------
c_hdr "Bootstrap complete — NEXT STEPS"
cat <<EOF

  1. SECRETS (none live in this repo — create them yourself; keep them chmod 600):
       ~/.recon_es_netrc                          ES creds (machine 127.0.0.1 login elastic password <pw>)
       ~/recon/state/discord/{review,ops,digest,takeovers}   Discord webhook URLs (one per file, optional)
       ~/.recon_shodan_key / _github_token / ...  per-lane API keys (optional; see README)
     Then:  chmod 600 ~/.recon_*

  2. ELASTICSEARCH (local, loopback-only):
       cp docker/.env.example docker/.env && \$EDITOR docker/.env   # set ELASTIC/KIBANA passwords
       docker compose -f docker/docker-compose.yml up -d
       bash scripts/recon_es_bootstrap.sh                          # index + mappings

  3. VPN — Mullvad must be the SOLE egress, fail-closed. The daemon refuses to
     scan unless it sees a Mullvad exit and no ~/recon/state/vpn_down flag.

  4. CLAUDE — the AI engine runs on a Claude Max subscription (headless \`claude -p\`,
     no API key). Log in on the box:  claude  then /login
     For FULL capability on offensive-security tasks, enroll in Anthropic's
     Cyber Verification Program (CVP) — see README "AI engine" + docs/knowledge/ai-providers.md.

  5. GO LIVE:
       ./tools/start_ui.sh      # web control plane (http://127.0.0.1:8787 — token-gated)
       recon-start              # the daemon (preflight + VPN gate, then loops)

EOF

if [ "${#MISSING_REQUIRED[@]}" -gt 0 ]; then
  c_warn "MISSING REQUIRED tools: ${MISSING_REQUIRED[*]} — install before running the core pipeline."
fi
if [ "${#MISSING_OPTIONAL[@]}" -gt 0 ]; then
  c_warn "Missing optional (lane-specific) tools: ${MISSING_OPTIONAL[*]} — those lanes no-op gracefully until installed."
fi
c_ok "Done. Re-run ./install.sh any time — it skips whatever is already in place."

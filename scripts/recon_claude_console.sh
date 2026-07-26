#!/usr/bin/env bash
# =============================================================================
# recon_claude_console.sh — the in-UI Claude co-pilot turn executor.
#
# Runs ONE conversational turn of the operator's driving console. Emits
# stream-json events (one JSON object per line) that the recon-ui-runner
# captures and the web process streams to the browser over WebSocket.
#
# Conversation continuity: the first turn of a session pins a --session-id;
# every later turn --resume's it. A per-session marker file survives frontend
# reloads so a page refresh keeps talking to the same conversation.
#
# Usage: recon_claude_console.sh <session_uuid> <message> [model] [perm_mode]
#
# This is the operator driving their OWN local pipeline through a loopback,
# token-gated UI. Claude inherits repo CLAUDE.md (scope discipline, the
# recon-vs-attack hard line) as its standing doctrine.
# =============================================================================
set -uo pipefail

SESSION="${1:-}"
MESSAGE="${2:-}"
MODEL="${3:-}"
# FULL PARITY (operator 2026-07-22): the in-UI co-pilot has the SAME power as a
# fully-permissioned Claude Code session — unrestricted tools, no allow-list.
# bypassPermissions runs every tool without an (impossible, headless) prompt. The
# ONLY guardrail is now the doctrine in APPEND_SYS + CLAUDE.md, so that prompt
# carries the recon-vs-attack hard line that the tool restriction used to enforce.
PERM="${4:-${RECON_CONSOLE_PERM:-bypassPermissions}}"

[[ -n "$SESSION" ]] || { echo '{"type":"error","error":"session uuid required"}'; exit 2; }
[[ -n "$MESSAGE" ]] || { echo '{"type":"error","error":"message required"}'; exit 2; }
# Defense-in-depth: the session id is used in a path — force it to a UUID shape.
[[ "$SESSION" =~ ^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$ ]] \
  || { echo '{"type":"error","error":"malformed session id"}'; exit 2; }

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLAUDE_BIN="${CLAUDE_BIN:-$HOME/.local/bin/claude}"
STATE_DIR="${STATE_DIR:-$HOME/recon/state}"
CONSOLE_DIR="$STATE_DIR/ui_console"
MARKER="$CONSOLE_DIR/$SESSION.started"
mkdir -p "$CONSOLE_DIR" 2>/dev/null || true

cd "$REPO_DIR" 2>/dev/null || { echo '{"type":"error","error":"repo dir missing"}'; exit 1; }

# Shared bidirectional failover engine (Claude <-> local WhiteRabbitNeo). Sourcing it here is
# what makes the in-UI co-pilot / Guide-me / auto-drive / AutoNote fail over to the local model
# when Claude is rate-limited — the same engine the shell AI lanes use (scripts/ai_invoke.sh).
# A MISSING claude CLI is no longer fatal: the dispatch at the end routes the turn to the local
# model instead of erroring the console.
source "$REPO_DIR/scripts/lib/ai_failover.sh"

# TOOLS: no --allowedTools is passed. Under bypassPermissions the co-pilot has the
# full built-in toolset (Bash, Read/Grep/Glob, Edit/Write, WebSearch/WebFetch, Task,
# TodoWrite, …) plus every MCP tool that loads — exactly like a Claude Code session.
# Burp Pro (Windows) auto-loads from the project .mcp.json (approved via
# settings.local.json → enabledMcpjsonServers:["burp"]) whenever its MCP server is
# listening on 127.0.0.1:9876; under bypassPermissions ITS ENTIRE toolset is usable,
# INCLUDING target-facing sends (send_http1/2_request, Repeater/Intruder). Those are
# no longer tool-gated — the recon-vs-attack hard line in APPEND_SYS + CLAUDE.md is
# what governs them: in-scope+PAYING only, read-only by default, confirm-then-stop.
#
# SELF-EXPOSURE DENY (kept closed on purpose, security-first): the ONLY Burp tools we
# still block are the config dumps — their sole function is to spill Burp's saved
# config (stored creds / upstream-proxy secrets) into a transcript that renders in the
# web UI. Denying them costs ZERO hunting capability. Deny rules are enforced even
# under bypassPermissions, so this survives the full-parity mode.
DISALLOWED="mcp__burp__output_project_options mcp__burp__output_user_options"

APPEND_SYS="You are the in-UI co-pilot of this recon pipeline, embedded in the operator's mission-control web app — you are INSIDE the ship, not commanding it from Earth. This is the operator's OWN local single-operator pipeline and you are authorized to drive it, with FULL tool parity to a Claude Code session: unrestricted Bash, file edits, WebSearch/WebFetch, subagents (Task), the full Burp Pro toolset when its MCP is up (proxy/scanner reads AND target-facing sends — Repeater/Intruder/send_http), and full control of the operator's real logged-in Brave. NO tool is blocked; that means the SAFETY DOCTRINE below is the ONLY guardrail and it is ABSOLUTE. Use Bash to run the dispatcher: 'recon <sub>' (e.g. 'recon briefing', 'recon top 20', 'recon fresh', 'recon scope <host>', 'recon note <host> \"text\"', 'recon verify <host>', 'recon roundup'). Read/Grep the repo and ~/recon state directly. RECON-VS-ATTACK HARD LINE (non-negotiable, CLAUDE.md): before ANY target-facing send (Burp send/Repeater/Intruder, an active probe, a browser POST) verify the host is in-scope AND per-asset PAYING; default to READ-ONLY / GET-HEAD-OPTIONS; confirm an exposure exists, do NOT exploit past it (the PoC is 'this leaks without auth', never a data harvest); for IDOR/BAC use TWO accounts the OPERATOR OWNS and swap ONLY owned object IDs (NEVER a guessed/enumerated/third-party ID); NEVER move money, place/amend/cancel orders, run destructive/DoS/RCE-for-harm, or bypass a login to get IN; confirm-then-STOP at proof. ANTI-BURN: respect 429/403/rate-limits, back off, never get the Mullvad exit banned. TEMPLATE-SAFETY: read before you fire — never auto-run off-the-shelf SSRF/RCE/LFI templates that harvest data. NOTE EVERYTHING: every FP/skip/disqualification/noise gets a host_note the moment you hit it; CONFIRMED-vs-LEAD discipline (only a directly-observed primitive mints CONFIRMED). Answer for a narrow chat pane: lead with the decision/answer, keep prose tight, prefer ranked concrete output over essays. When you run a command, briefly say what you ran and what it means. BROWSER — YOU CAN ALWAYS CONTROL THE OPERATOR'S REAL LOGGED-IN BRAVE over CDP (chrome-devtools-mcp). This capability is PERMANENT — never say you cannot control the browser. Only its live wiring is conditional: when mcp__brave__* tools are loaded, debug-Brave is running NOW — drive it directly for AUTHED recon (map API ops, read the logged-in DOM / network requests / auth-header names + own IDs, screenshots) and operator-SUPERVISED PoCs, under the same read-only/in-scope-paying/2-owned-accounts/confirm-then-stop safety as above. If mcp__brave__* tools are NOT loaded, debug-Brave simply isn't running yet — the capability still exists, so do NOT claim you can't. Bring it online yourself: run via Bash 'powershell.exe -ExecutionPolicy Bypass -File scripts/launch_brave_debug.ps1' (starts their Brave with remote debugging on a dedicated profile). The browser tools then arm on your NEXT turn (they bind at turn start), so launch it, tell the operator to log into that Brave window if the target needs auth, and drive it on the next turn. TOKEN ECONOMY (conserve without cutting quality): reuse output already in this conversation instead of re-running; read targeted line ranges / grep instead of dumping whole files; batch independent shell commands into one call; don't restate long tool output back to the operator — summarize it. Full rigor on the thinking, lean on the tokens."

# ---- Logged-in Brave over CDP (chrome-devtools-mcp, Windows-side node) ---------
# Drives the operator's REAL Brave over the DevTools protocol for AUTHED recon +
# operator-supervised testing. Wired ONLY when debug-Brave is listening on
# BRAVE_PORT (launch it: scripts/launch_brave_debug.ps1 → --remote-debugging-port
# on a DEDICATED profile the operator logs into once). Like burp, the MCP server
# is a WINDOWS node process so it reaches Brave on Windows-loopback natively (no
# WSL→Windows bridge). Passed via a RUNTIME --mcp-config: brave is deliberately
# NOT in .mcp.json, so there is no duplicate-server hang and the project burp
# server still auto-loads beside it. Debug port down ⇒ skip; console runs as before.
BRAVE_NODE="${BRAVE_NODE:-/mnt/c/Program Files/nodejs/node.exe}"
BRAVE_MCP_ENTRY="${BRAVE_MCP_ENTRY:-C:/Users/mhabs/AppData/Roaming/npm/node_modules/chrome-devtools-mcp/build/src/bin/chrome-devtools-mcp.js}"
BRAVE_PORT="${BRAVE_PORT:-9222}"
MCP_CONFIG=()
_PSB="/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
if [[ -x "$BRAVE_NODE" && -x "$_PSB" ]] && timeout 6 "$_PSB" -NoProfile -Command \
     "if (Get-NetTCPConnection -LocalPort $BRAVE_PORT -State Listen -ErrorAction SilentlyContinue) {exit 0} else {exit 1}" \
     >/dev/null 2>&1; then
  BRAVE_CFG="$STATE_DIR/console_brave_mcp.json"
  printf '{ "mcpServers": { "brave": { "command": "%s", "args": ["%s","--browserUrl","http://127.0.0.1:%s"] } } }\n' \
    "$BRAVE_NODE" "$BRAVE_MCP_ENTRY" "$BRAVE_PORT" > "$BRAVE_CFG"
  MCP_CONFIG=( --mcp-config "$BRAVE_CFG" )
fi

# The pipeline's DATA dir (~/recon: findings.db, state, notes, briefings, logs)
# lives OUTSIDE the repo cwd. Declare it a workspace dir so the co-pilot's file
# tools read/write it without friction and it survives any future FS sandbox —
# reads/writes to it are the co-pilot's whole job (e.g. `recon ai real` opens
# ~/recon/v3/findings.db). d0k already has ACL access at the OS level.
RECON_DATA_DIR="${RECON_DATA_DIR:-$HOME/recon}"

# No --allowedTools: bypassPermissions grants the full built-in + MCP toolset.
# --disallowedTools still applies (deny rules win) — closes the config-dump self-leak.
ARGS=( -p "$MESSAGE"
       --output-format stream-json --verbose
       --permission-mode "$PERM"
       --add-dir "$RECON_DATA_DIR"
       --disallowedTools $DISALLOWED
       "${MCP_CONFIG[@]}"
       --append-system-prompt "$APPEND_SYS" )
[[ -n "$MODEL" ]] && ARGS+=( --model "$MODEL" )

# session continuity: the first claude turn pins --session-id, later turns --resume. The marker
# is created only AFTER claude actually runs (see dispatch) so an ollama-fallback turn never
# leaves a marker pointing at a claude session that was never created.
if [[ -f "$MARKER" ]]; then
  ARGS+=( --resume "$SESSION" )
else
  ARGS+=( --session-id "$SESSION" )
fi

# Emit the local model's plain-text answer as the SAME stream-json events the browser already
# parses (assistant text + result) — so a fallback turn is readable, not invisible JSON.
emit_local_streamjson() {  # $1 = user message
  local ans note
  ans="$(run_ollama "$1")"
  [[ -n "$ans" ]] || ans="(Claude is rate-limited and the local model returned no output — check that ollama is running at ${OLLAMA_URL} and ${OLLAMA_MODEL} is pulled.)"
  note="⚠ Claude is rate-limited — answered by the local model (plain chat: the agent was unavailable this turn)."
  if have_jq; then
    jq -nc --arg n "$note" --arg a "$ans" '{type:"assistant",message:{content:[{type:"text",text:($n+"\n\n"+$a)}]}}'
    jq -nc --arg a "$ans" '{type:"result",subtype:"success",is_error:false,result:$a,num_turns:1,duration_ms:0}'
  else
    local esc
    esc="$(printf '%s\n\n%s' "$note" "$ans" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))' 2>/dev/null)"
    [[ -n "$esc" ]] || esc='"local model output unavailable"'
    printf '{"type":"assistant","message":{"content":[{"type":"text","text":%s}]}}\n' "$esc"
  fi
}

# Serve a local turn with the FULL-CAPABILITY agent (native tool-calling: bash/recon-ctl/burp/brave
# + web_search, doctrine-guarded) when wired; fall back to plain-chat stream-json if the agent
# produced nothing (exit!=0). The agent emits stream-json itself, so its output flows straight through.
serve_local() {  # $1 = message
  local agent="$REPO_DIR/scripts/ai_agent.py"
  if [[ "${AI_AGENT_ENABLED:-1}" == "1" && -f "$agent" ]] && command -v python3 >/dev/null 2>&1; then
    if AGENT_MODEL="${AI_AGENT_MODEL:-hermes3:8b}" OLLAMA_URL="$OLLAMA_URL" \
       python3 "$agent" "$1" 2>>"$STATE_DIR/ai_agent.err"; then
      return 0
    fi
  fi
  emit_local_streamjson "$1"   # fallback: plain chat wrapped as stream-json
}

# ---- dispatch: pick the live brain from the shared failover state ----
_st="$(read_state)"
_active="$(printf '%s' "$_st" | cut -f1)"
_reset="$(printf '%s' "$_st" | cut -f2)"
_pc="$(printf '%s' "$_st" | cut -f3)"
[[ -x "$CLAUDE_BIN" ]] || _active="ollama"

if [[ "$_active" == "ollama" ]]; then
  # reverse-check whether Claude's quota is back before serving locally
  _pc=$(( _pc + 1 )); _probe=0
  reset_passed "$_reset" && _probe=1
  [[ "$_reset" == "null" ]] && (( _pc % PROBE_EVERY_N == 0 )) && _probe=1
  if [[ "$_probe" == "1" && -x "$CLAUDE_BIN" ]] && claude_alive; then
    write_state claude null "claude quota renewed (console reverse-probe)" 0
    log "SWITCH ollama->claude (console reverse-probe)"
    _active="claude"
  else
    write_state ollama "$_reset" "$( { have_jq && jq -r '.reason // "fallback active"' "$STATE_FILE" 2>/dev/null; } || echo 'fallback active')" "$_pc"
    serve_local "$MESSAGE"
    exit 0
  fi
fi

# active=claude: stream live via `tee` while capturing stdout+stderr to spot a usage limit.
_tmp="$(mktemp "${TMPDIR:-/tmp}/console.XXXXXX")"
"$CLAUDE_BIN" "${ARGS[@]}" 2>"$_tmp.err" | tee "$_tmp"
_ec=${PIPESTATUS[0]}
# mark a NEW session started only on success, so a limited first turn retries cleanly next time
[[ ! -f "$MARKER" && "$_ec" -eq 0 ]] && : > "$MARKER"
_combined="$(cat "$_tmp" "$_tmp.err" 2>/dev/null)"
# fall over ONLY on a genuine failure (non-zero exit) that also looks like a limit — a successful
# answer that merely mentions "rate limit" is never mistaken for one.
if [[ "$_ec" -ne 0 ]] && is_limit "$_ec" "$_combined"; then
  _rt="$(parse_reset "$_combined")"
  [[ "$_rt" == "null" ]] && _rt="$(date -u -d "+${FALLBACK_COOLDOWN} seconds" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo null)"
  _why="$(printf '%s' "$_combined" | grep -ioE '.{0,60}(usage limit|rate limit|limit reached|out of credit|quota|429).{0,40}' | head -1 | tr -d '\n' | cut -c1-160)"
  write_state ollama "$_rt" "${_why:-claude limit detected}" 0
  log "SWITCH claude->ollama (console limit: ${_why:-detected}; reset_at=$_rt)"
  serve_local "$MESSAGE"
  _ec=0   # the turn was served by the fallback — don't surface a task failure to the UI
fi
rm -f "$_tmp" "$_tmp.err" 2>/dev/null
exit "$_ec"

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
PERM="${4:-${RECON_CONSOLE_PERM:-acceptEdits}}"

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
[[ -x "$CLAUDE_BIN" ]] || { echo "{\"type\":\"error\",\"error\":\"claude cli not found at $CLAUDE_BIN\"}"; exit 1; }

# The tools the co-pilot may use to drive the pipeline. Bash runs `recon <sub>`
# and reads ~/recon state; Read/Grep/Glob explore the repo; WebSearch/WebFetch
# do research (Anthropic→web, not target traffic). No target traffic is issued
# by the console itself — target-facing lanes stay behind run_scanner/Mullvad.
ALLOWED="Bash Read Grep Glob Edit Write WebSearch WebFetch Task TodoWrite"

# Burp Pro (Windows) via the official MCP Server bridge (.mcp.json → Windows java.exe →
# mcp-proxy-all.jar → SSE 127.0.0.1:9876). Auto-allow only READ/analysis + Collaborator +
# encoder tools so the co-pilot can read proxy history / scanner issues / the loaded target
# and shape payloads. TARGET-FACING SENDS + state mutations (send_http1/2_request,
# create_repeater_tab[_http2], send_to_intruder, set_project/user_options,
# set_proxy_intercept_state, set_task_execution_engine_state, set_active_editor_contents)
# are DELIBERATELY excluded — they require explicit operator approval per the recon-vs-attack
# hard line ("sends stay approval-gated"; the console issues no autonomous target traffic).
# output_project/user_options are ALSO excluded: they dump Burp config which can contain saved
# credentials / upstream-proxy secrets (security-first; approve on demand when a scope read is
# genuinely needed — normal history/issue/collaborator reads don't require them).
BURP_READ="mcp__burp__get_proxy_http_history mcp__burp__get_proxy_http_history_regex \
mcp__burp__get_proxy_websocket_history mcp__burp__get_proxy_websocket_history_regex \
mcp__burp__get_scanner_issues mcp__burp__get_collaborator_interactions \
mcp__burp__generate_collaborator_payload mcp__burp__get_organizer_items \
mcp__burp__get_organizer_items_regex mcp__burp__get_active_editor_contents \
mcp__burp__url_encode mcp__burp__url_decode mcp__burp__base64_encode \
mcp__burp__base64_decode mcp__burp__generate_random_string"

APPEND_SYS="You are the in-UI co-pilot of this recon pipeline, embedded in the operator's mission-control web app — you are INSIDE the ship, not commanding it from Earth. This is the operator's OWN local single-operator pipeline and you are authorized to drive it. Use Bash to run the dispatcher: 'recon <sub>' (e.g. 'recon briefing', 'recon top 20', 'recon fresh', 'recon scope <host>', 'recon note <host> \"text\"', 'recon verify <host>', 'recon roundup'). Read/Grep the repo and ~/recon state directly. Follow every rule in CLAUDE.md — the recon-vs-attack hard line, per-asset scope+pays gating, note every FP/skip, and CONFIRMED-vs-LEAD discipline are absolute. Answer for a narrow chat pane: lead with the decision/answer, keep prose tight, prefer ranked concrete output over essays. When you run a command, briefly say what you ran and what it means. TOKEN ECONOMY (conserve without cutting quality): reuse output already in this conversation instead of re-running; read targeted line ranges / grep instead of dumping whole files; batch independent shell commands into one call; don't restate long tool output back to the operator — summarize it. Full rigor on the thinking, lean on the tokens."

# Load the Burp MCP bridge ONLY when Burp's MCP server is actually listening on the
# Windows loopback — otherwise the mcp-proxy startup would tax every console turn while
# Burp is closed. Probe via Windows PowerShell (Burp binds 127.0.0.1, unreachable from
# WSL's own stack); on any failure we silently skip Burp and the console runs as before.
if [[ -f "$REPO_DIR/.mcp.json" ]]; then
  _PS="/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
  if [[ -x "$_PS" ]] && timeout 5 "$_PS" -NoProfile -Command \
       "if (Get-NetTCPConnection -LocalPort 9876 -State Listen -ErrorAction SilentlyContinue) {exit 0} else {exit 1}" \
       >/dev/null 2>&1; then
    # Burp is up → expose the READ tools. The server AUTO-LOADS from the project .mcp.json
    # (approved once via .claude/settings.local.json → enabledMcpjsonServers:["burp"]).
    # Do NOT pass --mcp-config here: an explicit config spawns a DUPLICATE server that hangs
    # at status "pending" with 0 tools (verified 2026-07-19) — auto-load is the working path.
    ALLOWED="$ALLOWED $BURP_READ"
  fi
fi

ARGS=( -p "$MESSAGE"
       --output-format stream-json --verbose
       --permission-mode "$PERM"
       --allowedTools $ALLOWED
       --append-system-prompt "$APPEND_SYS" )
[[ -n "$MODEL" ]] && ARGS+=( --model "$MODEL" )

if [[ -f "$MARKER" ]]; then
  ARGS+=( --resume "$SESSION" )
else
  ARGS+=( --session-id "$SESSION" )
  : > "$MARKER"
fi

exec "$CLAUDE_BIN" "${ARGS[@]}"

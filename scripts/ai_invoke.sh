#!/usr/bin/env bash
# ai_invoke.sh — unified "run this prompt on the best available brain" wrapper.
#
# Drop-in for `claude -p …`: pass the SAME argv you would give the claude CLI. The
# wrapper resolves the ACTIVE provider from ~/recon/state/ai_fallback.json and:
#   * active=claude (default): runs the real `claude` CLI with your argv verbatim.
#       If the result shows a usage/credit/rate LIMIT, it flips the state to `ollama`
#       and FALLS THROUGH to the local model for THIS call (so no work is lost).
#   * active=ollama: serves the prompt from the local Ollama model
#       (WhiteRabbitNeo-V3-7B), PREPENDED with the system primer so the local brain
#       has pipeline context. Before serving it REVERSE-CHECKS Claude: if the parsed
#       reset time has passed (or every Nth call) it cheaply probes `claude -p ok`;
#       on success it flips back to claude and uses it.
#
# Model output goes to stdout so callers are drop-in. Provider switches are logged to
# ~/recon/state/ai_fallback.log. The failover ENGINE (state, limit-detection, ollama
# call, reverse-probe) lives in scripts/lib/ai_failover.sh — shared verbatim with the
# in-UI co-pilot (recon_claude_console.sh) so there is ONE engine, not two.
set -u
IFS=$' \t\n'

# shared failover engine (config + is_limit/parse_reset/run_ollama/claude_alive/state I-O)
# shellcheck source=lib/ai_failover.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/ai_failover.sh"

# ----------------------------------------------------------------- main
main() {
  local st active reset pc
  st="$(read_state)"; active="$(printf '%s' "$st" | cut -f1)"
  reset="$(printf '%s' "$st" | cut -f2)"; pc="$(printf '%s' "$st" | cut -f3)"

  if [[ -z "$CLAUDE_BIN" || ! -x "$CLAUDE_BIN" ]]; then active="ollama"; fi

  if [[ "$active" == "ollama" ]]; then
    # reverse-check: is Claude back?
    pc=$(( pc + 1 ))
    local should_probe=0
    reset_passed "$reset" && should_probe=1
    [[ "$reset" == "null" ]] && (( pc % PROBE_EVERY_N == 0 )) && should_probe=1
    if [[ "$should_probe" == "1" ]] && claude_alive; then
      write_state claude null "claude quota renewed (reverse-probe ok)" 0
      log "SWITCH ollama->claude (reverse-probe succeeded)"
      exec "$CLAUDE_BIN" "$@"
    fi
    write_state ollama "$reset" "$(jq -r '.reason // "fallback active"' "$STATE_FILE" 2>/dev/null || echo 'fallback active')" "$pc"
    local prompt; prompt="$(extract_prompt "$@")"
    [[ -n "$prompt" ]] || prompt="$(cat 2>/dev/null)"
    run_ollama "$prompt"
    return 0
  fi

  # active=claude: run it, watch for a limit, fall through to ollama on limit
  local tmp; tmp="$(mktemp "${TMPDIR:-/tmp}/ai_invoke.XXXXXX")"
  "$CLAUDE_BIN" "$@" >"$tmp" 2>>"$tmp.err"; local ec=$?
  local combined; combined="$(cat "$tmp" "$tmp.err" 2>/dev/null)"
  if is_limit "$ec" "$combined"; then
    local rt; rt="$(parse_reset "$combined")"
    [[ "$rt" == "null" ]] && rt="$(date -u -d "+${FALLBACK_COOLDOWN} seconds" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo null)"
    local why; why="$(printf '%s' "$combined" | grep -ioE '.{0,60}(usage limit|rate limit|limit reached|out of credit|quota|429).{0,40}' | head -1 | tr -d '\n' | cut -c1-160)"
    write_state ollama "$rt" "${why:-claude limit detected}" 0
    log "SWITCH claude->ollama (limit: ${why:-detected}; reset_at=$rt)"
    local prompt; prompt="$(extract_prompt "$@")"
    [[ -n "$prompt" ]] || prompt="$(cat "$tmp" 2>/dev/null)"  # (no stdin left; best-effort)
    rm -f "$tmp" "$tmp.err" 2>/dev/null
    run_ollama "$prompt"
    return 0
  fi
  cat "$tmp"; [[ -s "$tmp.err" ]] && cat "$tmp.err" >&2
  rm -f "$tmp" "$tmp.err" 2>/dev/null
  return "$ec"
}

main "$@"

# TODO (deferred follow-on capability layer — do NOT build here):
#   * local-model MCP tool-use (burp / brave) so the fallback brain can act, not just reason
#   * web-search for the local model (Anthropic->web parity)
#   * compounding-knowledge RAG over docs/knowledge + host_notes for grounded local answers

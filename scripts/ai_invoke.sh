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
# ~/recon/state/ai_fallback.log. This is the CORE bidirectional failover; local-model
# MCP tool-use / web-search / RAG is a deferred follow-on layer (see TODO at bottom).
#
# ai_fallback.json schema:
#   { "active": "claude"|"ollama",     # which brain is live now
#     "since": "<ISO8601>",             # when it became active
#     "claude_reset_at": "<ISO8601>|null",  # when Claude quota is expected back
#     "reason": "<free text>",          # why we switched (limit line / manual)
#     "probe_count": <int> }            # ollama calls since last reverse-probe
set -u
IFS=$' \t\n'

# ----------------------------------------------------------------- config / paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
STATE_FILE="${AI_FALLBACK_STATE:-$STATE_DIR/ai_fallback.json}"
LOG_FILE="${AI_FALLBACK_LOG:-$STATE_DIR/ai_fallback.log}"

CLAUDE_BIN="${CLAUDE_BIN:-$HOME/.local/bin/claude}"; [[ -x "$CLAUDE_BIN" ]] || CLAUDE_BIN="$(command -v claude 2>/dev/null || echo '')"
OLLAMA_URL="${OLLAMA_URL:-http://127.0.0.1:11434}"
OLLAMA_MODEL="${OLLAMA_MODEL:-WhiteRabbitNeo/WhiteRabbitNeo-V3-7B:latest}"
OLLAMA_TIMEOUT="${OLLAMA_TIMEOUT:-600}"
PRIMER_FILE="${AI_PRIMER_FILE:-$REPO_DIR/docs/knowledge/ai-system-primer.md}"
[[ -f "$PRIMER_FILE" ]] || PRIMER_FILE="${AI_PRIMER_FALLBACK:-$STATE_DIR/ai_primer.txt}"

# cooldown before we assume Claude MIGHT be back if we couldn't parse a reset time (sec)
FALLBACK_COOLDOWN="${AI_FALLBACK_COOLDOWN:-18000}"   # 5h
# reverse-probe every Nth ollama call even before the reset time
PROBE_EVERY_N="${AI_FALLBACK_PROBE_EVERY_N:-12}"

mkdir -p "$STATE_DIR" 2>/dev/null || true

now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }
log() { printf '%s %s\n' "$(now_iso)" "$*" >>"$LOG_FILE" 2>/dev/null || true; }
have_jq() { command -v jq >/dev/null 2>&1; }

# ----------------------------------------------------------------- state helpers
read_state() {  # echoes: <active> <claude_reset_at> <probe_count>
  local active reset pc
  if have_jq && [[ -f "$STATE_FILE" ]]; then
    active="$(jq -r '.active // "claude"' "$STATE_FILE" 2>/dev/null)"
    reset="$(jq -r '.claude_reset_at // "null"' "$STATE_FILE" 2>/dev/null)"
    pc="$(jq -r '.probe_count // 0' "$STATE_FILE" 2>/dev/null)"
  fi
  printf '%s\t%s\t%s' "${active:-claude}" "${reset:-null}" "${pc:-0}"
}

write_state() {  # write_state <active> <reset_at|null> <reason> <probe_count>
  local active="$1" reset="$2" reason="$3" pc="${4:-0}"
  if have_jq; then
    jq -nc --arg a "$active" --arg s "$(now_iso)" --arg r "$reset" \
       --arg why "$reason" --argjson pc "${pc:-0}" \
       '{active:$a, since:$s, claude_reset_at:(if $r=="null" or $r=="" then null else $r end), reason:$why, probe_count:$pc}' \
       >"$STATE_FILE" 2>/dev/null || true
  else
    printf '{"active":"%s","since":"%s","claude_reset_at":%s,"reason":"%s","probe_count":%s}\n' \
      "$active" "$(now_iso)" \
      "$([[ "$reset" == "null" || -z "$reset" ]] && echo null || echo "\"$reset\"")" \
      "$reason" "${pc:-0}" >"$STATE_FILE" 2>/dev/null || true
  fi
}

# ----------------------------------------------------------------- limit detection
# Returns 0 if the given text/exit looks like a Claude usage/credit/rate LIMIT.
is_limit() {  # is_limit <exit_code> <combined_text>
  local ec="$1" txt="$2"
  printf '%s' "$txt" | grep -qiE \
    'usage limit|session limit|rate limit|5-hour limit|weekly limit|limit reached|out of (credit|credits)|insufficient (credit|credits|quota)|quota (exceeded|exhausted)|too many requests|429|will reset|resets? (at|in)|please try again later' \
    && return 0
  return 1
}

# Best-effort parse of a reset time from a Claude limit message → ISO8601 (or "null").
parse_reset() {  # parse_reset <text>
  local txt="$1" got=""
  # explicit ISO timestamp
  got="$(printf '%s' "$txt" | grep -oiE '[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}' | head -1)"
  if [[ -n "$got" ]]; then printf '%sZ' "${got%Z}"; return; fi
  # unix epoch (10 digits) near "reset"
  got="$(printf '%s' "$txt" | grep -oiE 'reset[^0-9]{0,20}[0-9]{10}' | grep -oE '[0-9]{10}' | head -1)"
  if [[ -n "$got" ]]; then date -u -d "@$got" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null && return; fi
  # "resets at 6pm" / "reset at 18:00" — let `date` interpret the clock time
  got="$(printf '%s' "$txt" | grep -oiE 'reset[s]?[^0-9a-z]{0,6}(at )?[0-9]{1,2}(:[0-9]{2})?\s?(am|pm)?' | grep -oiE '[0-9]{1,2}(:[0-9]{2})?\s?(am|pm)?' | head -1)"
  if [[ -n "$got" ]]; then date -u -d "$got" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null && return; fi
  printf 'null'
}

reset_passed() {  # reset_passed <iso|null> -> 0 if the time is in the past / null-with-cooldown-elapsed
  local reset="$1"
  if [[ "$reset" == "null" || -z "$reset" ]]; then return 1; fi
  local rt nt
  rt="$(date -u -d "$reset" +%s 2>/dev/null || echo 0)"
  nt="$(date -u +%s)"
  [[ "$rt" -gt 0 && "$nt" -ge "$rt" ]]
}

# ----------------------------------------------------------------- prompt extraction
# Pull the prompt text out of a claude-style argv (value after -p/--print) or stdin.
extract_prompt() {
  local prev="" a
  for a in "$@"; do
    if [[ "$prev" == "-p" || "$prev" == "--print" ]]; then printf '%s' "$a"; return; fi
    prev="$a"
  done
  # -p present but no inline value, or prompt on stdin
  if [[ ! -t 0 ]]; then cat; fi
}

# ----------------------------------------------------------------- ollama path
run_ollama() {  # run_ollama <prompt-text>
  # Uses /api/chat (NOT /api/generate) so Ollama applies the model's chat template —
  # raw generate skips it and the qwen2-family model returns gibberish. The primer is
  # the system message; the caller's prompt is the user message.
  local prompt="$1" primer="" body resp
  [[ -f "$PRIMER_FILE" ]] && primer="$(cat "$PRIMER_FILE" 2>/dev/null)"
  if have_jq; then
    body="$(jq -nc --arg m "$OLLAMA_MODEL" --arg s "$primer" --arg p "$prompt" \
      '{model:$m, stream:false,
        messages:( ($s|length>0|if . then [{role:"system",content:$s}] else [] end) + [{role:"user",content:$p}] )}')"
  else
    local esc_s esc_p
    esc_s="$(printf '%s' "$primer" | sed 's/\\/\\\\/g; s/"/\\"/g' | awk 'BEGIN{ORS="\\n"}{print}')"
    esc_p="$(printf '%s' "$prompt" | sed 's/\\/\\\\/g; s/"/\\"/g' | awk 'BEGIN{ORS="\\n"}{print}')"
    body="{\"model\":\"$OLLAMA_MODEL\",\"stream\":false,\"messages\":[{\"role\":\"system\",\"content\":\"$esc_s\"},{\"role\":\"user\",\"content\":\"$esc_p\"}]}"
  fi
  resp="$(curl -s --max-time "$OLLAMA_TIMEOUT" "$OLLAMA_URL/api/chat" \
            -H 'Content-Type: application/json' -d "$body" 2>/dev/null)"
  if have_jq; then
    printf '%s' "$resp" | jq -r '.message.content // .error // empty' 2>/dev/null
  else
    printf '%s' "$resp"
  fi
}

# ----------------------------------------------------------------- claude probe
claude_alive() {  # cheap reverse-probe; 0 if Claude answers OK (quota back)
  [[ -n "$CLAUDE_BIN" && -x "$CLAUDE_BIN" ]] || return 1
  local out
  out="$(timeout 60 "$CLAUDE_BIN" -p "Reply with exactly: OK" 2>&1)"
  local ec=$?
  is_limit "$ec" "$out" && return 1
  printf '%s' "$out" | grep -q "OK"
}

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

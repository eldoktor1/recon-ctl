#!/usr/bin/env bash
# ai_failover.sh — shared bidirectional Claude <-> WhiteRabbitNeo failover engine.
#
# Sourced by BOTH callers so there is ONE engine, not two:
#   * scripts/ai_invoke.sh          — drop-in `claude -p …` wrapper for the shell AI lanes
#   * scripts/recon_claude_console.sh — the in-UI co-pilot (Guide-me / auto-drive / AutoNote),
#     which wraps the local model's plain text into stream-json so the browser renders it.
#
# Pure config + functions; NO main() and NO output — the caller owns control flow and the
# output format (plain passthrough for lanes, stream-json for the console).
#
# ai_fallback.json schema:
#   { "active": "claude"|"ollama", "since": "<ISO8601>",
#     "claude_reset_at": "<ISO8601>|null", "reason": "<free text>", "probe_count": <int> }

# ----------------------------------------------------------------- config / paths
_AIFO_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${REPO_DIR:-$(cd "$_AIFO_LIB_DIR/../.." && pwd)}"
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
read_state() {  # echoes: <active>\t<claude_reset_at>\t<probe_count>
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
  got="$(printf '%s' "$txt" | grep -oiE '[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}' | head -1)"
  if [[ -n "$got" ]]; then printf '%sZ' "${got%Z}"; return; fi
  got="$(printf '%s' "$txt" | grep -oiE 'reset[^0-9]{0,20}[0-9]{10}' | grep -oE '[0-9]{10}' | head -1)"
  if [[ -n "$got" ]]; then date -u -d "@$got" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null && return; fi
  got="$(printf '%s' "$txt" | grep -oiE 'reset[s]?[^0-9a-z]{0,6}(at )?[0-9]{1,2}(:[0-9]{2})?\s?(am|pm)?' | grep -oiE '[0-9]{1,2}(:[0-9]{2})?\s?(am|pm)?' | head -1)"
  if [[ -n "$got" ]]; then date -u -d "$got" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null && return; fi
  printf 'null'
}

reset_passed() {  # reset_passed <iso|null> -> 0 if the time is in the past
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
  if [[ ! -t 0 ]]; then cat; fi
}

# ----------------------------------------------------------------- ollama path
run_ollama() {  # run_ollama <prompt-text>  -> plain-text answer on stdout
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

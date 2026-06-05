#!/usr/bin/env bash
# Minimal local Ollama chat wrapper. Returns model content only.
# Retries up to 3 times on curl/timeout failure before giving up.
set -uo pipefail
IFS=$'\n\t'

MODEL="${1:?model required}"
PROMPT_FILE="${2:?prompt file required}"
OLLAMA_URL="${OLLAMA_URL:-http://127.0.0.1:11434}"
OLLAMA_TIMEOUT="${OLLAMA_TIMEOUT:-120}"
OLLAMA_RETRIES="${OLLAMA_RETRIES:-3}"
# Cap inference threads. ollama defaults to ~all physical cores; on this 14-core
# WSL2 box that lets a 50-lead AI scoring burst saturate every core at the
# ollama service's nice 0, starving root /init so `wsl.exe` session creation from
# Windows times out (WSAETIMEDOUT / 0x8007274c). An 8B-Q4 model is memory-
# bandwidth bound, so 6 threads costs little throughput while leaving ~8 cores
# for /init, the 9p file server and the rest of the pipeline. 0 = let ollama decide.
OLLAMA_NUM_THREAD="${OLLAMA_NUM_THREAD:-6}"

[[ -s "$PROMPT_FILE" ]] || exit 1

payload="$(jq -n \
  --arg model "$MODEL" \
  --argjson nthread "$OLLAMA_NUM_THREAD" \
  --rawfile prompt "$PROMPT_FILE" \
  '{
    model: $model,
    stream: false,
    format: "json",
    options: ({temperature: 0.1, num_ctx: 8192} + (if $nthread > 0 then {num_thread: $nthread} else {} end)),
    messages: [
      {
        role: "system",
        content: "You are a bug bounty triage assistant. Return strict JSON only. Do not suggest exploitation, fuzzing, brute force, bypass attempts, or payloads. Suggest only low-impact verification."
      },
      {role: "user", content: $prompt}
    ]
  }')"

attempt=0
while (( attempt < OLLAMA_RETRIES )); do
  attempt=$(( attempt + 1 ))
  resp="$(curl -fsS -m "$OLLAMA_TIMEOUT" "$OLLAMA_URL/api/chat" \
    -H 'Content-Type: application/json' \
    -d "$payload" 2>/dev/null)" && {
    printf '%s' "$resp" | jq -r '.message.content // empty'
    exit 0
  }
  # Transient failure — back off before retrying (skip sleep on last attempt)
  (( attempt < OLLAMA_RETRIES )) && sleep $(( attempt * 5 ))
done
exit 1

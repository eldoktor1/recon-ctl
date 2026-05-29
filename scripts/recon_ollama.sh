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

[[ -s "$PROMPT_FILE" ]] || exit 1

payload="$(jq -n \
  --arg model "$MODEL" \
  --rawfile prompt "$PROMPT_FILE" \
  '{
    model: $model,
    stream: false,
    format: "json",
    options: {temperature: 0.1, num_ctx: 8192},
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

#!/usr/bin/env bash
# Minimal local Ollama chat wrapper. Returns model content only.
set -Eeuo pipefail
IFS=$'\n\t'

MODEL="${1:?model required}"
PROMPT_FILE="${2:?prompt file required}"
OLLAMA_URL="${OLLAMA_URL:-http://127.0.0.1:11434}"
OLLAMA_TIMEOUT="${OLLAMA_TIMEOUT:-120}"

[[ -s "$PROMPT_FILE" ]] || exit 1

curl -fsS -m "$OLLAMA_TIMEOUT" "$OLLAMA_URL/api/chat" \
  -H 'Content-Type: application/json' \
  -d "$(jq -n \
    --arg model "$MODEL" \
    --rawfile prompt "$PROMPT_FILE" \
    '{
      model: $model,
      stream: false,
      options: {temperature: 0.1, num_ctx: 8192},
      messages: [
        {
          role: "system",
          content: "You are a bug bounty triage assistant. Return strict JSON only. Do not suggest exploitation, fuzzing, brute force, bypass attempts, or payloads. Suggest only low-impact verification."
        },
        {role: "user", content: $prompt}
      ]
    }')" \
  | jq -r '.message.content // empty'

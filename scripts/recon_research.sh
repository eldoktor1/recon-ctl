#!/usr/bin/env bash
# =============================================================================
# recon_research.sh — standing Claude RESEARCH routine: keeps the system UPDATED.
#
# The pipeline already has DATA feeds (CVE/KEV intel, nuclei-update, self-audit). This is the
# missing CLAUDE-DRIVEN research layer that keeps tooling / detection / verification / vuln
# knowledge fresh — the "research is the edge" doctrine, automated. Runs headless Claude on the
# Max subscription (no API key) with WebSearch/WebFetch, per topic, on a cadence.
#
# NOT target traffic (Claude's web tools egress Anthropic→web, not us→target) → runs as d0k, no
# Mullvad/run_scanner gate.
#
# OUTPUT (autonomy = operator-chosen "auto-commit digests + new KB, propose edits"):
#   - docs/research/<topic>_<date>.md        dated digest (auto-commit + push)
#   - docs/knowledge/<slug>.md               brand-NEW KB doc, ONLY if slug is new (auto-commit)
#   - docs/research/proposals/<date>_*.md     edits to EXISTING KB → review-only (never auto-applied)
#   + a concise Discord summary (#research → #digest → #ops fallback).
# bash controls ALL file writes (Claude gets only WebSearch/WebFetch — never Write/Edit/Bash).
#
# TOPICS:  tooling (weekly) · vulns (daily) · kb-enrich (weekly) · detect-tune (weekly) · all
# USAGE:   recon_research.sh <topic>
# =============================================================================
set -uo pipefail
IFS=$'\n\t'
log()  { printf '[%s RESEARCH] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s RESEARCH WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

# Alert #ops when the headless CLI is logged out / rate-limited (an OPERATOR action — re-run /login).
# Cooled down to once per 24h across all topics so a broken login can't spam the channel every cycle.
cli_error_alert() {
  local topic="$1" errline="$2" stamp="$STATE_DIR/research_cli_error.alerted"
  [[ -f "$stamp" && "$(find "$stamp" -mmin -1440 2>/dev/null)" ]] && return 0
  local hook; hook="$(discord_hook ops 2>/dev/null || true)"
  [[ -n "$hook" ]] || hook="$(discord_hook digest 2>/dev/null || true)"
  if [[ -n "$hook" ]]; then
    discord_post "$hook" "$(jq -nc --arg c "⚠️ **recon-research halted** — headless Claude CLI: \`${errline:0:120}\`. Research digests are paused until you re-auth: run \`~/.local/bin/claude\` → \`/login\`. (No junk committed.)" '{content:$c}')" >/dev/null 2>&1 || true
  fi
  : > "$stamp" 2>/dev/null || true
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/recon_net.sh"
setup_es_netrc
ES_AUTH=(--netrc-file "$HOME/.recon_es_netrc")

BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"
INDEX_NAME="${INDEX_NAME:-recon_alive}"

CLAUDE_BIN="${CLAUDE_BIN:-$HOME/.local/bin/claude}"; [[ -x "$CLAUDE_BIN" ]] || CLAUDE_BIN="$(command -v claude 2>/dev/null || echo '')"
RESEARCH_MODEL="${RESEARCH_MODEL:-sonnet}"
RESEARCH_TIMEOUT="${RESEARCH_TIMEOUT:-900}"
RESEARCH_GIT_PUSH="${RESEARCH_GIT_PUSH:-1}"
RESEARCH_GIT_COMMIT="${RESEARCH_GIT_COMMIT:-1}"

HELPER="$SCRIPT_DIR/recon_research.py"
KB_DIR="$REPO_DIR/docs/knowledge"
RESEARCH_DIR="$REPO_DIR/docs/research"
WORK="$BASE_DIR/research/work"
LOCK_FILE="$STATE_DIR/research.lock"

mkdir -p "$RESEARCH_DIR/proposals" "$WORK" "$STATE_DIR" 2>/dev/null || true
command -v jq >/dev/null 2>&1 || { warn "jq missing"; exit 0; }
[[ -n "$CLAUDE_BIN" && -x "$CLAUDE_BIN" ]] || { warn "claude CLI not found ($CLAUDE_BIN) — skipping"; exit 0; }

# ---- context for the prompt ----
kb_list() { ls "$KB_DIR" 2>/dev/null | sed 's/\.md$//' | paste -sd', ' -; }
LANES="subdomain/CT-fresh enum, JS-intel endpoint mining, IDOR/BAC ranking (reasoning-only), XSS/SQLi (dalfox/sqlmap), n-day/KEV version-reasoning, GitHub-leak secrets (trufflehog), cloud buckets (S3Scanner), subdomain takeover, SSRF (interactsh OOB), GraphQL schema-worklist, web-cache deception, active param discovery (arjun), nuclei exposure templates"
top_tech() {
  local q resp
  q='{"size":0,"query":{"bool":{"filter":[{"term":{"triage_in_scope":true}}]}},"aggs":{"t":{"terms":{"field":"tech","size":25}}}}'
  resp="$(curl -sS -m20 "${ES_AUTH[@]}" -H 'Content-Type: application/json' -X POST "$ES_URL/$INDEX_NAME/_search" -d "$q" 2>/dev/null)" || resp=""
  printf '%s' "$resp" | jq -r '[.aggregations.t.buckets[]?.key] | join(", ")' 2>/dev/null | head -c 600
}

PREAMBLE() {
  cat <<EOF
You are the standing RESEARCH routine for an autonomous bug-bounty recon pipeline. Keep the system
UPDATED with what is NEW and ACTIONABLE — do NOT restate basics we already know.

DOCTRINE (what is useful to us):
- be UNIQUE: anything the whole crowd runs (subfinder|httpx|nuclei-defaults on saturated programs) =
  duplicates = worthless. Only surface genuine EDGES.
- unauth-safe, non-destructive, dup-resistant; IDOR/authed testing is human-in-the-loop; theoretical
  / no-impact classes (CORS, missing headers, self-XSS, version-only) get declined — don't surface them.
- precision over volume; cite SOURCES (URLs); flag uncertainty; be concise.
- BE EFFICIENT: at most ~6-8 web searches/fetches this run — prioritize the highest-value sources and
  finish within a few minutes. Quality over exhaustiveness; it's fine to surface 2-3 strong items.

OUR LANES: $LANES.
OUR KB TOPICS (docs/knowledge/): $(kb_list).
OUR IN-SCOPE TOP TECH (from our data): $(top_tech).

OUTPUT CONTRACT:
- Produce a CONCISE, SOURCE-CITED markdown digest of NEW, actionable findings (highest-value first,
  no fluff). If nothing genuinely new/actionable this run, say so in one line.
- For durable reusable knowledge, embed fenced blocks (the harness writes the files — you only emit text):
    \`\`\`kb-new:<slug>
    <full markdown body of a BRAND-NEW doc; slug = tech-<x> or class-<x> we do NOT already have>
    \`\`\`
    \`\`\`kb-proposal:<slug>
    <an addition/edit to an EXISTING doc named <slug>>
    \`\`\`
  Use existing slug names from OUR KB TOPICS for proposals; only use kb-new for topics we lack.
- Keep total output focused (a few hundred lines max).
- Output ONLY the digest markdown (plus any kb-new/kb-proposal blocks). NO conversational preamble,
  no "Now I'll…" framing, no closing remarks — start directly with the digest content.
EOF
}

topic_task() {
  case "$1" in
    tooling) cat <<'EOF'

TASK — TOOLING WATCH: survey for NEW or BETTER open-source tools (GitHub, active in the last ~6-12
months: releases, stars, maintenance) that would genuinely improve any of our lanes, OR a tool
CATEGORY we lack. For each candidate: what it does, whether it BEATS what we already use, whether it
fits our doctrine (unauth-safe? dup-resistant? or a dup-trap?), and a verdict: ADOPT / EVALUATE / SKIP
(say why). Be skeptical — only flag real upgrades. We already use: subfinder, httpx, nuclei, katana,
gau, dalfox, sqlmap, trufflehog, S3Scanner, arjun, native-graphql, WCVS, interactsh, naabu, gungnir.
We REJECTED VulnAPI (no BOLA, sends mutating requests). Don't re-recommend what we have or rejected.
EOF
;;
    vulns) cat <<'EOF'

TASK — VULN/CVE + WRITEUP WATCH (last ~7-14 days): find NEW CVEs/KEV additions and fresh disclosed
reports / technique writeups RELEVANT TO OUR TOP TECH and vuln classes. Prioritize: version-reasoned
n-day candidates for tech we run (give affected version range + a REAL fingerprint/path to detect, not
just the tech-class — per our doctrine a KEV tech-class without a confirmed in-range version is only a
LEAD), new high-severity UNAUTH classes, and new bypasses. For each: what, affected versions, how to
detect (fingerprint/header/path/dork), is it in-range-verifiable unauth, and the SOURCE url.
EOF
;;
    kb-enrich) cat <<'EOF'

TASK — KB ENRICHMENT: pick 1-2 of OUR existing KB tech-/class- docs and research NEW (last ~12 months)
published techniques, payloads, bypasses, sinks, or fingerprints that would deepen them. Emit the
additions as kb-proposal:<existing-slug> blocks (these will be queued for review, not auto-applied). If
you find a tech/class that is clearly in-scope for us but we have NO doc for, emit a kb-new:<slug> block
with a full first draft. Favor depth on the highest-EV money classes (IDOR/BAC, GraphQL, SSRF, SQLi).
EOF
;;
    detect-tune) cat <<'EOF'

TASK — DETECTION & VERIFICATION TUNING: research improvements to how we DETECT and CONFIRM, aimed at
fewer false positives + higher real-finding yield. Cover: new fingerprints/dorks (favicon hashes,
headers, error pages, paths, Shodan/FOFA-style queries) to enumerate our classes/tech from already-
collected data; known FALSE-POSITIVE patterns to suppress; better/safer confirm primitives; and
precision-tuning ideas. Make each item ACTIONABLE (what to match, where). Emit durable fingerprint/FP
knowledge as kb-proposal blocks to the relevant existing class-/tech- docs.
EOF
;;
  esac
}

run_topic() {
  local topic="$1" today raw prompt summary
  today="$(date '+%Y-%m-%d')"
  raw="$WORK/${topic}.raw.md"
  prompt="$(PREAMBLE)$(topic_task "$topic")"
  [[ -n "$(topic_task "$topic")" ]] || { warn "unknown topic: $topic"; return 1; }

  log "$topic — researching (model=$RESEARCH_MODEL, WebSearch/WebFetch)…"
  timeout "$RESEARCH_TIMEOUT" "$CLAUDE_BIN" -p "$prompt" --model "$RESEARCH_MODEL" \
    --permission-mode dontAsk --allowedTools "WebSearch WebFetch" > "$raw" 2>/dev/null || true
  if [[ ! -s "$raw" ]]; then warn "$topic — no research output (auth/timeout?)"; return 0; fi

  # GUARD: the headless CLI emits a short meta-error (logged out / rate-limited) to stdout instead of
  # research. That is NOT a digest — never commit/push it (it poisoned git history Jun 28–Jul 09).
  # A real digest is multi-KB and starts with content; an error stub is one short line. Gate on both.
  if [[ "$(wc -c < "$raw")" -lt 1000 ]] && grep -qiE \
       'not logged in|please run /login|hit your (weekly|usage) limit|invalid api key|authentication_error|credit balance is too low' \
       "$raw"; then
    local errline; errline="$(head -1 "$raw" | tr -d '\r')"
    warn "$topic — CLI auth/limit error, skipping commit: ${errline}"
    cli_error_alert "$topic" "$errline"
    return 0
  fi

  summary="$(python3 "$HELPER" route --topic "$topic" --date "$today" --input "$raw" \
              --kb-dir "$KB_DIR" --research-dir "$RESEARCH_DIR" 2>/dev/null)" || summary=""
  [[ -n "$summary" ]] || { warn "$topic — router failed"; return 0; }
  local nnew nprop headline digest
  nnew="$(jq -r '.new_kb | length' <<<"$summary" 2>/dev/null || echo 0)"
  nprop="$(jq -r '.proposals | length' <<<"$summary" 2>/dev/null || echo 0)"
  headline="$(jq -r '.headline // ""' <<<"$summary" 2>/dev/null)"
  digest="$(jq -r '.digest // ""' <<<"$summary" 2>/dev/null)"
  log "$topic — digest + ${nnew} new KB + ${nprop} proposal(s)"

  commit_and_notify "$topic" "$today" "$nnew" "$nprop" "$headline"
}

commit_and_notify() {
  local topic="$1" today="$2" nnew="$3" nprop="$4" headline="$5"
  # commit the research outputs + any brand-new KB doc (scoped add; never code/secrets)
  [[ "$RESEARCH_GIT_COMMIT" == "1" ]] || { log "$topic — commit skipped (RESEARCH_GIT_COMMIT=0)"; return 0; }
  ( cd "$REPO_DIR" || exit 0
    git add docs/research docs/knowledge 2>/dev/null || true
    if git diff --cached --quiet 2>/dev/null; then
      log "$topic — nothing new to commit"
    else
      git commit -q -m "research(${topic}): ${headline:-update} — ${today}

Auto-generated by recon_research.sh (digest + new KB; edits-to-existing queued as proposals).

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>" 2>/dev/null \
        && log "$topic — committed" || { warn "$topic — commit failed"; return 0; }
      if [[ "$RESEARCH_GIT_PUSH" == "1" ]]; then
        git push -q origin HEAD 2>/dev/null && log "$topic — pushed" || warn "$topic — push failed (commit kept local)"
      fi
    fi
  )
  # Discord summary (low-noise: one line per run)
  local hook; hook="$(discord_hook research 2>/dev/null || true)"
  [[ -n "$hook" ]] || hook="$(discord_hook digest 2>/dev/null || true)"
  [[ -n "$hook" ]] || hook="$(discord_hook ops 2>/dev/null || true)"
  if [[ -n "$hook" ]]; then
    local card; card="$(printf '🔬 **Research — %s (%s)**\n%s\n_%s new KB · %s proposal(s) → docs/research/%s_%s.md_' \
      "$topic" "$today" "${headline:0:300}" "$nnew" "$nprop" "$topic" "$today")"
    discord_post "$hook" "$(jq -nc --arg c "${card:0:1900}" '{content:$c}')" >/dev/null 2>&1 || true
  fi
}

main() {
  exec 9>"$LOCK_FILE"; flock -n 9 || { log "another research run in progress"; exit 0; }
  case "${1:-}" in
    tooling|vulns|kb-enrich|detect-tune) run_topic "$1" ;;
    all) run_topic tooling; run_topic vulns; run_topic kb-enrich; run_topic detect-tune ;;
    ""|-h|--help) echo "usage: $0 <tooling|vulns|kb-enrich|detect-tune|all>" >&2; exit 2 ;;
    *) warn "unknown topic: $1"; exit 2 ;;
  esac
}
main "$@"

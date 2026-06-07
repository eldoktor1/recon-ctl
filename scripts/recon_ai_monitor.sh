#!/usr/bin/env bash
# =============================================================================
# recon_ai_monitor.sh — Claude-Max MONITOR / GUIDANCE pass over the whole pipeline.
#
# Claude's third role (besides ANALYZE and VERIFY): a skeptical second enforcer that
# watches every process and GUIDES — read-only reasoning over LOCAL telemetry only, it
# issues NO target traffic. Each run it gathers burn signals (probe rate-limits / cooldowns
# / 429-403 bans), verdict health + precision, failures/halts, daemon errors and VPN state,
# then asks Claude for a health assessment + concrete guidance, posts a compact card to
# #ops, and writes ~/recon/state/ai_monitor_latest.json. Best-effort and non-blocking.
#
# Runs as d0k (Claude auth). Low frequency (hourly-ish). No Mullvad requirement (local only).
# =============================================================================
set -uo pipefail
IFS=$'\n\t'
log()  { printf '[%s AI-MONITOR] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s AI-MONITOR WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/recon_net.sh" 2>/dev/null || true
BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
LOG_DIR="${LOG_DIR:-$BASE_DIR/logs}"
V3_DB="${V3_DB:-$BASE_DIR/v3/findings.db}"
STATE_PY="${STATE_PY:-$SCRIPT_DIR/../engine/state.py}"
CLAUDE_BIN="${CLAUDE_BIN:-$HOME/.local/bin/claude}"; [[ -x "$CLAUDE_BIN" ]] || CLAUDE_BIN="$(command -v claude 2>/dev/null || echo '')"
CLAUDE_MONITOR_MODEL="${CLAUDE_MONITOR_MODEL:-sonnet}"
CLAUDE_TIMEOUT="${CLAUDE_TIMEOUT:-120}"
PROBE_AUDIT="${SAFE_PROBE_AUDIT:-$STATE_DIR/safe_probe_audit.log}"
OUT="${AI_MONITOR_OUT:-$STATE_DIR/ai_monitor_latest.json}"

mkdir -p "$STATE_DIR"
exec 9>"$STATE_DIR/ai_monitor.lock"; flock -n 9 || { warn "already running"; exit 0; }
[[ -n "$CLAUDE_BIN" && -x "$CLAUDE_BIN" ]] || { warn "claude CLI not found — skipping"; exit 0; }
command -v jq >/dev/null 2>&1 || { warn "jq missing"; exit 0; }

now_iso="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
hr_ago="$(date -u -d '1 hour ago' '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo '')"

# ---- gather LOCAL telemetry (read-only) -------------------------------------
# burn signals from the probe audit log (ts\tmethod\tstatus\turl)
probes_1h=0; blocks_1h=0
if [[ -f "$PROBE_AUDIT" && -n "$hr_ago" ]]; then
  probes_1h="$(awk -F'\t' -v c="$hr_ago" '$1>=c' "$PROBE_AUDIT" 2>/dev/null | grep -c . 2>/dev/null)"
  blocks_1h="$(awk -F'\t' -v c="$hr_ago" '$1>=c && ($3==429||$3==403||$3==503)' "$PROBE_AUDIT" 2>/dev/null | grep -c . 2>/dev/null)"
fi
cooldowns="$(ls "$STATE_DIR"/probe_rl/cooldown_* 2>/dev/null | grep -c . 2>/dev/null)"
gpause="none"; [[ -f "$STATE_DIR/probe_global_pause" ]] && gpause="ACTIVE"
vpn="up"; [[ -f "$STATE_DIR/vpn_down" ]] && vpn="DOWN"
halt="none"; [[ -f "$STATE_DIR/v3_halt" ]] && halt="$(head -c 200 "$STATE_DIR/v3_halt" 2>/dev/null)"
maint="off"; [[ -f "$STATE_DIR/maintenance" ]] && maint="ON"

# verdict health + precision (SQLite truth)
acc="{}"; [[ -f "$V3_DB" ]] && acc="$(V3_DB="$V3_DB" python3 "$STATE_PY" ai-accuracy 2>/dev/null || echo '{}')"
[[ -n "$acc" ]] || acc="{}"

# failures / backoffs (SQLite)
fails="[]"
if [[ -f "$V3_DB" ]]; then
  fails="$(V3_DB="$V3_DB" python3 - <<'PY' 2>/dev/null || echo '[]'
import os,sqlite3,json
try:
    c=sqlite3.connect(os.environ["V3_DB"]); c.row_factory=sqlite3.Row
    r=[dict(x) for x in c.execute("SELECT pattern_type,target,count,recovery_state FROM failure_patterns WHERE recovery_state IN ('backoff','halted') ORDER BY last_at DESC LIMIT 15")]
    print(json.dumps(r))
except Exception: print('[]')
PY
)"
fi
[[ -n "$fails" ]] || fails="[]"

# recent daemon errors/warnings
derr="$(tail -n 250 "$LOG_DIR/recon_daemon.log" 2>/dev/null | grep -iE 'error|fail|halt|ban|forbidden|429|403' | grep -viE 'no error|0 error' | tail -12 | sed 's/"/'"'"'/g')"

telemetry="$(jq -nc \
  --arg now "$now_iso" --arg vpn "$vpn" --arg halt "$halt" --arg maint "$maint" --arg gpause "$gpause" \
  --argjson probes "${probes_1h:-0}" --argjson blocks "${blocks_1h:-0}" --argjson cooldowns "${cooldowns:-0}" \
  --argjson acc "$acc" --argjson fails "$fails" --arg derr "$derr" \
  '{generated_at:$now, vpn:$vpn, maintenance:$maint, halt:$halt,
    probing:{probes_last_1h:$probes, blocked_responses_1h:$blocks, host_cooldowns_active:$cooldowns, global_pause:$gpause},
    verdict_health:$acc, active_failures:$fails, recent_daemon_errors:($derr|split("\n"))}' 2>/dev/null || echo '{}')"

[[ -n "$telemetry" && "$telemetry" != "{}" ]] || { warn "no telemetry gathered — skipping"; exit 0; }

SCHEMA='{"type":"object","additionalProperties":false,"properties":{"health":{"type":"string","enum":["ok","degraded","halted","unknown"]},"burn_risk":{"type":"string","enum":["none","low","elevated","high"]},"summary":{"type":"string"},"guidance":{"type":"array","maxItems":4,"items":{"type":"string"}},"anomalies":{"type":"array","maxItems":4,"items":{"type":"string"}}},"required":["health","burn_risk","summary"]}'

PROMPT="$(cat <<EOF
You are the MONITOR / GUIDANCE enforcer for an autonomous bug-bounty recon pipeline —
a skeptical second set of eyes. From the LOCAL telemetry below (no network access), assess:
- health: ok | degraded | halted
- burn_risk: are we getting rate-limited / WAF-blocked / banned? Weigh blocked_responses_1h
  (429/403/503), host_cooldowns_active, and global_pause. Any of those rising = elevated/high.
- a one-line summary, up to 4 concrete operator GUIDANCE bullets (each checkable/actionable,
  e.g. "global probe pause active — investigate which program returned 403s"), and any anomalies.
Be concrete and skeptical; do not invent problems that the telemetry does not show. If
everything looks nominal, say so plainly and keep guidance minimal.

TELEMETRY:
$telemetry
EOF
)"

out="$(timeout "$CLAUDE_TIMEOUT" "$CLAUDE_BIN" -p "$PROMPT" --model "$CLAUDE_MONITOR_MODEL" --tools "" \
       --no-session-persistence --json-schema "$SCHEMA" --output-format json </dev/null 2>/dev/null)"
so="$(printf '%s' "$out" | jq -c '.structured_output // empty' 2>/dev/null)"
[[ -n "$so" && "$so" != "null" ]] || { warn "no monitor assessment produced"; exit 0; }

# persist + log
printf '%s' "$so" | jq -c --arg t "$now_iso" '. + {at:$t}' > "$OUT" 2>/dev/null || printf '%s\n' "$so" > "$OUT"
health="$(printf '%s' "$so" | jq -r '.health')"; burn="$(printf '%s' "$so" | jq -r '.burn_risk')"
summ="$(printf '%s' "$so" | jq -r '.summary')"
case "$health" in ok) hi="🟢";; degraded) hi="🟡";; halted) hi="🔴";; *) hi="⚪";; esac
case "$burn" in none) bi="🔥none";; low) bi="🔥low";; elevated) bi="🔥ELEVATED";; high) bi="🔥HIGH";; *) bi="🔥?";; esac
log "🧠 ─── CLAUDE MONITOR ─── health=$hi$health · burn=$bi · $summ"
printf '%s' "$so" | jq -r '(.guidance//[])[] | "        ↳ 🧭 \(.)"' 2>/dev/null | while IFS= read -r l; do log "$l"; done
printf '%s' "$so" | jq -r '(.anomalies//[])[] | "        ↳ ⚠️  \(.)"' 2>/dev/null | while IFS= read -r l; do log "$l"; done

# post a compact card to #ops (only when not nominal, to avoid noise)
if [[ "$health" != "ok" || "$burn" != "none" ]]; then
  oh="$(discord_hook ops 2>/dev/null || true)"
  if [[ -n "$oh" ]]; then
    msg="$(printf '%s' "$so" | jq -r --arg hi "$hi" --arg bi "$bi" \
      '"\($hi) **pipeline \(.health)** · burn-risk \(.burn_risk)\n\(.summary)" +
       (if (.guidance//[])|length>0 then "\n🧭 " + ((.guidance|join("\n🧭 "))) else "" end) +
       (if (.anomalies//[])|length>0 then "\n⚠️ " + ((.anomalies|join("\n⚠️ "))) else "" end)' 2>/dev/null)"
    [[ -n "$msg" ]] && discord_post "$oh" "$(jq -nc --arg c "$msg" '{content:$c}')" >/dev/null 2>&1 || true
  fi
fi

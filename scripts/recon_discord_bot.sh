#!/usr/bin/env bash
# =============================================================================
# recon_discord_bot.sh — Remote check-in via Discord (outbound poll only)
# SECURITY: No open ports. No inbound connections. Outbound HTTPS only.
#           Commands accepted from ONE whitelisted Discord user ID.
#           Hardcoded command whitelist — no arbitrary shell execution.
# =============================================================================
set -uo pipefail
IFS=$'\n\t'

log()  { printf '[%s BOT] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s BOT WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="$BASE_DIR/state"
LOG_DIR="$BASE_DIR/logs"
LOCK_FILE="$STATE_DIR/discord_bot.lock"
PID_FILE="$STATE_DIR/discord_bot.pid"
BOT_LOG="$LOG_DIR/discord_bot.log"
LAST_MSG_FILE="$STATE_DIR/discord_bot_last_msg.txt"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CTL_SCRIPT="${CTL_SCRIPT:-$SCRIPT_DIR/recon_ctl.sh}"
[[ -f "$CTL_SCRIPT" ]] || CTL_SCRIPT="$HOME/recon_ctl.sh"
source "$SCRIPT_DIR/recon_net.sh"

POLL_INTERVAL=5
RATE_LIMIT_SECS=10
MAX_CHARS=1800

# ---- Load secrets -----------------------------------------------------------
BOT_TOKEN=""
ALLOWED_UID=""
CHANNEL_ID=""
[[ -f "$HOME/.recon_discord_bot" ]]          && BOT_TOKEN="$(tr -d '[:space:]' < "$HOME/.recon_discord_bot")"
[[ -f "$HOME/.recon_discord_allowed_uid" ]]  && ALLOWED_UID="$(tr -d '[:space:]' < "$HOME/.recon_discord_allowed_uid")"
[[ -f "$HOME/.recon_discord_channel_id" ]]   && CHANNEL_ID="$(tr -d '[:space:]' < "$HOME/.recon_discord_channel_id")"

[[ -z "$BOT_TOKEN" ]]   && { echo "Missing ~/.recon_discord_bot"; exit 1; }
[[ -z "$ALLOWED_UID" ]] && { echo "Missing ~/.recon_discord_allowed_uid"; exit 1; }
[[ -z "$CHANNEL_ID" ]]  && { echo "Missing ~/.recon_discord_channel_id"; exit 1; }

API="https://discord.com/api/v10"
HDR=(-H "Authorization: Bot $BOT_TOKEN" -H "Content-Type: application/json")

mkdir -p "$STATE_DIR" "$LOG_DIR"
exec 9>"$LOCK_FILE"; flock -n 9 || { warn "Already running"; exit 0; }
echo $$ > "$PID_FILE"
trap "rm -f '$PID_FILE'" EXIT

# ---- API helpers ------------------------------------------------------------
# v2.5.5: Discord API blocks Tor exits — bot polls + posts go direct, NOT
# via curl_net. The bot communicates with our own Discord channel; it
# never touches a bug-bounty target, so bypassing Tor is correct.
api_get()  { curl_direct -fsS -m 10 "${HDR[@]}" "$API$1" 2>/dev/null; }
api_post() { curl_direct -fsS -m 10 "${HDR[@]}" -X POST -d "$2" "$API$1" 2>/dev/null; }
# v2.5.4 with v2.5.5 fix: same direct curl, with HTTP-code capture.
api_get_with_code() {
  local code
  code="$(curl_direct -fsS -m 10 -o /tmp/_bot_resp.$$ -w '%{http_code}' "${HDR[@]}" "$API$1" 2>/dev/null || echo 000)"
  if [[ "$code" =~ ^2 ]]; then
    cat /tmp/_bot_resp.$$ 2>/dev/null
    rm -f /tmp/_bot_resp.$$
    return 0
  else
    local snippet; snippet="$(head -c 200 /tmp/_bot_resp.$$ 2>/dev/null | tr -d '\n')"
    rm -f /tmp/_bot_resp.$$
    printf 'HTTP=%s %s' "$code" "$snippet" >&2
    return 1
  fi
}

# Send embed to channel
# Colors: green=3066993 blue=3447003 orange=15105570 red=15158332 grey=9807270
send() {
    local title="$1" body="$2" color="${3:-3447003}"

    # Strip secrets from output
    body="$(printf '%s' "$body" | sed \
        -e 's/password=[^ ]*/password=REDACTED/gi' \
        -e 's/PASS=[^ ]*/PASS=REDACTED/gi' \
        -e 's/TOKEN=[^ ]*/TOKEN=REDACTED/gi' \
        -e 's|https://discord.com/api/webhooks/[^ ]*|WEBHOOK_REDACTED|g')"

    # Truncate
    if [[ ${#body} -gt $MAX_CHARS ]]; then
        body="${body:0:$MAX_CHARS}"$'\n...(truncated)'
    fi

    # Build embed — jq handles escaping and newlines correctly
    local payload
    payload="$(jq -n \
        --arg t "$title" \
        --arg d "$body" \
        --argjson c "$color" \
        --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        '{embeds:[{title:$t, description:$d, color:$c,
           footer:{text:"recon-bot"}, timestamp:$ts}]}')"
    api_post "/channels/$CHANNEL_ID/messages" "$payload" >/dev/null
}

ok()   { send "$1" "$2" 3066993;  }  # green
info() { send "$1" "$2" 3447003;  }  # blue
warn_d(){ send "$1" "$2" 15105570; } # orange
err()  { send "$1" "$2" 15158332; }  # red

run_ctl() { bash "$CTL_SCRIPT" "$@" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' || true; }

# ---- Commands ---------------------------------------------------------------
cmd_help() {
    info "Commands" "$(cat << 'EOF'
!status          daemon + queue + ES summary
!health          full health check
!queue           queue file counts
!top [N]         top N targets (default 10, max 20)
!vuln            passive vuln intelligence + race queue
!ai              AI review status and pending packet counts
!takeovers       high-confidence takeover candidates
!watching        medium-confidence watching list
!logs [N]        last N daemon log lines (default 20)
!mode            show current mode
!mode boost      switch to faster mode
!mode browse     switch to polite mode
!clean           archive stale sent spool and old done files
!start           start daemon if stopped
!stop            stop daemon
!rescue          automated rescue attempt
!help            this list
EOF
)"
}

cmd_status() {
    ok "Status" "$(run_ctl status)"
}

cmd_health() {
    ok "Health" "$(run_ctl health)"
}

cmd_queue() {
    info "Queue" "$(run_ctl queue)"
}

cmd_top() {
    local n="${1:-10}"
    [[ "$n" =~ ^[0-9]+$ ]] || n=10
    [[ "$n" -gt 20 ]] && n=20
    info "Top $n targets" "$(run_ctl top "$n")"
}

cmd_ai() {
    info "AI review layer" "$(run_ctl ai)"
}

cmd_vuln() {
    info "Vuln intelligence" "$(run_ctl vuln status)"
}

cmd_takeovers() {
    local f="$BASE_DIR/firstblood/takeovers_to_claim.tsv"
    if [[ ! -s "$f" ]]; then
        info "Takeovers" "No CLAIM candidates yet."
        return
    fi
    local out
    out="$(tail -20 "$f" | awk -F'\t' '{printf "%s\n  %s via %s [%s]\n  %s\n\n", $2, $3, $4, $5, $7}')"
    ok "CLAIM list (top 20)" "$out"
}

cmd_watching() {
    local f="$BASE_DIR/firstblood/takeovers_watching.tsv"
    if [[ ! -s "$f" ]]; then
        info "Watching" "Empty."
        return
    fi
    local out
    out="$(tail -20 "$f" | awk -F'\t' '{printf "%s  %s -> %s [%s]\n", $1, $2, $3, $5}')"
    info "WATCH list" "$out"
}

cmd_logs() {
    local n="${1:-20}"
    [[ "$n" =~ ^[0-9]+$ ]] || n=20
    [[ "$n" -gt 50 ]] && n=50
    local out
    out="$(tail -n "$n" "$LOG_DIR/recon_daemon.log" 2>/dev/null || echo "(no log)")"
    info "Daemon log (last $n)" "$out"
}

cmd_mode() {
    local m="${1:-}"
    if [[ -z "$m" ]]; then
        info "Mode" "Current: $(cat "$HOME/.recon_mode" 2>/dev/null || echo browse)"
        return
    fi
    [[ "$m" == "night" ]] && m="boost"
    case "$m" in
        browse|boost)
            echo "$m" > "$HOME/.recon_mode"
            ok "Mode" "Switched to $m (effective next cycle)"
            ;;
        *) err "Mode" "Usage: !mode browse|boost" ;;
    esac
}

cmd_start() {
    local pid_file="$STATE_DIR/recon_daemon.pid"
    if [[ -s "$pid_file" ]] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
        warn_d "Start" "Already running (pid $(cat "$pid_file"))"
        return
    fi
    run_ctl start >/dev/null
    sleep 2
    if [[ -s "$pid_file" ]] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
        ok "Started" "Daemon running (pid $(cat "$pid_file"))"
    else
        err "Start failed" "Daemon did not start. Check !logs."
    fi
}

cmd_stop() {
    run_ctl stop >/dev/null
    warn_d "Stopped" "Daemon stopped. Use !start to restart."
}

cmd_clean() {
    ok "Cleanup" "$(run_ctl clean)"
}

cmd_rescue() {
    warn_d "Rescue" "Starting rescue attempt..."
    local lines=()
    local all_ok=true

    # ES check
    local ep
    ep="$(tr -d '[:space:]' < "$HOME/.recon_es_pass" 2>/dev/null || true)"
    if curl -fsS -m 5 -u "elastic:$ep" "http://127.0.0.1:9200/_cluster/health" >/dev/null 2>&1; then
        lines+=("[OK] ES reachable")
    else
        lines+=("[FAIL] ES unreachable - check Docker on Windows")
        all_ok=false
    fi

    # Kill hung httpx (>30min)
    local hung
    hung="$(ps -eo pid,etimes,comm 2>/dev/null | awk '$2>1800 && $3=="httpx"{print $1}' || true)"
    if [[ -n "$hung" ]]; then
        echo "$hung" | xargs kill -KILL 2>/dev/null || true
        lines+=("[FIXED] Killed hung httpx: $hung")
    else
        lines+=("[OK] No hung httpx")
    fi

    # Kill hung subfinder (>2h)
    hung="$(ps -eo pid,etimes,comm 2>/dev/null | awk '$2>7200 && $3=="subfinder"{print $1}' || true)"
    if [[ -n "$hung" ]]; then
        echo "$hung" | xargs kill -KILL 2>/dev/null || true
        lines+=("[FIXED] Killed hung subfinder: $hung")
    else
        lines+=("[OK] No hung subfinder")
    fi

    # Clear stale locks
    local cleared=0
    for lock in "$STATE_DIR"/*.lock; do
        [[ -f "$lock" ]] || continue
        local lname; lname="$(basename "$lock" .lock)"
        local pid_f="$STATE_DIR/${lname}.pid"
        if [[ -f "$pid_f" ]]; then
            local lpid; lpid="$(cat "$pid_f" 2>/dev/null || true)"
            [[ -n "$lpid" ]] && kill -0 "$lpid" 2>/dev/null && continue
        fi
        rm -f "$lock" "$pid_f" 2>/dev/null || true
        cleared=$((cleared+1))
    done
    [[ "$cleared" -gt 0 ]] && lines+=("[FIXED] Cleared $cleared stale locks") \
                           || lines+=("[OK] No stale locks")

    # Move stuck processing files back to inbox
    local stuck
    stuck="$(find "$BASE_DIR/queue/processing" -name '*.txt' -mmin +30 2>/dev/null | wc -l | tr -d ' ')"
    if [[ "$stuck" -gt 0 ]]; then
        find "$BASE_DIR/queue/processing" -name '*.txt' -mmin +30 \
            -exec mv {} "$BASE_DIR/queue/inbox/" \; 2>/dev/null || true
        lines+=("[FIXED] Moved $stuck stuck files back to inbox")
    else
        lines+=("[OK] No stuck processing files")
    fi

    # Restart daemon if down
    local pid_file="$STATE_DIR/recon_daemon.pid"
    if [[ -s "$pid_file" ]] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
        lines+=("[OK] Daemon running (pid $(cat "$pid_file"))")
    else
        rm -f "$pid_file" 2>/dev/null || true
        run_ctl start >/dev/null
        sleep 3
        if [[ -s "$pid_file" ]] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
            lines+=("[FIXED] Daemon restarted (pid $(cat "$pid_file"))")
        else
            lines+=("[FAIL] Daemon failed to restart")
            all_ok=false
        fi
    fi

    local inbox_n
    inbox_n="$(find "$BASE_DIR/queue/inbox" -name '*.txt' 2>/dev/null | wc -l | tr -d ' ')"
    lines+=("[INFO] Inbox: $inbox_n files")

    local body; body="$(printf '%s\n' "${lines[@]}")"
    if $all_ok; then
        ok "Rescue complete" "$body"
    else
        warn_d "Rescue (issues remain)" "$body"
    fi
}

# ---- Rate limiter -----------------------------------------------------------
LAST_CMD_TIME=0
rate_ok() { (( $(date +%s) - LAST_CMD_TIME >= RATE_LIMIT_SECS )); }
bump_rate() { LAST_CMD_TIME=$(date +%s); }

# ---- Dispatch ---------------------------------------------------------------
dispatch() {
    local content="$1"
    content="$(echo "$content" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [[ "$content" == !* ]] || return 0

    if ! rate_ok; then
        warn_d "Rate limited" "Wait a moment between commands."
        return 0
    fi
    bump_rate

    local cmd arg
    cmd="$(echo "$content" | awk '{print tolower($1)}')"
    arg="$(echo "$content" | sed 's/^[^ ]* *//')"
    [[ "$arg" == "$content" ]] && arg=""

    log "CMD: $cmd${arg:+ ($arg)}"

    case "$cmd" in
        '!help')      cmd_help ;;
        '!status')    cmd_status ;;
        '!health')    cmd_health ;;
        '!queue')     cmd_queue ;;
        '!top')       cmd_top "$arg" ;;
        '!vuln')      cmd_vuln ;;
        '!ai')        cmd_ai ;;
        '!takeovers') cmd_takeovers ;;
        '!watching')  cmd_watching ;;
        '!logs')      cmd_logs "$arg" ;;
        '!mode')      cmd_mode "$arg" ;;
        '!clean')     cmd_clean ;;
        '!start')     cmd_start ;;
        '!stop')      cmd_stop ;;
        '!rescue')    cmd_rescue ;;
        *)            err "Unknown" "Unknown: $cmd — send !help" ;;
    esac
}

# ---- Main polling loop ------------------------------------------------------
main() {
    log "===== Discord bot started (pid $$) ====="
    log "Channel: $CHANNEL_ID"
    log "Allowed UID: $ALLOWED_UID"

    # Announce — use $'...' so \n becomes real newline
    ok "Bot online" $'Recon bot started and polling.\nSend !help to see commands.\nOnly your whitelisted user ID is accepted.'

    # Seed watermark to avoid replaying old commands on restart
    local last_msg_id=""
    if [[ -s "$LAST_MSG_FILE" ]]; then
        last_msg_id="$(cat "$LAST_MSG_FILE")"
    else
        local seed
        seed="$(api_get "/channels/$CHANNEL_ID/messages?limit=1" | jq -r '.[0].id // empty' 2>/dev/null || true)"
        [[ -n "$seed" ]] && last_msg_id="$seed"
        echo "$last_msg_id" > "$LAST_MSG_FILE"
    fi

    log "Starting from message ID: ${last_msg_id:-(beginning)}"

    while :; do
        sleep "$POLL_INTERVAL"

        local url="/channels/$CHANNEL_ID/messages?limit=10"
        [[ -n "$last_msg_id" ]] && url+="&after=$last_msg_id"

        local resp err
        err="$(mktemp)"
        if ! resp="$(api_get_with_code "$url" 2>"$err")"; then
          warn "Poll failed: $(cat "$err" 2>/dev/null | head -1)"
          rm -f "$err"
          # Back off on 429 rate-limit
          if grep -q 'HTTP=429' "$err" 2>/dev/null; then sleep 30; fi
          continue
        fi
        rm -f "$err"

        local messages
        messages="$(echo "$resp" | jq -c 'if type=="array" then sort_by(.id)[] else empty end' 2>/dev/null)" || continue
        [[ -z "$messages" ]] && continue

        while IFS= read -r msg; do
            [[ -z "$msg" ]] && continue
            local msg_id author_id content bot_flag
            msg_id="$(echo "$msg"    | jq -r '.id // empty')"
            author_id="$(echo "$msg" | jq -r '.author.id // empty')"
            content="$(echo "$msg"   | jq -r '.content // empty')"
            bot_flag="$(echo "$msg"  | jq -r '.author.bot // false')"

            [[ -z "$msg_id" ]] && continue

            # Always advance watermark
            last_msg_id="$msg_id"
            echo "$last_msg_id" > "$LAST_MSG_FILE"

            # Skip bot messages (including our own responses)
            [[ "$bot_flag" == "true" ]] && continue

            # Auth check — log what we see vs what we expect
            if [[ "$author_id" != "$ALLOWED_UID" ]]; then
                if [[ "$content" == !* ]]; then
                    log "Rejected command from uid=$author_id (expected=$ALLOWED_UID)"
                    # Vague response — confirms bot alive but not which UID is whitelisted
                    err "Unauthorised" "This user ID is not authorised."
                fi
                continue
            fi

            [[ -z "$content" ]] && continue
            dispatch "$content"

        done <<< "$messages"
    done
}

{
    main "$@"
} 2>&1 | tee -a "$BOT_LOG"

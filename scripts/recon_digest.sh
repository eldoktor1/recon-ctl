#!/usr/bin/env bash
# =============================================================================
# recon_digest.sh — Daily pipeline summary via Discord
#
# Fires once per day (daemon interval 86400s). Queries ES for the last 24h
# of activity and posts one structured embed to the #health channel.
# Gives the operator a single-glance daily brief without tailing logs.
#
# CONTENT
#   New P0 hosts found in last 24h + total P0 count
#   New P1 hosts found in last 24h
#   Critical port scanner finds (last 24h)
#   Bypass confirmations (last 24h)
#   Queue depth (inbox + processing)
#   Total indexed hosts
#   Active killswitches (if any)
#   Last ingest timestamp (freshness check)
#
# CHANNEL: health   (reads ~/.recon_discord_health)
# =============================================================================
set -uo pipefail
IFS=$'\n\t'

log() { printf '[%s DIGEST] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/recon_net.sh"
setup_es_netrc
ES_AUTH=(--netrc-file "$HOME/.recon_es_netrc")

BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"
INDEX_NAME="${INDEX_NAME:-recon_alive}"

WINDOW="now-24h"

ec() { curl -sS -m20 "${ES_AUTH[@]}" -H 'Content-Type: application/json' "$@"; }

_count() {
  # _count <filter_json>  — returns integer from _count endpoint.
  # Body is {"query":{"bool":{"filter":[ <filters> ]}}} — three opening braces,
  # three closing. The original draft was missing the final "}" so every count
  # came back 0 (silent failure: jq saw "error" and emitted 0).
  ec -X POST "$ES_URL/$INDEX_NAME/_count" -d "{\"query\":{\"bool\":{\"filter\":[$1]}}}" \
    2>/dev/null | jq -r '.count // 0'
}

# ── Gather stats ──────────────────────────────────────────────────────────────

new_p0="$(_count "{\"term\":{\"triage_priority\":\"P0\"}},{\"range\":{\"first_seen\":{\"gte\":\"$WINDOW\"}}}")"
new_p1="$(_count "{\"term\":{\"triage_priority\":\"P1\"}},{\"range\":{\"first_seen\":{\"gte\":\"$WINDOW\"}}}")"

total_p0="$(ec -X POST "$ES_URL/$INDEX_NAME/_count" \
  -d '{"query":{"term":{"triage_priority":"P0"}}}' \
  2>/dev/null | jq -r '.count // 0')"

total_p1="$(ec -X POST "$ES_URL/$INDEX_NAME/_count" \
  -d '{"query":{"term":{"triage_priority":"P1"}}}' \
  2>/dev/null | jq -r '.count // 0')"

port_critical="$(_count "{\"term\":{\"portscan_critical\":true}},{\"range\":{\"portscan_at\":{\"gte\":\"$WINDOW\"}}}")"

bypass_new="$(_count "{\"term\":{\"bypass_confirmed\":true}},{\"range\":{\"bypass_at\":{\"gte\":\"$WINDOW\"}}}")"

exposure_new="$(_count "{\"exists\":{\"field\":\"exposure_nuclei_template\"}},{\"range\":{\"exposure_scan_at\":{\"gte\":\"$WINDOW\"}}}")"

# Queue depth
inbox_count="$(ls "$BASE_DIR/queue/inbox/"*.txt 2>/dev/null | wc -l | tr -d ' ')"
proc_count="$(ls "$BASE_DIR/queue/processing/"*.txt 2>/dev/null | wc -l | tr -d ' ')"

total_hosts="$(ec -X POST "$ES_URL/$INDEX_NAME/_count" -d '{"query":{"match_all":{}}}' \
  2>/dev/null | jq -r '.count // 0')"

# Active killswitches
ks_list=""
shopt -s nullglob
for ks_file in "$STATE_DIR/kill/v2_"*; do
  [[ -f "$ks_file" ]] && ks_list="${ks_list}  \`$(basename "$ks_file")\`"
done
shopt -u nullglob
ks_list="${ks_list#  }"
[[ -z "$ks_list" ]] && ks_list="none"

# Last ingest
last_ingest="$(ec -X POST "$ES_URL/$INDEX_NAME/_search" \
  -d '{"size":1,"_source":["first_seen"],"sort":[{"first_seen":{"order":"desc"}}]}' \
  2>/dev/null | jq -r '.hits.hits[0]._source.first_seen // "unknown"')"

# ── Build and send embed ──────────────────────────────────────────────────────
hook="$(discord_hook digest)"
if [[ -z "$hook" ]]; then
  log "No health webhook configured — digest not sent (set ~/.recon_discord_health)"
  exit 0
fi

ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
date_label="$(date -u '+%a %d %b %Y, %H:%M UTC')"

# Emoji decorators for active signals
p0_em="";     [[ "$new_p0"     -gt 0 ]] && p0_em=" 🔴"
port_em="";   [[ "$port_critical" -gt 0 ]] && port_em=" 🚨"
bypass_em=""; [[ "$bypass_new"  -gt 0 ]] && bypass_em=" 💥"
exp_em="";    [[ "$exposure_new" -gt 0 ]] && exp_em=" 🧪"
ks_em="";     [[ "$ks_list" != "none" ]] && ks_em=" ⚠️"

color=3447003   # blue (healthy); turn orange if P0s found
[[ "$new_p0" -gt 0 ]] && color=15105570   # orange

payload="$(jq -nc \
  --arg ts "$ts" \
  --arg date_label "$date_label" \
  --arg new_p0 "$new_p0" \
  --arg new_p1 "$new_p1" \
  --arg total_p0 "$total_p0" \
  --arg total_p1 "$total_p1" \
  --arg port_critical "$port_critical" \
  --arg bypass_new "$bypass_new" \
  --arg exposure_new "$exposure_new" \
  --arg inbox_count "$inbox_count" \
  --arg proc_count "$proc_count" \
  --arg total_hosts "$total_hosts" \
  --arg ks_list "$ks_list" \
  --arg last_ingest "$last_ingest" \
  --arg p0_em "$p0_em" \
  --arg port_em "$port_em" \
  --arg bypass_em "$bypass_em" \
  --arg exp_em "$exp_em" \
  --arg ks_em "$ks_em" \
  --argjson color "$color" '{
    embeds: [{
      title: ("📊 Daily Recon Digest — " + $date_label),
      color: $color,
      fields: [
        {name: ("New Leads (24h)" + $p0_em),
         value: ($new_p0 + " P0  /  " + $new_p1 + " P1  |  totals: " + $total_p0 + " P0, " + $total_p1 + " P1"),
         inline: false},
        {name: ("Critical Ports (24h)" + $port_em),
         value: ($port_critical + " critical service(s) found"),
         inline: true},
        {name: ("Access Bypass (24h)" + $bypass_em),
         value: ($bypass_new + " confirmed bypass(es)"),
         inline: true},
        {name: ("Exposure Scan (24h)" + $exp_em),
         value: ($exposure_new + " exposed file/config finding(s)"),
         inline: true},
        {name: "Queue",
         value: ($inbox_count + " inbox  /  " + $proc_count + " processing"),
         inline: true},
        {name: "Index",
         value: ($total_hosts + " hosts"),
         inline: true},
        {name: ("Killswitches" + $ks_em),
         value: $ks_list,
         inline: false},
        {name: "Last Ingest",
         value: $last_ingest,
         inline: false}
      ],
      footer: {text: "recon-pipeline · run recon-health for full status"},
      timestamp: $ts
    }]
  }')"

if discord_post "$hook" "$payload"; then
  log "Daily digest sent (${new_p0} new P0, ${port_critical} critical ports, ${bypass_new} bypasses)"
else
  log "Discord post failed"
  exit 1
fi

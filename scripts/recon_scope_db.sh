#!/usr/bin/env bash
# =============================================================================
# recon_scope_db.sh — Fetch and normalize scope from H1/Bugcrowd/Intigriti/YWH/Federacy
# =============================================================================

set -uo pipefail
IFS=$'\n\t'

log()  { printf '[%s SCOPE] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s SCOPE WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
die()  { printf '[%s SCOPE ERROR] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; exit 1; }

for c in curl jq; do command -v "$c" >/dev/null || die "missing: $c"; done
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/recon_net.sh"

SCOPE_DIR="${SCOPE_DIR:-$HOME/recon/scope}"
RAW_DIR="$SCOPE_DIR/raw"
KILL_DIR="${HOME}/recon/state/kill"
KILL_FILE="$KILL_DIR/v2_scope"
LOCK_FILE="${HOME}/recon/state/scope_db.lock"

mkdir -p "$SCOPE_DIR" "$RAW_DIR" "$KILL_DIR" "$(dirname "$LOCK_FILE")"

[[ -f "$KILL_FILE" ]] && { warn "killed: $(cat "$KILL_FILE")"; exit 0; }

exec 9>"$LOCK_FILE"
flock -n 9 || { log "already running"; exit 0; }

BASE="https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data"

declare -A FEEDS=(
  [hackerone]="$BASE/hackerone_data.json"
  [bugcrowd]="$BASE/bugcrowd_data.json"
  [intigriti]="$BASE/intigriti_data.json"
  [yeswehack]="$BASE/yeswehack_data.json"
  [federacy]="$BASE/federacy_data.json"
)

log "Fetching scope feeds"
for platform in "${!FEEDS[@]}"; do
  url="${FEEDS[$platform]}"
  out="$RAW_DIR/${platform}.json"
  if curl_net -fsSL -m 60 "$url" -o "${out}.tmp" 2>/dev/null; then
    if jq -e 'type == "array" and length > 0' "${out}.tmp" >/dev/null 2>&1; then
      mv "${out}.tmp" "$out"
      log "  ok ${platform} ($(jq 'length' "$out") items)"
    else
      warn "  invalid JSON ${platform}"; rm -f "${out}.tmp"
    fi
  else
    warn "  fail ${platform}"; rm -f "${out}.tmp"
  fi
done

PROGRAMS_JSON="$SCOPE_DIR/programs.json"
INSCOPE_TSV="$SCOPE_DIR/inscope_patterns.tsv"
OUTSCOPE_TSV="$SCOPE_DIR/outscope_patterns.tsv"
TMP_NORM="$RAW_DIR/.normalized.jsonl"
: > "$TMP_NORM"

log "Normalizing programs"

# =============================================================================
# Payout-tier helper (jq fragment)
#
#   none  : pays=false
#   low   : pays=true, max_bounty < 500
#   mid   : 500 - 2999, OR pays=true with unknown amount (default for h1/federacy
#           which only expose offers_bounties bool)
#   high  : 3000 - 9999
#   elite : >= 10000
#
# Used by every normalizer below. Inputs $pays (bool) and $mb (number, 0 if unknown).
# =============================================================================
TIER_FRAG='
def tier($pays; $mb):
  if ($pays | not) then "none"
  elif ($mb // 0) >= 10000 then "elite"
  elif ($mb // 0) >=  3000 then "high"
  elif ($mb // 0) >=   500 then "mid"
  elif ($mb // 0) >      0 then "low"
  else "mid" end;
'

# ---- HackerOne (h1 only exposes offers_bounties bool — tier=mid when paying) ----
if [[ -s "$RAW_DIR/hackerone.json" ]]; then
  jq -c "$TIER_FRAG"' .[] | select(.handle != null) |
    ((.offers_bounties // false) == true) as $pays |
    0 as $mb |
    {
      handle: .handle,
      name: (.name // .handle),
      platform: "hackerone",
      url: ("https://hackerone.com/" + .handle),
      pays: $pays,
      max_bounty: $mb,
      payout_tier: tier($pays; $mb),
      in_scope: [
        .targets.in_scope[]?
        | select(.asset_type == "URL" or .asset_type == "WILDCARD")
        | .asset_identifier
        | select(. != null and . != "")
      ],
      out_scope: [
        .targets.out_of_scope[]?
        | select(.asset_type == "URL" or .asset_type == "WILDCARD")
        | .asset_identifier
        | select(. != null and . != "")
      ]
    }' "$RAW_DIR/hackerone.json" 2>/dev/null >> "$TMP_NORM" || warn "h1 normalize errors"
fi

# ---- Bugcrowd (max_payout numeric) -----------------------------------------
if [[ -s "$RAW_DIR/bugcrowd.json" ]]; then
  jq -c "$TIER_FRAG"' .[] |
    (((.max_payout // 0) | tonumber? // 0)) as $mb |
    ($mb > 0) as $pays |
    {
      handle: (.code // .name | tostring),
      name: (.name // .code | tostring),
      platform: "bugcrowd",
      url: (.url // ""),
      pays: $pays,
      max_bounty: $mb,
      payout_tier: tier($pays; $mb),
      in_scope: [
        (.targets.in_scope // [])[]
        | (if type == "string" then . else (.target // .uri // .name // "") end)
        | select(. != null and . != "")
      ],
      out_scope: [
        (.targets.out_of_scope // [])[]
        | (if type == "string" then . else (.target // .uri // .name // "") end)
        | select(. != null and . != "")
      ]
    }' "$RAW_DIR/bugcrowd.json" 2>/dev/null >> "$TMP_NORM" || warn "bc normalize errors"
fi

# ---- Intigriti — FIXED with real schema -------------------------------------
# Real fields: handle, name, url, status, max_bounty.value (object), targets.in_scope[].endpoint
if [[ -s "$RAW_DIR/intigriti.json" ]]; then
  jq -c "$TIER_FRAG"' .[] | select(.handle != null) |
    (((.max_bounty.value // 0) | tonumber? // 0)) as $mb |
    ($mb > 0) as $pays |
    {
      handle: .handle,
      name: (.name // .handle),
      platform: "intigriti",
      url: (.url // ""),
      pays: $pays,
      max_bounty: $mb,
      payout_tier: tier($pays; $mb),
      in_scope: [
        .targets.in_scope[]?
        | select(.type == "url" or .type == "wildcard" or .type == "api")
        | .endpoint
        | select(. != null and . != "")
      ],
      out_scope: [
        (.targets.out_of_scope // [])[]?
        | (if type == "string" then . else (.endpoint // "") end)
        | select(. != null and . != "")
      ]
    }' "$RAW_DIR/intigriti.json" 2>/dev/null >> "$TMP_NORM" || warn "intigriti normalize errors"
  # Confirm count
  ic="$(jq -c 'select(.platform == "intigriti")' "$TMP_NORM" 2>/dev/null | wc -l)"
  log "  intigriti: $ic normalized"
fi

# ---- YesWeHack — FIXED with real schema -------------------------------------
# Real fields: id, name, public, max_bounty (number), targets.in_scope[].target with type
if [[ -s "$RAW_DIR/yeswehack.json" ]]; then
  jq -c "$TIER_FRAG"' .[] | select(.id != null) |
    (((.max_bounty // 0) | tonumber? // 0)) as $mb |
    ($mb > 0) as $pays |
    {
      handle: (.id | tostring),
      name: (.name | tostring),
      platform: "yeswehack",
      url: ("https://yeswehack.com/programs/" + (.id | tostring)),
      pays: $pays,
      max_bounty: $mb,
      payout_tier: tier($pays; $mb),
      in_scope: [
        .targets.in_scope[]?
        | select(.type == "web-application" or .type == "api" or .type == "website" or .type == null)
        | .target
        | select(. != null and . != "")
      ],
      out_scope: [
        (.targets.out_of_scope // [])[]?
        | (if type == "string" then . else (.target // "") end)
        | select(. != null and . != "")
      ]
    }' "$RAW_DIR/yeswehack.json" 2>/dev/null >> "$TMP_NORM" || warn "ywh normalize errors"
  yc="$(jq -c 'select(.platform == "yeswehack")' "$TMP_NORM" 2>/dev/null | wc -l)"
  log "  yeswehack: $yc normalized"
fi

# ---- Federacy — FIXED with real schema --------------------------------------
# Real fields: id, name, offers_awards, targets.in_scope[].target with type
if [[ -s "$RAW_DIR/federacy.json" ]]; then
  jq -c "$TIER_FRAG"' .[] | select(.id != null) |
    ((.offers_awards // false) == true) as $pays |
    0 as $mb |
    {
      handle: (.id | tostring),
      name: (.name | tostring),
      platform: "federacy",
      url: (.url // ""),
      pays: $pays,
      max_bounty: $mb,
      payout_tier: tier($pays; $mb),
      in_scope: [
        .targets.in_scope[]?
        | select(.type == "website" or .type == "url" or .type == "api" or .type == null)
        | .target
        | select(. != null and . != "")
      ],
      out_scope: [
        (.targets.out_of_scope // [])[]?
        | (if type == "string" then . else (.target // "") end)
        | select(. != null and . != "")
      ]
    }' "$RAW_DIR/federacy.json" 2>/dev/null >> "$TMP_NORM" || warn "federacy normalize errors"
  fc="$(jq -c 'select(.platform == "federacy")' "$TMP_NORM" 2>/dev/null | wc -l)"
  log "  federacy: $fc normalized"
fi

# =============================================================================
# Combine + sanity gate
# =============================================================================
COUNT="$(wc -l < "$TMP_NORM" | tr -d ' ')"
log "Total normalized: $COUNT"

MIN=500
if [[ "$COUNT" -lt "$MIN" ]]; then
  if [[ -s "$PROGRAMS_JSON" ]]; then
    PREV="$(jq 'length' "$PROGRAMS_JSON")"
    warn "Got $COUNT (< $MIN) — keeping previous $PREV"
    rm -f "$TMP_NORM"
    exit 0
  fi
fi

jq -s '.' "$TMP_NORM" > "$PROGRAMS_JSON.tmp"
if jq -e 'type == "array" and length > 0' "$PROGRAMS_JSON.tmp" >/dev/null 2>&1; then
  mv "$PROGRAMS_JSON.tmp" "$PROGRAMS_JSON"
  log "Programs loaded: $(jq 'length' "$PROGRAMS_JSON")"
else
  warn "Final JSON invalid"
  rm -f "$PROGRAMS_JSON.tmp"
  exit 1
fi
rm -f "$TMP_NORM"

# Pattern tables
log "Building pattern tables"
# TSV columns (5):  pattern  handle  platform  pays  payout_tier
# Old consumers (pre-v2.2) reading 4 columns still work — extra column is appended.
jq -r '.[] |
  . as $p |
  ($p.in_scope // [])[] |
  select(. != null and . != "") |
  [
    (. | ascii_downcase | sub("^https?://"; "") | sub("/.*$"; "")),
    $p.handle, $p.platform, ($p.pays | tostring),
    ($p.payout_tier // (if $p.pays then "mid" else "none" end))
  ] | @tsv
' "$PROGRAMS_JSON" | sort -u > "$INSCOPE_TSV"

jq -r '.[] |
  . as $p |
  ($p.out_scope // [])[] |
  select(. != null and . != "") |
  [
    (. | ascii_downcase | sub("^https?://"; "") | sub("/.*$"; "")),
    $p.handle, $p.platform
  ] | @tsv
' "$PROGRAMS_JSON" | sort -u > "$OUTSCOPE_TSV"

log "Patterns: in_scope=$(wc -l < "$INSCOPE_TSV") out_scope=$(wc -l < "$OUTSCOPE_TSV")"

# Per-platform stats
jq -r '
  group_by(.platform) | map({
    platform: .[0].platform,
    count: length,
    paying: [.[] | select(.pays == true)] | length
  }) | .[] | "\(.platform): \(.count) total, \(.paying) paying"
' "$PROGRAMS_JSON" 2>/dev/null | while read -r line; do log "  $line"; done

# Payout-tier distribution
jq -r '
  group_by(.payout_tier // "none") | map({
    tier: (.[0].payout_tier // "none"),
    count: length
  }) | sort_by(
    if .tier == "elite" then 0
    elif .tier == "high"  then 1
    elif .tier == "mid"   then 2
    elif .tier == "low"   then 3
    else 4 end
  ) | .[] | "tier=\(.tier): \(.count)"
' "$PROGRAMS_JSON" 2>/dev/null | while read -r line; do log "  $line"; done

log "Scope DB build complete"

#!/usr/bin/env bash
# =============================================================================
# recon_takeover_hunter.sh — Real-time subdomain takeover detector
# =============================================================================
# DESIGN GOALS
#   - First-blood: detect & notify within minutes of dangling CNAME appearing
#   - Zero false positives: 5-stage verification before notification
#   - Provider-specific claim instructions baked in
#   - Multi-resolver to defeat DNS flake
#   - Persistent state for dedup
#   - Bypasses normal triage queue — URGENT path direct to Discord
#
# USAGE
#   stream mode:  recon_takeover_hunter.sh stream <jsonl>   (one-shot from file)
#   watch mode:   recon_takeover_hunter.sh watch            (loops on inbox/done)
#   recheck:      recon_takeover_hunter.sh recheck          (re-verifies WATCHING)
#   manual:       recon_takeover_hunter.sh check <host>     (single host probe)
#
# OUTPUTS
#   ~/recon/firstblood/takeovers_to_claim.tsv      HIGH/CRITICAL — claim NOW
#   ~/recon/firstblood/takeovers_watching.tsv      MEDIUM — periodic recheck
#   ~/recon/firstblood/takeovers_seen.txt          dedup state
#   ~/recon/firstblood/takeovers.log               structured event log
#   Discord: URGENT embeds with claim instructions
# =============================================================================

set -uo pipefail
IFS=$'\n\t'

# ---- Logging --------------------------------------------------------------
log()  { printf '[%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
die()  { printf '[%s FATAL] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; exit 1; }

# ---- Config ---------------------------------------------------------------
BASE_DIR="${BASE_DIR:-$HOME/recon}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"
INDEX_NAME="${INDEX_NAME:-recon_alive}"
FB_DIR="${FB_DIR:-$BASE_DIR/firstblood}"
STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
LOG_DIR="${LOG_DIR:-$BASE_DIR/logs}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/recon_net.sh"
setup_es_netrc
ES_AUTH=(--netrc-file "$HOME/.recon_es_netrc")

CLAIM_FILE="$FB_DIR/takeovers_to_claim.tsv"
WATCH_FILE="$FB_DIR/takeovers_watching.tsv"
SEEN_FILE="$FB_DIR/takeovers_seen.txt"
EVENT_LOG="$FB_DIR/takeovers.log"
HUNTER_LOG="$LOG_DIR/takeover_hunter.log"
PID_FILE="$STATE_DIR/takeover_hunter.pid"
LOCK_FILE="$STATE_DIR/takeover_hunter.lock"

# CNAME whitelist (Fix 6) — safe CDN CNAMEs that are never takeovers
CNAME_WHITELIST_FILE="${CNAME_WHITELIST_FILE:-$SCRIPT_DIR/data/cname_whitelist.txt}"

# Fingerprint DB — provider signatures for subdomain takeover detection
FINGERPRINT_DB_FILE="${FINGERPRINT_DB_FILE:-$SCRIPT_DIR/data/takeover_fingerprints.tsv}"

# HackerOne disclosed-report lookup (Fix 7)
HACKERONE_API_TOKEN="${HACKERONE_API_TOKEN:-}"
H1_USERNAME="${H1_USERNAME:-d0k}"   # HackerOne username for API auth

# Resolvers used in parallel — 2-of-3 must agree
RESOLVERS=("1.1.1.1" "8.8.8.8" "9.9.9.9")

# Stability re-check delay (seconds) — kills DNS-flake FPs.
# 30s is enough on a local setup; set to 60+ on cloud/unreliable resolvers.
STABILITY_DELAY="${STABILITY_DELAY:-30}"

# Discord
# Discord: takeover candidates → #takeovers via discord_hook() (recon_net.sh)

# Behaviour toggles
NOTIFY_HIGH="${NOTIFY_HIGH:-1}"        # fire Discord on HIGH/CRITICAL
NOTIFY_MEDIUM="${NOTIFY_MEDIUM:-0}"    # fire Discord on MEDIUM (default off — noise)
HTTP_TIMEOUT="${HTTP_TIMEOUT:-10}"
DIG_TIMEOUT="${DIG_TIMEOUT:-3}"

mkdir -p "$FB_DIR" "$STATE_DIR" "$LOG_DIR" "$(dirname "$CNAME_WHITELIST_FILE")"
touch "$CLAIM_FILE" "$WATCH_FILE" "$SEEN_FILE" "$EVENT_LOG"

for c in dig curl jq awk grep sort head tail flock timeout; do
  command -v "$c" >/dev/null 2>&1 || die "Missing dependency: $c"
done

# =============================================================================
# FINGERPRINT DATABASE -- stored in scripts/data/takeover_fingerprints.tsv
# Format (^-separated): service^cname_regex^nx_trigger^http_regex^status_csv^difficulty^payout^claim
# Edit that file to add or update providers without touching this script.
# =============================================================================

# =============================================================================
# Helper: load fingerprint DB into associative arrays
# =============================================================================
declare -a FP_SVC FP_CNAME FP_NX FP_HTTP FP_STATUS FP_DIFF FP_PAYOUT FP_CLAIM
load_fingerprints() {
  FP_SVC=(); FP_CNAME=(); FP_NX=(); FP_HTTP=(); FP_STATUS=(); FP_DIFF=(); FP_PAYOUT=(); FP_CLAIM=()
  while IFS='^' read -r svc cname nx http status diff payout claim; do
    [[ -z "$svc" || "$svc" =~ ^# ]] && continue
    FP_SVC+=("$svc")
    FP_CNAME+=("$cname")
    FP_NX+=("$nx")
    FP_HTTP+=("$http")
    FP_STATUS+=("$status")
    FP_DIFF+=("$diff")
    FP_PAYOUT+=("$payout")
    FP_CLAIM+=("$claim")
  done < "$FINGERPRINT_DB_FILE"
  log "Loaded ${#FP_SVC[@]} provider fingerprints"

  # Fix 6: load CNAME whitelist
  CNAME_WHITELIST_PATTERNS=()
  if [[ -s "$CNAME_WHITELIST_FILE" ]]; then
    while IFS= read -r line; do
      [[ -z "$line" || "$line" =~ ^# ]] && continue
      # strip leading/trailing spaces, convert glob * to regex .*
      line="$(printf '%s' "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
      local pat; pat="$(printf '%s' "$line" | sed 's/\./\\./g; s/\*/\.\*/g')"
      CNAME_WHITELIST_PATTERNS+=("$pat")
    done < "$CNAME_WHITELIST_FILE"
    log "Loaded ${#CNAME_WHITELIST_PATTERNS[@]} CNAME whitelist patterns"
  fi
}

# Fix 6: check CNAME against whitelist
cname_whitelisted() {
  local cname="$1"
  local pat
  for pat in "${CNAME_WHITELIST_PATTERNS[@]:-}"; do
    [[ -z "$pat" ]] && continue
    if [[ "$cname" =~ $pat ]]; then
      return 0
    fi
  done
  return 1
}

# Fix 5: extract apex/root domain (last two labels, or three for ccTLDs — simplified)
extract_apex() {
  local host="$1"
  # Strip trailing dot
  host="${host%.}"
  # Count labels
  local labels; IFS='.' read -ra labels <<< "$host"
  local n="${#labels[@]}"
  if [[ "$n" -le 2 ]]; then
    printf '%s\n' "$host"
  elif [[ "$n" -eq 3 && "${#labels[-1]}" -le 2 && "${#labels[-2]}" -le 3 ]]; then
    # Likely ccTLD e.g. co.uk — take last 3 labels
    printf '%s\n' "${labels[-3]}.${labels[-2]}.${labels[-1]}"
  else
    printf '%s\n' "${labels[-2]}.${labels[-1]}"
  fi
}

# Fix 3: check if CNAME target is AWS managed load balancer infrastructure
cname_is_aws_elb() {
  local cname="$1"
  [[ "$cname" =~ \.elb\.amazonaws\.com\.?$ ]] && return 0
  [[ "$cname" =~ \.nlb\.amazonaws\.com\.?$ ]] && return 0
  [[ "$cname" =~ \.alb\.amazonaws\.com\.?$ ]] && return 0
  return 1
}

# ---- 99%-FP-free takeover gating (can-i-take-over-xyz authoritative) ----------
# Services marked "Not vulnerable" on can-i-take-over-xyz REQUIRE DNS/file ownership
# verification before any custom domain is served — so a dangling CNAME + provider error
# page is NEVER claimable by an outsider. These are the FP factory (Fastly/Firebase/
# CloudFront/Akamai/...) and must never mint a takeover finding.
TKO_NOTVULN="${TKO_NOTVULN:-fastly firebase aws_cloudfront acquia freshdesk hubspot feedpress fly_io desk_com statuspage gcp_appengine zendesk akamai sendgrid mailchimp dreamhost kinsta instapage keycdn squarespace gcs google_sites gitlab azure_trafficmanager intercom}"
# Services whose HTTP error fingerprint is itself authoritative-unclaimed (the resource
# name is provably free WITHOUT needing NXDOMAIN): S3 "NoSuchBucket", Beanstalk. For
# everyone else, confirmation REQUIRES NXDOMAIN on the CNAME target.
TKO_HTTP_AUTH="${TKO_HTTP_AUTH:-aws_s3 aws_elasticbeanstalk}"
svc_in_list() { local s="$1" l="$2" x; for x in $l; do [[ "$s" == "$x" ]] && return 0; done; return 1; }
# provider's OWN namespace = unclaimable by an outsider (github.github.io is GitHub's own
# org pages; *.map.fastly.net is Fastly's service-map; live *.cloudfront.net 404s at root).
cname_provider_own() {
  local c="${1%.}"
  [[ "$c" == "github.github.io" ]] && return 0
  [[ "$c" =~ \.map\.fastly\.net$ ]] && return 0
  [[ "$c" =~ \.cloudfront\.net$ ]] && return 0
  return 1
}

# Fix 7: check HackerOne disclosed reports for this host
check_already_disclosed() {
  local host="$1"
  [[ -z "$HACKERONE_API_TOKEN" ]] && return 1
  # Search H1 disclosed reports — simplified query (root domain matching)
  local root; root="$(extract_apex "$host")"
  # Write a per-call netrc so the token never appears on the command line
  local _h1rc; _h1rc="$(mktemp)"; chmod 600 "$_h1rc"
  printf 'machine api.hackerone.com\nlogin %s\npassword %s\n' \
    "$H1_USERNAME" "$HACKERONE_API_TOKEN" > "$_h1rc"
  local resp
  resp="$(curl -sS -m10 \
    --netrc-file "$_h1rc" \
    -H "Accept: application/json" \
    "https://api.hackerone.com/v1/hackers/reports?filter[state][]=resolved&filter[keyword][]=${root}&page[size]=1" \
    2>/dev/null)"
  rm -f "$_h1rc"
  local count; count="$(printf '%s' "$resp" | jq -r '.data | length // 0' 2>/dev/null || echo 0)"
  [[ "${count:-0}" -gt 0 ]] && return 0
  return 1
}

# Fix 7: check last_verified timestamp from TSV and return true if >6h old
needs_reverify() {
  local host="$1"
  # Last_verified is the 9th column (epoch) in claim TSV
  local last_epoch
  last_epoch="$(grep -F "$host" "$CLAIM_FILE" 2>/dev/null | tail -1 | awk -F'\t' '{print $9}')"
  [[ -z "$last_epoch" || ! "$last_epoch" =~ ^[0-9]+$ ]] && return 0  # no ts → reverify
  local now_epoch; now_epoch="$(date +%s)"
  local age_h=$(( (now_epoch - last_epoch) / 3600 ))
  [[ "$age_h" -ge 6 ]] && return 0
  return 1
}

# =============================================================================
# DNS via multiple resolvers — return CNAME chain (last hop) and resolution status
# Output (TSV): "<cname_target>\t<resolves>\t<agreement>"
#   resolves: "yes"=A record present, "no"=NXDOMAIN, "err"=all resolvers failed
#   agreement: "N/3" how many resolvers gave matching answer
# =============================================================================
multi_resolve_cname() {
  local host="$1"
  local r cname_target
  declare -A cname_votes nx_votes
  local total=0 dns_errs=0

  for r in "${RESOLVERS[@]}"; do
    local out
    out="$(timeout "$DIG_TIMEOUT" dig +short +time=2 +tries=1 "@$r" "$host" CNAME 2>/dev/null | tr -d '[:space:]' | tail -1)"
    if [[ -z "$out" ]]; then
      # Possibly direct A or NXDOMAIN. Check status.
      local astat
      astat="$(timeout "$DIG_TIMEOUT" dig +noall +comments +time=2 +tries=1 "@$r" "$host" 2>/dev/null | grep -oE 'status: [A-Z]+' | head -1 | awk '{print $2}')"
      if [[ "$astat" == "NXDOMAIN" ]]; then
        nx_votes["nx"]=$(( ${nx_votes["nx"]:-0} + 1 ))
      fi
      total=$((total + 1))
      continue
    fi
    # CNAME found — strip trailing dot
    out="${out%.}"
    cname_votes["$out"]=$(( ${cname_votes["$out"]:-0} + 1 ))
    total=$((total + 1))
  done

  # Find majority CNAME vote
  local best="" best_count=0
  for cname_target in "${!cname_votes[@]}"; do
    if (( cname_votes[$cname_target] > best_count )); then
      best_count=${cname_votes[$cname_target]}
      best="$cname_target"
    fi
  done

  if [[ -n "$best" && "$best_count" -ge 2 ]]; then
    printf '%s\tcname\t%d/3\n' "$best" "$best_count"
  elif [[ "${nx_votes[nx]:-0}" -ge 2 ]]; then
    printf '%s\tnxdomain\t%d/3\n' "$host" "${nx_votes[nx]}"
  else
    printf '\terr\t0/3\n'
  fi
}

# Check if CNAME target itself NXDOMAINs (multi-resolver)
target_nxdomains() {
  local target="$1"
  local nxcount=0
  for r in "${RESOLVERS[@]}"; do
    local stat
    stat="$(timeout "$DIG_TIMEOUT" dig +noall +comments +time=2 +tries=1 "@$r" "$target" 2>/dev/null | grep -oE 'status: [A-Z]+' | head -1 | awk '{print $2}')"
    [[ "$stat" == "NXDOMAIN" ]] && nxcount=$((nxcount + 1))
  done
  [[ "$nxcount" -ge 2 ]]
}

# =============================================================================
# Match a CNAME target against our fingerprint DB
# Returns index into FP arrays, or -1
# =============================================================================
match_provider() {
  local cname="$1"
  local i
  for ((i=0; i<${#FP_SVC[@]}; i++)); do
    [[ -n "${FP_CNAME[$i]}" ]] || continue
    if [[ "$cname" =~ ${FP_CNAME[$i]} ]]; then
      printf '%d\n' "$i"
      return 0
    fi
  done
  printf '%d\n' "-1"
  return 1
}

# =============================================================================
# HTTP fingerprint check — fetch host, match body against provider regex
# Returns: "match" | "nomatch" | "fetcherr" | "livecontent:<size>"
# Fix 4: also detects live content (large body with real HTML = not a takeover)
# =============================================================================
http_fingerprint_check() {
  local host="$1" idx="$2"
  local pattern="${FP_HTTP[$idx]}"

  local body schemes=("https" "http")
  for scheme in "${schemes[@]}"; do
    body="$(curl_net -sk -L --max-redirs 3 -m "$HTTP_TIMEOUT" -A 'Mozilla/5.0 recon-takeover-hunter/2.0' "$scheme://$host/" 2>/dev/null | tr -d '\0')"
    [[ -n "$body" ]] && break
  done

  if [[ -z "$body" ]]; then
    [[ -z "$pattern" ]] && { echo "skipped"; return; }
    echo "fetcherr"
    return
  fi

  # Fix 4: live content disqualifier — large body with real HTML tags but no takeover fingerprint
  local body_len; body_len="${#body}"
  if [[ "$body_len" -gt 1000 ]]; then
    # Check for non-error HTML structure (real page content)
    if printf '%s' "$body" | grep -qiE '<(html|body|head|title|main|div|nav|header)[^>]*>' 2>/dev/null; then
      # Only disqualify if pattern is set and not matching
      if [[ -n "$pattern" ]]; then
        if ! grep -qE "$pattern" <<< "$body" 2>/dev/null; then
          echo "livecontent:${body_len}"
          return
        fi
      else
        echo "livecontent:${body_len}"
        return
      fi
    fi
  fi

  [[ -z "$pattern" ]] && { echo "skipped"; return; }

  if grep -qE "$pattern" <<< "$body" 2>/dev/null; then
    echo "match"
  else
    echo "nomatch"
  fi
}

# =============================================================================
# Confidence scoring
# Stages passed → confidence:
#   5 stages (cname+resolver-agree+nx+http+stable) = CRITICAL
#   4 stages (cname+resolver-agree+(nx OR http)+stable) = HIGH
#   3 stages = MEDIUM (watching)
#   2 stages = LOW (ignore unless specifically requested)
# =============================================================================
classify_confidence() {
  local stages_passed="$1"
  local provider_difficulty="$2"

  case "$stages_passed" in
    5) echo "CRITICAL" ;;
    4)
      [[ "$provider_difficulty" == "easy" ]] && echo "HIGH" || echo "MEDIUM-HIGH"
      ;;
    3) echo "MEDIUM" ;;
    *) echo "LOW" ;;
  esac
}

# =============================================================================
# Discord URGENT notification — embed with full claim instructions
# Fix 1: claim_status field; @here ONLY on full verified claims (Fix 13)
# =============================================================================
notify_takeover() {
  local host="$1" idx="$2" confidence="$3" cname="$4" stages="$5" notes="$6"
  local claim_status="${7:-unknown}"   # Fix 1: "full" | "partial" | "unknown"
  [[ -z "$(discord_hook takeovers)" ]] && return 0

  local svc="${FP_SVC[$idx]}"
  local diff="${FP_DIFF[$idx]}"
  local payout="${FP_PAYOUT[$idx]}"
  local claim="${FP_CLAIM[$idx]}"

  local color
  case "$confidence" in
    CRITICAL) color=10038562 ;;   # dark red
    HIGH)     color=15105570 ;;   # orange
    *)        color=15844367 ;;   # yellow
  esac

  # Fix 1: downgrade confidence for partial claims
  local effective_confidence="$confidence"
  if [[ "$claim_status" == "partial" ]]; then
    [[ "$confidence" == "HIGH" || "$confidence" == "CRITICAL" ]] && effective_confidence="MEDIUM"
    color=15844367  # yellow for partial
  fi

  local emoji
  case "$effective_confidence" in
    CRITICAL) emoji="🚨🚨🚨" ;;
    HIGH)     emoji="🚨" ;;
    *)        emoji="⚠️" ;;
  esac

  local title="$emoji TAKEOVER [$effective_confidence] $svc → $host"

  # Fix 13: @here ONLY on full verified claims, not partial/unknown
  local content
  if [[ "$claim_status" == "full" ]]; then
    content="@here 🩸 **FIRST-BLOOD CANDIDATE** — FULL CLAIM VERIFIED (${effective_confidence})"
  else
    content="🩸 **TAKEOVER CANDIDATE** (${effective_confidence}) — claim_status=${claim_status}"
  fi

  local payload
  payload="$(jq -n \
    --arg title "$title" \
    --arg host "$host" \
    --arg cname "$cname" \
    --arg svc "$svc" \
    --arg conf "$effective_confidence" \
    --arg diff "$diff" \
    --arg payout "$payout" \
    --arg claim "$claim" \
    --arg stages "$stages" \
    --arg notes "$notes" \
    --arg claim_status "$claim_status" \
    --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --argjson color "$color" \
    --arg content "$content" \
    '{
      content: $content,
      embeds: [{
        title: $title,
        color: $color,
        fields: [
          {name:"Host",            value:("`" + $host + "`"),  inline:false},
          {name:"Dangling CNAME",  value:("`" + $cname + "`"), inline:false},
          {name:"Provider",        value:$svc,    inline:true},
          {name:"Confidence",      value:$conf,   inline:true},
          {name:"Claim Status",    value:$claim_status, inline:true},
          {name:"Difficulty",      value:$diff,   inline:true},
          {name:"Typical payout",  value:$payout, inline:true},
          {name:"Verification",    value:$stages, inline:true},
          {name:"Notes",           value:$notes,  inline:true},
          {name:"⚡ CLAIM PROCEDURE", value:$claim, inline:false},
          {name:"⏰ TIME SENSITIVE", value:"Dangling CNAMEs get claimed by other hunters fast. Move now.", inline:false}
        ],
        footer:{text:"recon_takeover_hunter · first-blood path"},
        timestamp:$ts
      }]
    }')"

  # Return the real delivery status so the caller only marks the host SEEN
  # once the alert is confirmed delivered (no silent loss on a failed POST).
  if discord_post "$(discord_hook takeovers)" "$payload"; then
    return 0
  fi
  warn "Discord notify failed for $host (left unseen for retry next cycle)"
  return 1
}

# Fix 1: Fastly post-claim verification
# After a Fastly claim, re-check HTTP to see if fingerprint is gone
fastly_post_claim_check() {
  local host="$1" idx="$2"
  local http_result; http_result="$(http_fingerprint_check "$host" "$idx")"
  if [[ "$http_result" == "match" ]]; then
    echo "partial"
  else
    echo "full"
  fi
}

# =============================================================================
# ES write-back — tag the ES document with confirmed takeover metadata
# Called on CRITICAL/HIGH/MEDIUM-HIGH findings. Fire-and-forget (non-fatal).
# =============================================================================
es_tag_takeover() {
  local host="$1" svc="$2" cname="$3" confidence="$4" payout="$5" detected_at="$6"

  local payload
  payload="$(jq -n \
    --arg host "$host" --arg svc "$svc" --arg cname "$cname" \
    --arg conf "$confidence" --arg payout "$payout" --arg ts "$detected_at" \
    '{
      script: { source: "ctx._source.takeover_confirmed = true; ctx._source.takeover_service = params.svc; ctx._source.takeover_cname = params.cname; ctx._source.takeover_confidence = params.conf; ctx._source.takeover_payout = params.payout; ctx._source.takeover_detected_at = params.ts; if (ctx._source.triage_classes == null) { ctx._source.triage_classes = []; } if (!ctx._source.triage_classes.contains(\"takeover\")) { ctx._source.triage_classes.add(\"takeover\"); }", lang: "painless",
        params: {svc:$svc, cname:$cname, conf:$conf, payout:$payout, ts:$ts}},
      query: {term: {"host.keyword": $host}}
    }')" 2>/dev/null

  [[ -z "$payload" ]] && return 0

  curl -sS -m15 "${ES_AUTH[@]}" \
    -H 'Content-Type: application/json' \
    -X POST "$ES_URL/$INDEX_NAME/_update_by_query?conflicts=proceed&wait_for_completion=false" \
    -d "$payload" >/dev/null 2>&1 || true

  log "  ES tagged: $host ($svc) → takeover_confirmed=true"

  # Route to Claude VERIFY too (everything gets verified). The #takeovers fast-ping
  # is unchanged (first-blood speed); this adds the adversarial FP check (e.g. dangling
  # CNAME to a LIVE ELB) → reaches #review only when Claude agrees it's real.
  local _cf=0.9; case "$confidence" in *CRITICAL*) _cf=0.95 ;; *MEDIUM*) _cf=0.8 ;; esac
  db_confirm "$host" "https://$host" "" "takeover" "takeover" "15" "$_cf" \
    "$(jq -nc --arg s "$svc" --arg c "$cname" --arg cf "$confidence" \
        '{probe:"takeover-multistage", service:$s, cname:$c, confidence:$cf}' 2>/dev/null)"
}

# =============================================================================
# Single-host probe — runs all 5 stages, decides HIGH/MEDIUM/LOW/clean
# Atomic: writes to claim or watching, dedups via seen file
# =============================================================================
probe_host() {
  local host="$1"
  local hint_cname="${2:-}"   # optional pre-known CNAME from httpx

  # Dedup — if already seen recently, skip unless STAGE 5 recheck path
  if grep -qxF "$host" "$SEEN_FILE" 2>/dev/null; then
    return 0
  fi

  # ---- STAGE 1: Get CNAME (via hint or multi-resolver) ----
  local stage1=0 cname=""
  if [[ -n "$hint_cname" ]]; then
    cname="${hint_cname%.}"
    stage1=1
  fi

  if [[ -z "$cname" ]]; then
    local res; res="$(multi_resolve_cname "$host")"
    cname="$(awk -F'\t' '{print $1}' <<< "$res")"
    local restype; restype="$(awk -F'\t' '{print $2}' <<< "$res")"
    [[ "$restype" == "cname" ]] && stage1=1
    # NXDOMAIN with no CNAME means host itself doesn't exist — not a takeover
    if [[ "$restype" == "nxdomain" ]] && [[ -z "$cname" || "$cname" == "$host" ]]; then
      return 0
    fi
  fi

  [[ "$stage1" -eq 0 || -z "$cname" ]] && return 0

  # Fix 3: AWS ELB/NLB/ALB exclusion — owned infrastructure, never a takeover
  if cname_is_aws_elb "$cname"; then
    log "SKIP $host → $cname (AWS managed LB — hard exclusion)"
    return 0
  fi

  # Fix 6: CNAME whitelist check
  if cname_whitelisted "$cname"; then
    log "SKIP $host → $cname (CNAME whitelist match)"
    return 0
  fi

  # Fix 5: Same-apex CNAME filter — CNAME pointing back to same org is not a takeover
  local host_apex; host_apex="$(extract_apex "$host")"
  local cname_apex; cname_apex="$(extract_apex "$cname")"
  if [[ -n "$host_apex" && -n "$cname_apex" && "$host_apex" == "$cname_apex" ]]; then
    log "SKIP $host → $cname (same-apex CNAME: $host_apex == $cname_apex)"
    return 0
  fi

  # ---- STAGE 2: Provider match ----
  local idx; idx="$(match_provider "$cname")"
  [[ "$idx" -lt 0 ]] && return 0

  local stage2=1
  local svc="${FP_SVC[$idx]}"
  local diff="${FP_DIFF[$idx]}"

  # ---- 99%-FP-free GATE A: claimability (can-i-take-over-xyz) ----
  # Not-vulnerable services (ownership-verified) + the provider's own namespace are NEVER
  # claimable by an outsider — they are the dominant FP source. Drop them outright.
  if svc_in_list "$svc" "$TKO_NOTVULN"; then
    log "SKIP $host → $svc via $cname (NOT vulnerable per can-i-take-over-xyz — requires ownership verification)"
    return 0
  fi
  if cname_provider_own "$cname"; then
    log "SKIP $host → $svc via $cname (CNAME target is the provider's OWN namespace — unclaimable)"
    return 0
  fi

  # Skip impossible ones unless explicit override — they pollute notifications
  [[ "$diff" == "impossible" ]] && {
    log "Skipping $host → $svc (impossible difficulty)"
    return 0
  }

  log "STAGE 2 hit: $host → $svc via CNAME $cname"

  # ---- STAGE 3: NXDOMAIN check on CNAME target ----
  local stage3=0 nx_state="resolves"
  if target_nxdomains "$cname"; then
    stage3=1
    nx_state="nxdomain"
  fi

  # If provider triggers on NXDOMAIN alone (S3, GH-pages, Heroku without HTTP), stage 3 hit is strong
  local nx_trigger="${FP_NX[$idx]}"

  # ---- STAGE 4: HTTP fingerprint match ----
  local stage4=0 http_state
  http_state="$(http_fingerprint_check "$host" "$idx")"
  case "$http_state" in
    match)    stage4=1 ;;
    nomatch)  stage4=0 ;;
    skipped)  stage4=0 ;;
    fetcherr) stage4=0 ;;
    livecontent:*)
      # Fix 4: host is serving real content — disqualify silently
      log "SKIP $host → $svc: live content detected ($http_state), not a takeover candidate"
      return 0
      ;;
  esac

  # Fix 2: Azure "stopped app" disqualifier — resource EXISTS and is owned
  # Check if body contains the stopped-app indicator
  local body_check
  body_check="$( { curl_net -sk -L --max-redirs 2 -m "$HTTP_TIMEOUT" -A 'Mozilla/5.0 recon-takeover-hunter/2.0' "https://$host/" 2>/dev/null \
                   || curl_net -sk -L --max-redirs 2 -m "$HTTP_TIMEOUT" -A 'Mozilla/5.0 recon-takeover-hunter/2.0' "http://$host/" 2>/dev/null ; } | tr -d '\0')"
  if printf '%s' "$body_check" | grep -qiE 'this web app is stopped' 2>/dev/null; then
    log "SKIP $host → $svc: Azure 'web app stopped' — resource owned (disqualifier)"
    return 0
  fi

  # ---- STAGE 5: Stability re-check ----
  # Run only if 3+ stages passed otherwise — saves time on obvious clean
  local stages_so_far=$((stage1 + stage2 + stage3 + stage4))
  local stage5=0

  if [[ "$stages_so_far" -ge 3 ]]; then
    log "  → 3+ stages passed for $host, running ${STABILITY_DELAY}s stability check"
    sleep "$STABILITY_DELAY"

    local recheck_pass=1
    # Re-resolve CNAME
    local res2; res2="$(multi_resolve_cname "$host")"
    local cname2; cname2="$(awk -F'\t' '{print $1}' <<< "$res2")"
    [[ "$cname2" != "$cname" ]] && recheck_pass=0
    # Re-check NXDOMAIN if it was a factor
    if [[ "$stage3" -eq 1 ]]; then
      target_nxdomains "$cname" || recheck_pass=0
    fi
    # Re-check HTTP if it was a factor
    if [[ "$stage4" -eq 1 ]]; then
      local http2; http2="$(http_fingerprint_check "$host" "$idx")"
      [[ "$http2" != "match" ]] && recheck_pass=0
    fi

    [[ "$recheck_pass" -eq 1 ]] && stage5=1
  fi

  local total_stages=$((stage1 + stage2 + stage3 + stage4 + stage5))
  local stages_str="s1:$stage1 s2:$stage2 s3:$stage3 s4:$stage4 s5:$stage5"
  local confidence
  confidence="$(classify_confidence "$total_stages" "$diff")"

  # ---- 99%-FP-free GATE B: NXDOMAIN required to CONFIRM ----
  # A real takeover means the backing resource is GONE -> the CNAME target NXDOMAINs ->
  # the name is free to register. The classic FPs (Fastly/Firebase/live-CloudFront/an app
  # that merely 404s) all RESOLVE, so they fail this gate -> downgraded to LEAD (never a
  # confirmed P0). Exception: services whose HTTP error fingerprint is itself authoritative-
  # unclaimed (S3 "NoSuchBucket" / Beanstalk), which prove a free name without NXDOMAIN.
  if [[ "$nx_state" != "nxdomain" ]] && ! svc_in_list "$svc" "$TKO_HTTP_AUTH"; then
    log "  → $host ($svc): CNAME target RESOLVES (no NXDOMAIN) — downgrade to MEDIUM/WATCH, not a confirmed takeover"
    confidence="MEDIUM"   # -> WATCH file: re-checked each cycle; promotes only if it later NXDOMAINs
  fi

  # Build notes about what fired
  local notes=""
  [[ "$nx_state" == "nxdomain" ]] && notes+="NXDOMAIN "
  [[ "$http_state" == "match" ]] && notes+="HTTP-match "
  [[ "$http_state" == "fetcherr" ]] && notes+="HTTP-err "
  [[ "$stage5" -eq 1 ]] && notes+="stable "
  [[ -z "$notes" ]] && notes="(no extra signals)"

  # ---- Routing decision ----
  local now_iso; now_iso="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local now_epoch; now_epoch="$(date +%s)"

  case "$confidence" in
    CRITICAL|HIGH|MEDIUM-HIGH)
      # Fix 7: re-verify if last_verified is >6h old
      local claim_status="unknown"
      if [[ "$confidence" == "HIGH" || "$confidence" == "CRITICAL" ]]; then
        if needs_reverify "$host"; then
          log "  → Re-verifying $host (last_verified >6h or first time)"
          # For Fastly specifically, do a post-claim check
          if [[ "$svc" == "fastly" ]]; then
            claim_status="$(fastly_post_claim_check "$host" "$idx")"
            log "  → Fastly post-claim check: $claim_status"
          else
            claim_status="full"
          fi
        else
          claim_status="full"
        fi

        # Fix 7: check if already disclosed on HackerOne
        if check_already_disclosed "$host" 2>/dev/null; then
          log "  → $host already disclosed on HackerOne — downgrading to INFO"
          notes+="already-disclosed "
          printf '%s\t%s\t%s\tINFO\t%s\n' "$now_iso" "$host" "$svc" "$confidence" >> "$EVENT_LOG"
          return 0
        fi
      fi

      # Persist the finding immediately (CLAIM_FILE is the durable record, never
      # lost), but DEFER marking the host SEEN until the alert is confirmed
      # delivered — otherwise a failed Discord POST would permanently suppress
      # the first-blood ping. If notifications are disabled, mark SEEN at once.
      # Fix 1: TSV now has 9 columns: ts host svc cname confidence stages diff notes last_verified claim_status
      # flock: probe_host runs in parallel — guard all shared-file appends
      ( flock -x 200
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
          "$now_iso" "$host" "$svc" "$cname" "$confidence" "$stages_str" "$diff" "$notes" \
          "$now_epoch" "$claim_status" \
          >> "$CLAIM_FILE"
        printf '%s\t%s\t%s\tCLAIM\t%s\n' "$now_iso" "$host" "$svc" "$confidence" >> "$EVENT_LOG"
      ) 200>"${CLAIM_FILE}.lock"

      log "🚨 $confidence takeover candidate: $host ($svc, $stages_str, claim_status=$claim_status)"

      # Adjust confidence for partial claims (Fix 1)
      local effective_confidence="$confidence"
      if [[ "$claim_status" == "partial" ]]; then
        effective_confidence="MEDIUM"
        log "  → Fastly partial claim — downgrading to MEDIUM for notification"
      fi

      # Tag the ES document so viewers can pull confirmed takeovers from ES
      es_tag_takeover "$host" "$svc" "$cname" "$effective_confidence" \
        "${FP_PAYOUT[$idx]}" "$now_iso" &

      if [[ "$NOTIFY_HIGH" == "1" ]]; then
        if notify_takeover "$host" "$idx" "$effective_confidence" "$cname" "$stages_str" "$notes" "$claim_status"; then
          ( flock -x 201; echo "$host" >> "$SEEN_FILE" ) 201>"${SEEN_FILE}.lock"
        else
          log "  alert undelivered for $host — left unseen, will retry next cycle"
        fi
      else
        ( flock -x 201; echo "$host" >> "$SEEN_FILE" ) 201>"${SEEN_FILE}.lock"
      fi
      ;;
    MEDIUM)
      # Write to WATCH file — periodic recheck
      # Fix 7: add last_verified epoch column
      ( flock -x 202
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
          "$now_iso" "$host" "$svc" "$cname" "$confidence" "$stages_str" "$diff" "$notes" \
          "$now_epoch" \
          >> "$WATCH_FILE"
        printf '%s\t%s\t%s\tWATCH\t%s\n' "$now_iso" "$host" "$svc" "$confidence" >> "$EVENT_LOG"
      ) 202>"${WATCH_FILE}.lock"
      log "  ⚠ MEDIUM watching: $host ($svc, $stages_str)"

      # Fix 13: no @here on MEDIUM — notify_takeover with unknown claim_status (no ping)
      if [[ "$NOTIFY_MEDIUM" == "1" ]]; then
        notify_takeover "$host" "$idx" "$confidence" "$cname" "$stages_str" "$notes" "unknown"
      fi
      # Don't add to SEEN — we want to recheck later
      ;;
    LOW)
      # Pattern matched but only 2 stages — silent log, no notify
      printf '%s\t%s\t%s\tLOW\t%s\n' "$now_iso" "$host" "$svc" "$stages_str" >> "$EVENT_LOG"
      ;;
  esac
}

# =============================================================================
# Stream mode: parse jsonl and probe each host
# Input format: {host, cname, ...}  (httpx JSON output)
# =============================================================================
mode_stream() {
  local file="${1:-/dev/stdin}"
  load_fingerprints

  local processed=0 candidates=0
  # Parallel probing: STABILITY_DELAY dominates time — run up to N hosts in parallel.
  # Keep low (default 6) to avoid DNS resolver hammering during busy validate cycles.
  local max_parallel="${TAKEOVER_PARALLEL:-6}"

  while IFS= read -r line; do
    local host cname
    host="$(jq -r '.host // .input // empty' <<< "$line" 2>/dev/null)"
    cname="$(jq -r '(.cname // [""])[0] // ""' <<< "$line" 2>/dev/null | tr -d '[:space:]')"
    [[ -z "$host" ]] && continue
    processed=$((processed + 1))

    # Fast path: only probe hosts whose CNAME (if known) hits one of our patterns
    local should_probe=0 hint_cname=""
    if [[ -n "$cname" ]]; then
      local idx; idx="$(match_provider "$cname")"
      [[ "$idx" -lt 0 ]] && continue
      should_probe=1
      hint_cname="$cname"
    else
      # No CNAME hint — only probe if status was 404/0/5xx (otherwise wasteful)
      local sc; sc="$(jq -r '.status_code // 0' <<< "$line" 2>/dev/null)"
      if [[ "$sc" == "404" || "$sc" == "0" || "$sc" == "503" || "$sc" == "502" ]]; then
        should_probe=1
      fi
    fi
    [[ "$should_probe" -eq 0 ]] && continue

    candidates=$((candidates + 1))

    # Semaphore: wait for a slot before spawning
    while (( $(jobs -rp 2>/dev/null | wc -l) >= max_parallel )); do
      wait -n 2>/dev/null || sleep 0.5
    done

    probe_host "$host" "$hint_cname" &
  done < "$file"

  wait  # drain remaining background jobs
  log "Stream done: processed=$processed candidates_probed=$candidates"
}

# =============================================================================
# Watch mode: long-running loop for periodic WATCH rechecks.
#
# Validation already invokes stream mode for each completed httpx batch. Older
# watch mode also polled queue/done and re-streamed those same files, creating
# duplicate stream children during busy validate cycles. Leave that legacy poll
# path opt-in for manual recovery only.
# =============================================================================
mode_watch() {
  exec 9>"$LOCK_FILE"
  flock -n 9 || { log "Another takeover_hunter watch is running — exiting cleanly"; exit 0; }
  echo $$ > "$PID_FILE"

  load_fingerprints
  log "===== takeover_hunter watch started (pid $$) ====="

  local processed_marker="$STATE_DIR/takeover_processed.txt"
  touch "$processed_marker"
  local process_done="${TAKEOVER_WATCH_PROCESS_DONE:-0}"

  trap 'rm -f "$PID_FILE"' EXIT

  while :; do
    local found=0
    if [[ "$process_done" == "1" ]]; then
      # Manual recovery path only. The validator is the normal owner of
      # per-batch stream processing.
      local f
      while IFS= read -r f; do
        [[ -z "$f" || ! -s "$f" ]] && continue
        if grep -qxF "$f" "$processed_marker"; then continue; fi
        found=1
        log "Processing new validation output: $(basename "$f")"
        mode_stream "$f"
        echo "$f" >> "$processed_marker"
      done < <(find "$BASE_DIR/queue/done" -name '*.jsonl' -mmin -180 2>/dev/null | sort)
    fi

    # Trim processed_marker to keep last 5000 lines
    if [[ "$(wc -l < "$processed_marker")" -gt 5000 ]]; then
      tail -n 4000 "$processed_marker" > "$processed_marker.tmp" && mv "$processed_marker.tmp" "$processed_marker"
    fi

    # Periodic recheck of WATCH list. v2.5: loop cadence dropped to 15 min so
    # true-fresh hosts get faster re-verification. Inside mode_recheck, each
    # entry's last-probed timestamp gates whether it actually probes:
    #   - true_fresh host: always re-probe
    #   - regular host:    re-probe only if 30+ min since last probe
    local now_min last_recheck recheck_marker="$STATE_DIR/last_takeover_recheck.epoch"
    now_min="$(( $(date +%s) / 60 ))"
    last_recheck="$(cat "$recheck_marker" 2>/dev/null || echo 0)"
    if (( now_min - last_recheck >= 15 )); then
      mode_recheck
      echo "$now_min" > "$recheck_marker"
    fi

    [[ "$found" -eq 0 ]] && sleep 60 || sleep 5
  done
}

# =============================================================================
# Recheck mode: re-verify everything in WATCH file
# Promotes to CLAIM if confidence increased, drops if signals went away
# =============================================================================
mode_recheck() {
  load_fingerprints 2>/dev/null

  [[ ! -s "$WATCH_FILE" ]] && return 0

  log "Rechecking $(wc -l < "$WATCH_FILE" | tr -d ' ') WATCHING entries"
  local tmp_keep; tmp_keep="$(mktemp)"
  trap "rm -f $tmp_keep" RETURN

  # v2.5: Build set of true_fresh hosts (≤24h, valid) once for fast lookups.
  local fresh_set; fresh_set="$(mktemp)"
  trap "rm -f $tmp_keep $fresh_set" RETURN
  if [[ -s "$STATE_DIR/true_fresh.jsonl" ]]; then
    local cutoff; cutoff="$(date -u -d '-24 hours' '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || true)"
    jq -r --arg c "$cutoff" 'select((.external_first_seen // "") >= $c) | .host' \
      "$STATE_DIR/true_fresh.jsonl" 2>/dev/null | sort -u > "$fresh_set"
  fi

  # Per-host last-probe map (host\tepoch). Skip non-fresh hosts that were
  # probed within the last 30 min to keep load low.
  local lp_file="$STATE_DIR/takeover_recheck_lp.tsv"
  touch "$lp_file"
  local now_epoch; now_epoch="$(date +%s)"
  local probe_cutoff=$(( now_epoch - 30 * 60 ))

  declare -A last_probed
  while IFS=$'\t' read -r h ep; do
    [[ -n "$h" ]] && last_probed["$h"]="$ep"
  done < "$lp_file"

  local lp_new; lp_new="$(mktemp)"

  while IFS=$'\t' read -r ts host svc cname conf stages diff notes; do
    [[ -z "$host" ]] && continue
    if grep -qxF "$host" "$SEEN_FILE" 2>/dev/null; then continue; fi

    local is_fresh=0
    [[ -s "$fresh_set" ]] && grep -qxF "$host" "$fresh_set" 2>/dev/null && is_fresh=1

    local last="${last_probed[$host]:-0}"
    if [[ "$is_fresh" -eq 0 && "$last" -ge "$probe_cutoff" ]]; then
      # Non-fresh host recently probed — keep entry, don't re-probe
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$ts" "$host" "$svc" "$cname" "$conf" "$stages" "$diff" "$notes" >> "$tmp_keep"
      printf '%s\t%s\n' "$host" "$last" >> "$lp_new"
      continue
    fi

    probe_host "$host" "$cname"
    printf '%s\t%s\n' "$host" "$now_epoch" >> "$lp_new"

    if grep -qxF "$host" "$SEEN_FILE" 2>/dev/null; then
      log "  ↑ Promoted to CLAIM: $host"
      continue
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$ts" "$host" "$svc" "$cname" "$conf" "$stages" "$diff" "$notes" >> "$tmp_keep"
  done < "$WATCH_FILE"

  # Dedupe + keep latest per host
  sort -u -k1,1 -t$'\t' "$lp_new" -o "$lp_new"
  mv "$lp_new" "$lp_file"

  mv "$tmp_keep" "$WATCH_FILE"

  # Prune WATCH entries older than WATCH_MAX_AGE_DAYS (default 30).
  # Dangling CNAMEs that stay MEDIUM for a month are almost certainly gone.
  local max_age="${WATCH_MAX_AGE_DAYS:-30}"
  local cutoff_epoch; cutoff_epoch=$(( $(date +%s) - max_age * 86400 ))
  local pruned; pruned="$(mktemp)"
  while IFS=$'\t' read -r ts host rest; do
    [[ -z "$host" ]] && continue
    local entry_epoch
    entry_epoch="$(date -d "$ts" +%s 2>/dev/null || echo 0)"
    [[ "$entry_epoch" -ge "$cutoff_epoch" ]] && printf '%s\t%s\t%s\n' "$ts" "$host" "$rest"
  done < "$WATCH_FILE" > "$pruned"
  local before after
  before="$(wc -l < "$WATCH_FILE" | tr -d ' ')"
  after="$(wc -l < "$pruned" | tr -d ' ')"
  mv "$pruned" "$WATCH_FILE"
  [[ "$before" -gt "$after" ]] && log "  Pruned $(( before - after )) stale WATCH entries (>${max_age}d old)"

  # Prune CLAIM entries older than CLAIM_MAX_AGE_DAYS (default 90).
  # A claimed takeover that's 3 months old and still in the file was either
  # reported, rejected, or the target recovered — prune it to keep the file bounded.
  local claim_max_age="${CLAIM_MAX_AGE_DAYS:-90}"
  local claim_cutoff_epoch; claim_cutoff_epoch=$(( $(date +%s) - claim_max_age * 86400 ))
  local claim_pruned; claim_pruned="$(mktemp)"
  local claim_before claim_after
  claim_before="$(wc -l < "$CLAIM_FILE" | tr -d ' ')"
  while IFS=$'\t' read -r ts host rest; do
    [[ -z "$host" ]] && continue
    local entry_epoch
    entry_epoch="$(date -d "$ts" +%s 2>/dev/null || echo 0)"
    [[ "$entry_epoch" -ge "$claim_cutoff_epoch" ]] && printf '%s\t%s\t%s\n' "$ts" "$host" "$rest"
  done < "$CLAIM_FILE" > "$claim_pruned"
  claim_after="$(wc -l < "$claim_pruned" | tr -d ' ')"
  mv "$claim_pruned" "$CLAIM_FILE"
  [[ "$claim_before" -gt "$claim_after" ]] && \
    log "  Pruned $(( claim_before - claim_after )) stale CLAIM entries (>${claim_max_age}d old)"

  log "Recheck done. Remaining in WATCH: $(wc -l < "$WATCH_FILE" | tr -d ' ')"
}

# =============================================================================
# Single-host check — convenience for manual verification
# =============================================================================
mode_check() {
  local host="${1:?host required}"
  load_fingerprints
  log "Single-host probe: $host"
  # Allow re-probe of seen host in this mode
  grep -vxF "$host" "$SEEN_FILE" > "$SEEN_FILE.tmp" 2>/dev/null && mv "$SEEN_FILE.tmp" "$SEEN_FILE"
  probe_host "$host" ""
  log "Done. Check $CLAIM_FILE / $WATCH_FILE for results."
}

# =============================================================================
# Dedup mode: print unique CNAME targets from CLAIM file (grouped)
# Eliminates the noise of multiple hosts pointing to the same dangling CNAME —
# they're all one opportunity, not N separate bounties (usually).
# =============================================================================
mode_dedup() {
  [[ ! -s "$CLAIM_FILE" ]] && { echo "Claim file empty."; return; }

  local total_hosts; total_hosts="$(wc -l < "$CLAIM_FILE" | tr -d ' ')"
  local unique_cnames; unique_cnames="$(awk -F'\t' '{print $4}' "$CLAIM_FILE" | sort -u | wc -l | tr -d ' ')"
  printf '\n  Claim file: %s entries → %s unique CNAME targets\n\n' \
    "$total_hosts" "$unique_cnames"

  printf '  %-48s %-16s %-10s %-8s  %s\n' \
    "CNAME TARGET" "SERVICE" "CONF" "HOSTS" "EXAMPLE HOST"
  printf '  %s\n' "$(printf '─%.0s' {1..110})"

  awk -F'\t' '{print $4}' "$CLAIM_FILE" | sort -u | while IFS= read -r cname_target; do
    [[ -z "$cname_target" ]] && continue
    local host_count svc conf example
    host_count="$(grep -cF "$cname_target" "$CLAIM_FILE" 2>/dev/null || echo 0)"
    svc="$(grep -F "$cname_target" "$CLAIM_FILE" 2>/dev/null | head -1 | awk -F'\t' '{print $3}')"
    conf="$(grep -F "$cname_target" "$CLAIM_FILE" 2>/dev/null | head -1 | awk -F'\t' '{print $5}')"
    example="$(grep -F "$cname_target" "$CLAIM_FILE" 2>/dev/null | head -1 | awk -F'\t' '{print $2}')"
    printf '  %-48s %-16s %-10s %-8s  %s\n' \
      "$cname_target" "$svc" "$conf" "$host_count" "$example"
  done

  printf '\n  To probe a specific host:  %s check <host>\n' "$(basename "$0")"
  printf '  To recheck watching list:  %s recheck\n\n' "$(basename "$0")"
}

# =============================================================================
# Dispatch
# =============================================================================
{
case "${1:-}" in
  stream)  shift; mode_stream "${1:-/dev/stdin}" ;;
  watch)   mode_watch ;;
  recheck) mode_recheck ;;
  check)   shift; mode_check "$@" ;;
  dedup)   mode_dedup ;;
  *) cat <<EOF
Usage: $(basename "$0") <mode> [args]

Modes:
  stream <jsonl>   Process httpx JSONL output (one-shot, called by validator)
  watch            Long-running daemon, polls queue/done/, re-verifies WATCHING
  recheck          Re-verify all WATCHING entries once
  check <host>     Manual single-host probe (bypasses SEEN dedup)
  dedup            Show unique CNAME targets grouped (deduplicated opportunity view)

Files:
  $CLAIM_FILE
  $WATCH_FILE
  $EVENT_LOG
EOF
  exit 2 ;;
esac
} 2>&1 | tee -a "$HUNTER_LOG"

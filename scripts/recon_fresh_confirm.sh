#!/usr/bin/env bash
# =============================================================================
# recon_fresh_confirm.sh — Fresh, in-scope, low-noise confirmation queue.
#
# Goal:
#   Turn brand-new recon into claim-ready manual targets without broad exploit
#   traffic. This only uses indexed httpx evidence plus a single safe GET to
#   refresh page evidence through the configured proxy.
# =============================================================================
set -uo pipefail
IFS=$'\n\t'

log()  { printf '[%s FRESH] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s FRESH WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
die()  { printf '[%s FRESH FATAL] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/recon_net.sh"

for c in curl jq date mktemp sort head sha256sum; do
  command -v "$c" >/dev/null 2>&1 || die "missing: $c"
done

BASE_DIR="${BASE_DIR:-$HOME/recon}"
FRESH_DIR="${FRESH_DIR:-$BASE_DIR/fresh}"
STATE_DIR="$BASE_DIR/state"
LOCK_FILE="$FRESH_DIR/fresh_confirm.lock"
SCOPE_CHECK="${SCOPE_CHECK:-$SCRIPT_DIR/recon_scope_check.sh}"
[[ -f "$SCOPE_CHECK" ]] || SCOPE_CHECK="$HOME/recon_scope_check.sh"

ES_URL="${ES_URL:-http://127.0.0.1:9200}"
INDEX_NAME="${INDEX_NAME:-recon_alive}"
ES_USER="${ES_USER:-elastic}"
ES_PASS="${ES_PASS:-$(tr -d '[:space:]' < "$HOME/.recon_es_pass" 2>/dev/null || true)}"
[[ -z "$ES_PASS" ]] && die "ES password not set"

LOOKBACK_HOURS="${FRESH_LOOKBACK_HOURS:-36}"
MAX_CANDIDATES="${FRESH_MAX_CANDIDATES:-40}"
MAX_VERIFY="${FRESH_MAX_VERIFY:-12}"
COOLDOWN_HOURS="${FRESH_COOLDOWN_HOURS:-24}"
MIN_SCORE="${FRESH_MIN_SCORE:-7}"
PAYING_ONLY="${FRESH_PAYING_ONLY:-1}"

mkdir -p "$FRESH_DIR/evidence" "$STATE_DIR"
exec 9>"$LOCK_FILE"; flock -n 9 || { warn "fresh confirm already running"; exit 0; }

RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_JSONL="$FRESH_DIR/fresh_confirmed.jsonl"
REPORT="$FRESH_DIR/report_${RUN_TS}.md"
SEEN_FILE="$FRESH_DIR/.seen_keys"
touch "$OUT_JSONL" "$SEEN_FILE"

es_post() {
  curl -fsS -m 45 -u "$ES_USER:$ES_PASS" -H 'Content-Type: application/json' "$@"
}

fetch_recent() {
  local out="$1" since
  since="$(date -u -d "-${LOOKBACK_HOURS} hours" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)"
  local query
  query="$(jq -n --arg since "$since" --argjson size 1000 '{
    size:$size,
    _source:["host","url","scheme","port","status_code","title","tech","webserver","content_type","content_length","root_domain","first_seen","last_seen"],
    query:{bool:{filter:[
      {range:{first_seen:{gte:$since}}},
      {range:{status_code:{gte:200,lte:599}}}
    ]}},
    sort:[{"first_seen":{"order":"desc"}}]
  }')"
  es_post -X POST "$ES_URL/$INDEX_NAME/_search" -d "$query" 2>/dev/null \
    | jq -c '.hits.hits[]._source' > "$out"
}

score_candidates() {
  local in="$1" out="$2"
  jq -c --argjson min "$MIN_SCORE" '
    def title($p): (.title // "" | test($p; "i"));
    def tech($p): ((.tech // []) | map(tostring) | join(" ") | test($p; "i"));
    def host($p): (.host // "" | test($p; "i"));
    [
      (if title("index of /") then {pts:10, kind:"directory-listing", evidence:"Directory listing title", report:"Public directory listing with potential sensitive files"} else empty end),
      (if title("phpinfo\\(\\)|phpinfo") then {pts:10, kind:"phpinfo", evidence:"phpinfo page title/body marker", report:"Exposed phpinfo leaks environment, paths, modules, and configuration"} else empty end),
      (if title("swagger ui|openapi|redoc|api documentation") or tech("swagger|openapi") then {pts:8, kind:"api-docs", evidence:"API documentation exposed", report:"Public API documentation exposes endpoints and request models"} else empty end),
      (if title("graphql playground|graphiql|apollo") or tech("graphql") then {pts:8, kind:"graphql-console", evidence:"GraphQL console marker", report:"Public GraphQL console or schema explorer exposed"} else empty end),
      (if title("setup wizard|installation wizard|installer|install wordpress|joomla installation") then {pts:9, kind:"installer", evidence:"Installer/setup page marker", report:"Public installer/setup flow exposed"} else empty end),
      (if title("whoops!|stack trace|traceback|exception|fatal error|debug") and (.status_code >= 500 or .status_code == 200) then {pts:7, kind:"debug-error", evidence:"Debug/error page marker", report:"Verbose debug/error page leaks implementation detail"} else empty end),
      (if host("(^|[.-])(dev|stg|stage|test|qa|uat|preprod|sandbox)[.-]") and (.status_code == 200 or .status_code == 401 or .status_code == 403) then {pts:3, kind:"fresh-nonprod", evidence:"Fresh non-production host", report:"Fresh non-production surface worth manual auth/config review"} else empty end),
      (if host("(^|[.-])(admin|internal|grafana|kibana|jenkins|gitlab|jira|confluence|vpn|sso)[.-]") then {pts:4, kind:"fresh-high-value-host", evidence:"Fresh high-value hostname pattern", report:"Fresh high-value surface worth immediate manual review"} else empty end)
    ] as $hits |
    ($hits | map(.pts) | add // 0) as $score |
    select($score >= $min) |
    . + {
      fresh_score:$score,
      fresh_kinds:($hits | map(.kind) | unique),
      fresh_evidence:($hits | map(.evidence) | unique),
      report_angle:($hits | map(.report) | unique)
    }
  ' "$in" > "$out"
}

scope_filter() {
  local in="$1" out="$2" hosts scope
  hosts="$(mktemp)"; scope="$(mktemp)"
  jq -r '.host' "$in" | sort -u > "$hosts"
  bash "$SCOPE_CHECK" --batch "$hosts" > "$scope"
  jq -s --slurpfile s "$scope" --argjson paying_only "$PAYING_ONLY" '
    ($s[0]
      | map(select(.in_scope == true and .out_of_scope == false))
      | map(select(($paying_only == 0) or (.pays == true)))
      | map({(.host):.}) | add // {}) as $scope |
    map(select($scope[.host] != null) | . + {scope:$scope[.host]})
    | sort_by(-(.fresh_score), (.first_seen // "")) | reverse | .[]
  ' "$in" > "$out"
  rm -f "$hosts" "$scope"
}

verify_one() {
  local line="$1" host url kind key now marker age_h ev_dir headers body status title
  host="$(jq -r '.host' <<< "$line")"
  url="$(jq -r '.url // empty' <<< "$line")"
  [[ -z "$url" || "$url" == "null" ]] && url="https://$host"
  kind="$(jq -r '.fresh_kinds | join(",")' <<< "$line")"
  key="$(printf '%s|%s' "$host" "$kind" | sha256sum | awk '{print $1}')"
  marker="$FRESH_DIR/.last_$key"
  now="$(date +%s)"
  if [[ -f "$marker" ]]; then
    age_h=$(( (now - $(cat "$marker" 2>/dev/null || echo 0)) / 3600 ))
    [[ "$age_h" -lt "$COOLDOWN_HOURS" ]] && return 0
  fi

  ev_dir="$FRESH_DIR/evidence/${RUN_TS}_${host//[^a-zA-Z0-9_.-]/_}"
  mkdir -p "$ev_dir"
  headers="$ev_dir/headers.txt"
  body="$ev_dir/body_sample.txt"

  status="$(curl_net -sk -L --max-redirs 2 -m 20 -A 'Mozilla/5.0 recon-fresh-confirm/1.0' \
    -D "$headers" -o "$body" -w '%{http_code}' "$url" 2>/dev/null || true)"
  [[ -z "$status" ]] && status="000"
  head -c 12000 "$body" > "$body.tmp" 2>/dev/null && mv "$body.tmp" "$body"
  title="$(grep -ioE '<title>[^<]{0,160}' "$body" 2>/dev/null | head -1 | sed -E 's#<title>##I' || true)"

  echo "$now" > "$marker"
  jq -c \
    --arg run "$RUN_TS" --arg url "$url" --arg status "$status" --arg title "$title" \
    --arg headers "$headers" --arg body "$body" \
    '. + {confirmed_at:$run, verified_url:$url, verify_status:($status|tonumber? // 0),
          verify_title:$title, evidence_files:{headers:$headers, body_sample:$body}}' <<< "$line" >> "$OUT_JSONL"
}

notify_discord() {
  local fresh="$1" hook payload
  hook="${DISCORD_WEBHOOK:-$(tr -d '[:space:]' < "$HOME/.recon_discord" 2>/dev/null || true)}"
  [[ -z "$hook" || ! -s "$fresh" ]] && return 0
  payload="$(head -5 "$fresh" | jq -s '{
    content: ("Fresh confirmed queue: " + (length|tostring) + " high-signal in-scope candidate(s)"),
    embeds: [.[] | {
      title: ("[" + (.fresh_score|tostring) + "] " + .host),
      url: .verified_url,
      color: 15105570,
      fields: [
        {name:"Kinds", value:(.fresh_kinds | join(", ")), inline:false},
        {name:"Scope", value:((.scope.program // "?") + " / " + (.scope.platform // "?")), inline:true},
        {name:"Pays", value:(if .scope.pays then "yes" else "no/unknown" end), inline:true},
        {name:"Evidence", value:(.fresh_evidence | join("; ") | .[0:600]), inline:false},
        {name:"Angle", value:(.report_angle | join("; ") | .[0:700]), inline:false}
      ],
      footer:{text:"fresh-confirm"}
    }]
  }')"
  curl_net -fsS -m 15 -H 'Content-Type: application/json' -X POST -d "$payload" "$hook" >/dev/null 2>&1 || true
}

main() {
  log "=== fresh confirmation start ==="
  local raw scored scoped fresh_run
  raw="$(mktemp)"; scored="$(mktemp)"; scoped="$(mktemp)"; fresh_run="$(mktemp)"
  trap "rm -f '$raw' '$scored' '$scoped' '$fresh_run'" EXIT

  fetch_recent "$raw"
  [[ -s "$raw" ]] || { log "No fresh ES records"; exit 0; }
  score_candidates "$raw" "$scored"
  [[ -s "$scored" ]] || { log "No high-signal fresh candidates"; exit 0; }
  scope_filter "$scored" "$scoped"
  [[ -s "$scoped" ]] || { log "No in-scope high-signal fresh candidates"; exit 0; }

  head -n "$MAX_CANDIDATES" "$scoped" | head -n "$MAX_VERIFY" | while IFS= read -r line; do
    verify_one "$line"
  done

  grep -F "\"confirmed_at\":\"$RUN_TS\"" "$OUT_JSONL" > "$fresh_run" 2>/dev/null || true
  {
    printf '# Fresh Confirmed Queue — %s\n\n' "$RUN_TS"
    if [[ ! -s "$fresh_run" ]]; then
      printf 'No new paying-program candidates after cooldown.\n'
    else
      jq -r '
        "## [" + (.fresh_score|tostring) + "] " + .host + "\n" +
        "- URL: " + .verified_url + "\n" +
        "- Scope: " + (.scope.program // "?") + " / " + (.scope.platform // "?") + " / pays=" + ((.scope.pays // false)|tostring) + "\n" +
        "- Kinds: " + (.fresh_kinds | join(", ")) + "\n" +
        "- Evidence: " + (.fresh_evidence | join("; ")) + "\n" +
        "- Report angle: " + (.report_angle | join("; ")) + "\n" +
        "- Evidence files: " + .evidence_files.headers + " ; " + .evidence_files.body_sample + "\n"
      ' "$fresh_run"
    fi
  } > "$REPORT"
  notify_discord "$fresh_run"
  log "Report: $REPORT"
  log "=== fresh confirmation done ==="
}

main "$@"

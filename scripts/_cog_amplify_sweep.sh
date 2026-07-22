#!/usr/bin/env bash
# Scaled Amplify/Cognito sweep (the Dropbox path, corpus-wide). For a prioritised
# batch of in-scope+paying app/portal/api hosts, probe the predictable Amplify
# config locations + the root main-JS bundle, and extract Cognito pool IDs.
# Read-only GET, Mullvad egress. Emits pools -> ~/recon/cognito/pools.jsonl.
set -uo pipefail
NETRC="$HOME/.recon_es_netrc"; ES="http://127.0.0.1:9200/recon_alive"
POOLS="$HOME/recon/cognito/pools.jsonl"; mkdir -p "$HOME/recon/cognito"
UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36'
POOL_RE='[a-z]{2}-[a-z]+-[0-9]:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
MAX_HOSTS="${1:-6000}"
CAND="/tmp/cog_amp_hosts.txt"

# Prioritised in-scope+paying hosts: SPA/app-ish subdomains, status 200, by payout tier + score.
read -r -d '' Q <<JSON || true
{"size":$MAX_HOSTS,"_source":["host","triage_program"],
 "query":{"bool":{
   "filter":[{"term":{"triage_in_scope":true}},{"term":{"triage_pays":true}},{"term":{"status_code":200}},
     {"regexp":{"host":"(app|apps|portal|dashboard|account|accounts|my|me|console|admin|api|mobile|web|client|clients|customer|customers|user|users|secure|login|auth|id|connect|platform|studio|create|manage|go)[-.].*"}}],
   "must_not":[{"range":{"ignore_expires_at":{"gt":"now"}}},{"term":{"triage_out_of_scope":true}},{"wildcard":{"host":"*.tumblr.com"}}]}},
 "sort":[{"triage_payout_tier":{"order":"asc","missing":"_last"}},{"triage_score":{"order":"desc","missing":"_last"}}]}
JSON
curl -sS -m40 --netrc-file "$NETRC" -H 'Content-Type: application/json' -X POST "$ES/_search" -d "$Q" 2>/dev/null \
  | jq -r '.hits.hits[]?._source | "\(.host)\t\(.triage_program // "")"' 2>/dev/null | awk -F'\t' 'NF && !s[$1]++' > "$CAND"
n=$(wc -l < "$CAND" | tr -d ' ')
echo "[amp-sweep] $n candidate host(s)" >&2
[ "$n" -eq 0 ] && exit 0

probe(){
  local host="$1" program="$2" body pools mainjs
  # 1) predictable Amplify config paths
  for p in "aws-exports.js" "amplifyconfiguration.json" "assets/amplifyconfiguration.json" \
           "static/amplifyconfiguration.json" "config/amplifyconfiguration.json" "src/aws-exports.js" \
           "assets/aws-exports.js" "aws_config.js" "amplify/backend/amplify-meta.json" ; do
    body="$(curl -sS -m10 -A "$UA" "https://${host}/${p}" 2>/dev/null | head -c 200000)" || continue
    pools="$(grep -aoE "$POOL_RE" <<<"$body" | sort -u)"
    if [ -n "$pools" ]; then
      while read -r pool; do [ -n "$pool" ] && jq -nc --arg h "$host" --arg pr "$program" --arg pool "$pool" --arg r "${pool%%:*}" --arg k "$p" --arg t "$(date -u '+%FT%TZ')" '{provenance:$h,program:$pr,pool:$pool,region:$r,source_key:$k,kind:"amplify-config",at:$t}' >> "$POOLS"; done <<<"$pools"
      echo "  POOL(s) via $host/$p : $(tr "\n" " " <<<"$pools")" >&2
    fi
  done
  # 2) root -> first main/app bundle -> grep
  body="$(curl -sS -m10 -A "$UA" "https://${host}/" 2>/dev/null | head -c 400000)" || return
  mainjs="$(grep -aoE '(src|href)="[^"]*(main|app|runtime|index)[.-][0-9a-zA-Z]+\.js"' <<<"$body" | sed -E 's/.*"([^"]+)".*/\1/' | head -3)"
  while read -r j; do
    [ -z "$j" ] && continue
    case "$j" in http*) u="$j";; /*) u="https://${host}${j}";; *) u="https://${host}/${j}";; esac
    pools="$(curl -sS -m12 -A "$UA" "$u" 2>/dev/null | grep -aoE "$POOL_RE" | sort -u)"
    while read -r pool; do [ -n "$pool" ] && { jq -nc --arg h "$host" --arg pr "$program" --arg pool "$pool" --arg r "${pool%%:*}" --arg k "$u" --arg t "$(date -u '+%FT%TZ')" '{provenance:$h,program:$pr,pool:$pool,region:$r,source_key:$k,kind:"root-mainjs",at:$t}' >> "$POOLS"; echo "  POOL via $host mainjs: $pool" >&2; }; done <<<"$pools"
  done <<<"$mainjs"
}
export -f probe; export UA POOL_RE POOLS

awk -F'\t' '{print $1"\t"$2}' "$CAND" \
 | xargs -P 14 -I{} bash -c 'IFS=$'"'"'\t'"'"' read -r h p <<<"$1"; probe "$h" "$p"' _ {} 2>/dev/null

echo "[amp-sweep] done. pools file unique: $(jq -r .pool "$POOLS" 2>/dev/null | sort -u | wc -l)" >&2

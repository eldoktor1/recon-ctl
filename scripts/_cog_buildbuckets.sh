#!/usr/bin/env bash
# Build-artifact subdomain -> open-S3-bucket prong (the builds.myharmony.com pattern).
# Enumerate in-scope+paying hosts whose name looks like a build/artifact/mobile/CDN
# host, then probe each for an anonymous S3 ListBucketResult. Read-only GET, Mullvad
# egress (VPN already gated up). Emits JSONL: {host,program,bucket,url} for OPEN ones.
set -uo pipefail
ES_URL="http://127.0.0.1:9200"; INDEX="recon_alive"
NETRC="$HOME/.recon_es_netrc"
OUT="${1:-/home/d0k/recon/buckets/build_open.jsonl}"
CAND="/tmp/cog_build_cands.txt"
: > "$OUT"

# in-scope + paying + build-ish host prefix. host is a keyword field -> regexp.
read -r -d '' Q <<'JSON'
{"size":4000,"_source":["host","triage_program"],
 "query":{"bool":{
   "filter":[{"term":{"triage_in_scope":true}},{"term":{"triage_pays":true}},
     {"regexp":{"host":"(builds?|ci|jenkins|artifacts?|nexus|mobile|apps?|dl|downloads?|releases?|dist|static|assets|cdn|media|uploads?|storage|s3|files|packages|repo|repository)[-.].*"}}],
   "must_not":[{"range":{"ignore_expires_at":{"gt":"now"}}},{"term":{"triage_out_of_scope":true}},
     {"wildcard":{"host":"*.tumblr.com"}}]}}}
JSON

curl -sS -m30 --netrc-file "$NETRC" -H 'Content-Type: application/json' \
  -X POST "$ES_URL/$INDEX/_search" -d "$Q" 2>/dev/null \
  | jq -r '.hits.hits[]?._source | "\(.host)\t\(.triage_program // "")"' 2>/dev/null \
  | awk -F'\t' 'NF && !s[$1]++' > "$CAND"

n=$(wc -l < "$CAND" | tr -d ' ')
echo "[build-prong] $n in-scope+paying build-ish host(s) to probe" >&2
[ "$n" -eq 0 ] && exit 0

probe_one() {
  local host="$1" program="$2" body code name
  # anonymous list on the host itself (fronted bucket) — path/vhost agnostic
  body="$(curl -sS -m12 -A 'Mozilla/5.0' "https://${host}/?list-type=2&max-keys=5" 2>/dev/null)"
  if grep -qE '<ListBucketResult' <<<"$body"; then
    name="$(grep -oE '<Name>[^<]+</Name>' <<<"$body" | head -1 | sed -E 's,</?Name>,,g')"
    [ -z "$name" ] && name="$host"
    jq -nc --arg h "$host" --arg p "$program" --arg b "$name" \
      --arg u "https://${host}/?list-type=2" \
      '{host:$h,program:$p,bucket:$b,url:$u,src:"build-subdomain-open-list"}'
  fi
}
export -f probe_one

# gentle parallelism (multithread doctrine: cap ~8)
while IFS=$'\t' read -r host program; do
  [ -z "$host" ] && continue
  printf '%s\t%s\n' "$host" "$program"
done < "$CAND" \
 | xargs -P 8 -I{} bash -c 'IFS=$'"'"'\t'"'"' read -r h p <<<"$1"; probe_one "$h" "$p"' _ {} \
 >> "$OUT" 2>/dev/null

echo "[build-prong] OPEN buckets found: $(wc -l < "$OUT" | tr -d ' ')" >&2
cat "$OUT" >&2

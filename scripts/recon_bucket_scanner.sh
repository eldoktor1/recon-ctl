#!/usr/bin/env bash
# =============================================================================
# recon_bucket_scanner.sh — cloud-bucket exposure lane (backend: S3Scanner sa7mon v3)
#
# THE EDGE (the MOTTO): we do NOT blind-permute bucket names (the dup-magnet +
# third-party-data risk everyone runs). We mine the TARGET'S OWN surface
# (jsintel endpoints + the params catalog) for bucket references — Lane A — so
# every candidate is PROVENANCE-CONFIRMED (the in-scope host itself references
# it) before we ever touch the provider. Then S3Scanner READ-ONLY grades the
# ACL/permissions, and we classify CONFIRMED-vs-LEAD.
#
# SAFETY (read docs/knowledge/class-bucket-exposure.md):
#   - Unattended loop is GET-ONLY: HeadBucket (read) + GetBucketAcl (read-acl,
#     reveals WRITE grants when the ACL is world-readable) + (on `check`)
#     ListObjectsV2 key listing. S3Scanner v3 has NO destructive flag — PutObject
#     /DeleteObject/PutBucketAcl never fire.
#   - Public-WRITE: auto-detected when the ACL is world-readable. For the rarer
#     ACL-private-but-writable case, `writecheck` uses the Detectify invalid-MD5
#     PUT (zero object written) — a PUT method so it is OPERATOR-ON-DEMAND only,
#     never in the unattended loop. The benign-marker upload PoC is human-in-loop.
#   - Provenance + per-asset scope + pays gate on the source host before scanning.
#   - Anti-burn: few threads, bounded batch, 7d re-scan cooldown. Egress = the AWS/
#     GCS frontend (NOT the bug-bounty target) and stays on Mullvad via run_scanner.
#
# ROUTING:
#   public-write / write-acl / full-control  → CONFIRMED → db_confirm (Claude VERIFY
#                                              → #review/SUBMIT) + confirmed.jsonl + ES.
#   public-read / read-acl                    → LEAD → leads.jsonl + ES + briefing
#                                              (verify content sensitivity / not by-design).
#   NoSuchBucket referenced by a live host    → dangling-takeover LEAD (→ takeover lane) + note.
#   exists-but-403 (secure)                   → FP → note 2-3 representatives, drop.
#
# USAGE:
#   recon_bucket_scanner.sh [scan]          one bounded cycle (daemon entry)
#   recon_bucket_scanner.sh check  <bucket> [provider]   on-demand single bucket (+enumerate keys)
#   recon_bucket_scanner.sh writecheck <bucket> [region] SAFE invalid-MD5 write test (AWS, zero-write)
#   recon_bucket_scanner.sh seed   [--max N]             print mined candidates (debug)
#   recon_bucket_scanner.sh results [N] | list           recent confirmed + leads
# =============================================================================
set -uo pipefail
IFS=$'\n\t'

log()  { printf '[%s BUCKETS] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s BUCKETS WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/recon_net.sh"
setup_es_netrc
ES_AUTH=(--netrc-file "$HOME/.recon_es_netrc")

BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"
INDEX_NAME="${INDEX_NAME:-recon_alive}"
SCOPE_CHECK="${SCOPE_CHECK:-$SCRIPT_DIR/recon_scope_check.sh}"
HELPER="$SCRIPT_DIR/recon_bucket_scanner.py"

BUCKET_DIR="$BASE_DIR/buckets"
CONFIRMED="$BUCKET_DIR/confirmed.jsonl"
LEADS="$BUCKET_DIR/leads.jsonl"
SCANNED="$BUCKET_DIR/scanned.tsv"          # bucket<TAB>provider<TAB>epoch  (dedup ledger)
WORK="$BUCKET_DIR/work"
LOCK_FILE="$STATE_DIR/buckets.lock"
NOTES_FILE="${NOTES_FILE:-$STATE_DIR/host_notes.jsonl}"

JSINTEL="${JSINTEL:-$BASE_DIR/js_recon/endpoints.jsonl}"
PARAMS_DIR="${PARAMS_DIR:-$BASE_DIR/params}"
S3SCANNER_BIN="${S3SCANNER_BIN:-$(command -v s3scanner || echo "$HOME/go/bin/s3scanner")}"

# tunables (anti-burn; KB: cap ~3-5 threads, bound batch, long cycle)
BUCKETS_BATCH="${BUCKETS_BATCH:-120}"          # candidate buckets scanned per cycle
BUCKETS_THREADS="${BUCKETS_THREADS:-3}"        # s3scanner threads
BUCKETS_COOLDOWN_DAYS="${BUCKETS_COOLDOWN_DAYS:-7}"
BUCKETS_MAX_RUNTIME="${BUCKETS_MAX_RUNTIME:-600}"
BUCKETS_NOTE_FP="${BUCKETS_NOTE_FP:-3}"        # secure-403 reps to note per cycle

mkdir -p "$BUCKET_DIR" "$WORK" "$STATE_DIR" 2>/dev/null || true
touch "$CONFIRMED" "$LEADS" "$SCANNED" 2>/dev/null || true

command -v jq >/dev/null 2>&1 || { warn "jq missing"; exit 0; }

# Fail-closed VPN gate for target-facing subcommands (on-demand invocations bypass
# the daemon's run_scanner gate, so re-check here — egress must be Mullvad).
vpn_gate() {
  if [[ -f "$STATE_DIR/vpn_down" ]]; then
    warn "VPN down (state/vpn_down) — refusing target-facing bucket work (fail-closed)"
    exit 0
  fi
}

# ES full-text widening: pull IN-SCOPE recon_alive docs whose url/final_url/cname reference a
# bucket provider. The triage_in_scope filter makes .host trustworthy provenance; cname-fronted
# buckets surfaced here aren't in jsintel/params (the widening). Emits {host,program,text} JSONL.
es_bucket_refs() {
  local q
  q='{"size":3000,"_source":["host","triage_program","url","final_url","cname","title"],
      "query":{"bool":{
        "filter":[{"term":{"triage_in_scope":true}}],
        "must_not":[{"range":{"ignore_expires_at":{"gt":"now"}}}],
        "minimum_should_match":1,
        "should":[
          {"wildcard":{"url":"*amazonaws.com*"}},{"wildcard":{"final_url":"*amazonaws.com*"}},{"wildcard":{"cname":"*amazonaws.com*"}},
          {"wildcard":{"url":"*storage.googleapis.com*"}},{"wildcard":{"final_url":"*storage.googleapis.com*"}},{"wildcard":{"cname":"*storage.googleapis.com*"}},
          {"wildcard":{"url":"*digitaloceanspaces.com*"}},{"wildcard":{"final_url":"*digitaloceanspaces.com*"}},{"wildcard":{"cname":"*digitaloceanspaces.com*"}},
          {"wildcard":{"url":"*blob.core.windows.net*"}},{"wildcard":{"final_url":"*blob.core.windows.net*"}},{"wildcard":{"cname":"*blob.core.windows.net*"}}
        ]}}}'
  curl -sS -m30 "${ES_AUTH[@]}" -H 'Content-Type: application/json' \
    -X POST "$ES_URL/$INDEX_NAME/_search" -d "$q" 2>/dev/null \
    | jq -c '.hits.hits[]?._source
        | {host:(.host//""), program:(.triage_program//""),
           text:([.url,.final_url,.cname,.title]|map(select(.!=null))|join(" "))}' 2>/dev/null || true
}

es_stamp() {   # best-effort: stamp bucket result onto the source host's recon_alive doc
  local host="$1" bucket="$2" access="$3" sev="$4"
  [[ -z "$host" ]] && return 0
  local now; now="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  curl -sS -m 15 "${ES_AUTH[@]}" -H 'Content-Type: application/json' \
    -X POST "$ES_URL/$INDEX_NAME/_update/$host" \
    -d "$(jq -nc --arg b "$bucket" --arg a "$access" --arg s "$sev" --arg n "$now" \
      '{doc:{bucket_name:$b,bucket_access:$a,bucket_severity:$s,bucket_scan_at:$n}}')" \
    >/dev/null 2>&1 || true
}

# -----------------------------------------------------------------------------
# writecheck — SAFE public-WRITE detection (Detectify invalid-Content-MD5 trick).
# Sends an anonymous PutObject whose Content-MD5 cannot match the body. AWS checks
# the checksum AFTER the access check but BEFORE writing, so:
#   AccessDenied            → NOT writable
#   BadDigest/InvalidDigest → WRITABLE, with NOTHING written (zero state change)
# AWS only (the ordering is verified for S3, not other providers). On-demand.
# -----------------------------------------------------------------------------
cmd_writecheck() {
  vpn_gate
  local bucket="${1:?usage: writecheck <bucket> [region]}" region="${2:-us-east-1}"
  command -v aws >/dev/null 2>&1 || { warn "aws cli missing"; exit 1; }
  local key out
  key="recon-writecheck-$$-$(date +%s).txt"
  log "writecheck $bucket (region $region) — invalid-MD5 anonymous PUT (zero-write)"
  out="$(aws s3api put-object --bucket "$bucket" --key "$key" \
        --content-md5 "AAAAAAAAAAAAAAAAAAAAAA==" --no-sign-request \
        --region "$region" 2>&1)" || true
  if grep -qiE 'BadDigest|InvalidDigest|Content-MD5' <<<"$out"; then
    echo "WRITABLE — anonymous PutObject accepted (checksum rejected; NOTHING written): $bucket"
    echo "  → operator: prove with a UNIQUE-key benign marker (upload→screenshot→delete), then report HIGH."
    return 0
  elif grep -qiE 'AccessDenied|all access.*disabled|InvalidAccessKeyId' <<<"$out"; then
    echo "not writable (AccessDenied): $bucket"
    return 0
  else
    echo "inconclusive: $bucket"
    echo "$out" | head -3
    return 0
  fi
}

# -----------------------------------------------------------------------------
# run S3Scanner read-only over a per-provider bucket-name file → JSONL on stdout
# -----------------------------------------------------------------------------
run_s3scanner() {   # <provider> <bucket-name-file> [extra-args...]
  local provider="$1" file="$2"; shift 2
  [[ -x "$S3SCANNER_BIN" ]] || { warn "s3scanner not found ($S3SCANNER_BIN)"; return 1; }
  [[ -s "$file" ]] || return 0
  timeout --kill-after=20 "$BUCKETS_MAX_RUNTIME" \
    "$S3SCANNER_BIN" -provider "$provider" -bucket-file "$file" -json \
    -threads "$BUCKETS_THREADS" "$@" 2>/dev/null \
    | jq -c 'select(.bucket?.name)' 2>/dev/null || true
}

# Authoritative anonymous LIST probe — the real primitive (200 + <ListBucketResult>),
# region-aware + path-style so it (a) catches public-read that S3Scanner's HeadBucket
# check misses (proven: a real Comcast public bucket read=2/unknown), and (b) handles
# dotted bucket names that can't use a TLS virtual-host. Read-only GET, Mullvad egress.
# Echoes: "<PUBLIC|DENIED|GONE|UNKNOWN> <region>"
read_probe() {   # <provider> <bucket>
  local provider="$1" bucket="$2" region="" url body code
  case "$provider" in
    aws)
      # x-amz-bucket-region is returned even on a 403, so we learn the region first
      region="$(curl -sS -m12 -o /dev/null -D - "https://s3.amazonaws.com/$bucket" 2>/dev/null \
                | tr -d '\r' | awk -F': ' 'tolower($1)=="x-amz-bucket-region"{print $2; exit}')"
      [[ -z "$region" ]] && region="us-east-1"
      url="https://s3.$region.amazonaws.com/$bucket?list-type=2&max-keys=1"
      ;;
    gcp)         url="https://storage.googleapis.com/$bucket?max-keys=1" ;;
    *)           echo "UNKNOWN $region"; return 0 ;;   # DO/others: trust s3scanner
  esac
  body="$(curl -sS -m15 -w $'\n%{http_code}' "$url" 2>/dev/null)"
  code="$(printf '%s' "$body" | tail -n1)"
  body="$(printf '%s' "$body" | sed '$d')"
  if [[ "$code" == "200" ]] && grep -qE '<ListBucketResult|<Contents>|<Name>' <<<"$body"; then
    echo "PUBLIC $region"
  elif [[ "$code" == "403" ]]; then echo "DENIED $region"
  elif [[ "$code" == "404" ]]; then echo "GONE $region"
  else echo "UNKNOWN $region"; fi
}

# Resolve READ authoritatively for exists=1 buckets that S3Scanner left non-public
# (read != allowed) and that have no write grant — rewrite perm_all_users_read +
# region from the real list probe. Positive S3Scanner reads/writes are trusted as-is.
augment_reads() {   # <dedup-results-file> -> augmented JSONL on stdout
  local f="$1" line name prov exists rd w wacl full res st reg nr
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    name="$(jq -r '.bucket.name' <<<"$line")"
    prov="$(jq -r '.bucket.provider' <<<"$line")"
    exists="$(jq -r '.bucket.exists' <<<"$line")"
    rd="$(jq -r '.bucket.perm_all_users_read' <<<"$line")"
    w="$(jq -r '.bucket.perm_all_users_write' <<<"$line")"
    wacl="$(jq -r '.bucket.perm_all_users_write_acl' <<<"$line")"
    full="$(jq -r '.bucket.perm_all_users_full_control' <<<"$line")"
    if [[ "$exists" == "1" && "$rd" != "1" && "$w" != "1" && "$wacl" != "1" && "$full" != "1" ]]; then
      res="$(read_probe "$prov" "$name")"; st="${res%% *}"; reg="${res#* }"
      case "$st" in
        PUBLIC) nr=1 ;;
        DENIED) nr=0 ;;
        GONE)   line="$(jq -c '.bucket.exists=0' <<<"$line")"; nr="$rd" ;;
        *)      nr="$rd" ;;
      esac
      line="$(jq -c --argjson nr "$nr" --arg reg "$reg" \
        '.bucket.perm_all_users_read=$nr | (if ($reg|length)>0 then .bucket.region=$reg else . end)' <<<"$line")"
    fi
    printf '%s\n' "$line"
  done < "$f"
}

# -----------------------------------------------------------------------------
# emit a classified verdict line → the right lane
# -----------------------------------------------------------------------------
route_verdict() {   # reads one verdict JSON object on $1
  local v="$1"
  local kind verdict host bucket provider region url access sev program now
  kind="$(jq -r '.kind' <<<"$v")"
  verdict="$(jq -r '.verdict' <<<"$v")"
  host="$(jq -r '.host // ""' <<<"$v")"
  bucket="$(jq -r '.bucket' <<<"$v")"
  provider="$(jq -r '.provider' <<<"$v")"
  region="$(jq -r '.region // ""' <<<"$v")"
  url="$(jq -r '.url' <<<"$v")"
  access="$(jq -r '.access' <<<"$v")"
  sev="$(jq -r '.severity' <<<"$v")"
  program="$(jq -r '.program // ""' <<<"$v")"
  now="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

  case "$kind" in
    public-write)
      # CONFIRMED. db_confirm → Claude VERIFY adversarial panel → #review/SUBMIT.
      local score=9; [[ "$sev" == "critical" ]] && score=10
      printf '%s\n' "$(jq -c --arg ts "$now" '. + {ts:$ts}' <<<"$v")" >> "$CONFIRMED"
      local ev; ev="$(jq -nc --arg b "$bucket" --arg p "$provider" --arg r "$region" \
        --arg a "$access" --arg su "$(jq -r '.source_url // ""' <<<"$v")" \
        '{bucket:$b,provider:$p,region:$r,access:$a,source_url:$su}')"
      db_confirm "$host" "$url" "$program" "bucket-exposure" "public-write-bucket" \
                 "$score" "0.9" "$ev"
      es_stamp "$host" "$bucket" "$access" "$sev"
      log "CONFIRMED public-write: $bucket ($provider) ← $host [$sev]"
      ;;
    public-read|public-read-acl)
      printf '%s\n' "$(jq -c --arg ts "$now" '. + {ts:$ts}' <<<"$v")" >> "$LEADS"
      es_stamp "$host" "$bucket" "$access" "$sev"
      log "LEAD $kind: $bucket ($provider) ← $host"
      ;;
    dangling-takeover)
      printf '%s\n' "$(jq -c --arg ts "$now" '. + {ts:$ts}' <<<"$v")" >> "$LEADS"
      note_host "$host" "bucket $bucket ($provider) referenced but NoSuchBucket — dangling-bucket takeover lead (verify claimable → takeover lane)" "buckets"
      log "LEAD dangling-takeover: $bucket ($provider) ← $host"
      ;;
    secure)
      return 1   # caller batches secure reps for representative noting
      ;;
    *)           # inconclusive (exists but access undetermined) → drop silently
      return 2
      ;;
  esac
  return 0
}

note_host() {   # host text source  → recon-note (best-effort; mirrors into ES via ledger)
  local host="$1" text="$2" src="${3:-buckets}"
  [[ -z "$host" ]] && return 0
  bash "$SCRIPT_DIR/recon_ctl.sh" note "$host" "$text" >/dev/null 2>&1 || true
}

# -----------------------------------------------------------------------------
# scan — one bounded cycle
# -----------------------------------------------------------------------------
cmd_scan() {
  vpn_gate
  [[ -x "$S3SCANNER_BIN" ]] || { warn "s3scanner not installed — skipping"; exit 0; }

  exec 9>"$LOCK_FILE"
  flock -n 9 || { log "another bucket scan running"; exit 0; }

  local cand="$WORK/candidates.jsonl" gated="$WORK/gated.jsonl"
  : > "$cand"; : > "$gated"

  # ---- 1) Lane A: mine the target's OWN surface for bucket refs (jsintel + params + ES full-text) ----
  local esrefs="$WORK/es_refs.jsonl"; es_bucket_refs > "$esrefs" 2>/dev/null || : > "$esrefs"
  log "ES full-text refs: $(wc -l < "$esrefs" | tr -d ' ') in-scope host(s) referencing a bucket"
  python3 "$HELPER" extract --jsintel "$JSINTEL" --params-dir "$PARAMS_DIR" --es-refs "$esrefs" > "$cand" 2>/dev/null || true
  local ncand; ncand="$(wc -l < "$cand" | tr -d ' ')"
  [[ "$ncand" -eq 0 ]] && { log "no bucket references mined from surface"; exit 0; }
  log "mined $ncand candidate bucket(s) from target surface"

  # ---- 2) provenance + per-asset scope + pays gate (drop no-provenance + OOS) ----
  local inscope; inscope="$WORK/inscope_hosts.txt"
  jq -r 'select(.source_host != "") | .source_host' "$cand" | sort -u \
    | bash "$SCOPE_CHECK" --filter in-scope-paying 2>/dev/null | sort -u > "$inscope" || true
  if [[ ! -s "$inscope" ]]; then
    log "no candidate source-host is in-scope+paying — nothing to scan"
    exit 0
  fi
  # keep only candidates whose source host passed (provenance + scope + pays)
  jq -c 'select(.source_host != "")' "$cand" \
    | while IFS= read -r c; do
        sh="$(jq -r '.source_host' <<<"$c")"
        grep -qxF "$sh" "$inscope" && printf '%s\n' "$c"
      done > "$gated" || true
  local ngated; ngated="$(wc -l < "$gated" | tr -d ' ')"
  [[ "$ngated" -eq 0 ]] && { log "0 candidates after scope/pays gate"; exit 0; }

  # ---- 3) dedup vs 7d cooldown ledger, then cap the batch ----
  local cutoff; cutoff=$(( $(date +%s) - BUCKETS_COOLDOWN_DAYS*86400 ))
  local batch="$WORK/batch.jsonl"; : > "$batch"
  local kept=0
  while IFS= read -r c; do
    [[ "$kept" -ge "$BUCKETS_BATCH" ]] && break
    local b p last
    b="$(jq -r '.bucket' <<<"$c")"; p="$(jq -r '.provider' <<<"$c")"
    last="$(awk -F'\t' -v b="$b" -v p="$p" '$1==b && $2==p {print $3}' "$SCANNED" | tail -1)"
    [[ -n "$last" && "$last" =~ ^[0-9]+$ && "$last" -gt "$cutoff" ]] && continue
    printf '%s\n' "$c" >> "$batch"; kept=$((kept+1))
  done < "$gated"
  [[ "$kept" -eq 0 ]] && { log "all $ngated in-scope candidates within cooldown — nothing fresh"; exit 0; }
  log "scanning $kept bucket(s) (after scope+cooldown of $ngated in-scope)"

  # ---- 4) per-provider S3Scanner read-only ----
  local results="$WORK/results.jsonl"; : > "$results"
  local prov
  for prov in aws gcp digitalocean; do
    local nf="$WORK/names_$prov.txt"
    jq -r --arg p "$prov" 'select(.provider==$p) | .bucket' "$batch" | sort -u > "$nf"
    [[ -s "$nf" ]] || continue
    log "  s3scanner -provider $prov : $(wc -l < "$nf" | tr -d ' ') name(s)"
    run_s3scanner "$prov" "$nf" >> "$results" || true
  done
  # azure refs can't be scanned by s3scanner → record as manual leads
  jq -c 'select(.provider=="azure")' "$batch" 2>/dev/null | while IFS= read -r c; do
    jq -c '. + {kind:"manual-azure",verdict:"lead",severity:"info",
                access:"azure blob (no s3scanner support — inspect manually)",
                host:(.source_host),url:("https://"+.bucket+".blob.core.windows.net/")}' <<<"$c" >> "$LEADS"
  done

  # ---- 5) record scanned (dedup ledger) for everything attempted ----
  local nowep; nowep="$(date +%s)"
  jq -r '[.bucket,.provider] | @tsv' "$batch" | while IFS=$'\t' read -r b p; do
    printf '%s\t%s\t%s\n' "$b" "$p" "$nowep" >> "$SCANNED"
  done

  [[ -s "$results" ]] || { log "no s3scanner results this cycle"; exit 0; }

  # ---- 6) dedup (region-redirect emits 2 identical lines) → authoritative read probe → classify ----
  local dedup="$WORK/results.dedup.jsonl" augmented="$WORK/results.aug.jsonl"
  jq -s -c 'group_by(.bucket.name)[] | max_by(.bucket.exists)' "$results" > "$dedup" 2>/dev/null || cp "$results" "$dedup"
  augment_reads "$dedup" > "$augmented"

  local verdicts="$WORK/verdicts.jsonl"
  python3 "$HELPER" classify --results "$augmented" --candidates "$batch" > "$verdicts" 2>/dev/null || true

  local nconf=0 nlead=0 nsecure=0 ninc=0 rc
  local secure_reps="$WORK/secure_reps.jsonl"; : > "$secure_reps"
  while IFS= read -r v; do
    [[ -z "$v" ]] && continue
    route_verdict "$v"; rc=$?
    case "$rc" in
      0) case "$(jq -r '.kind' <<<"$v")" in
           public-write) nconf=$((nconf+1)) ;;
           *) nlead=$((nlead+1)) ;;
         esac ;;
      1) nsecure=$((nsecure+1)); printf '%s\n' "$v" >> "$secure_reps" ;;
      *) ninc=$((ninc+1)) ;;
    esac
  done < "$verdicts"

  # note 2-3 secure (403) representatives per cycle (doctrine: cluster → reps + class-reason)
  if [[ "$nsecure" -gt 0 ]]; then
    local noted=0
    while IFS= read -r v; do
      [[ "$noted" -ge "$BUCKETS_NOTE_FP" ]] && break
      local h b; h="$(jq -r '.host' <<<"$v")"; b="$(jq -r '.bucket' <<<"$v")"
      note_host "$h" "bucket $b exists but returns 403/AccessDenied (secure) — not exposed; ${nsecure} such this cycle" "buckets"
      noted=$((noted+1))
    done < "$secure_reps"
  fi

  log "cycle done — ✅ $nconf public-write · 🟡 $nlead read/acl/takeover leads · 🔒 $nsecure secure(403) · ❔ $ninc inconclusive"
}

# -----------------------------------------------------------------------------
# check — on-demand single bucket (with object-key listing for sensitivity triage)
# -----------------------------------------------------------------------------
cmd_check() {
  vpn_gate
  local bucket="${1:?usage: check <bucket> [provider]}" provider="${2:-aws}"
  [[ -x "$S3SCANNER_BIN" ]] || { warn "s3scanner not installed"; exit 1; }
  local nf; nf="$(mktemp)"; printf '%s\n' "$bucket" > "$nf"
  local res; res="$(run_s3scanner "$provider" "$nf" -enumerate)"
  rm -f "$nf"
  [[ -z "$res" ]] && { echo "no result for $bucket"; exit 0; }
  local cand; cand="$(jq -nc --arg b "$bucket" --arg p "$provider" '{provider:$p,bucket:$b,source_host:"",program:"",source_url:""}')"
  local cf; cf="$(mktemp)"; printf '%s\n' "$cand" > "$cf"
  local rf; rf="$(mktemp)"; printf '%s\n' "$res" > "$rf"
  python3 "$HELPER" classify --results "$rf" --candidates "$cf" \
    | jq -r '"\(.kind | ascii_upcase) [\(.severity)] \(.bucket) (\(.provider)\(if .region!="" then "/"+.region else "" end))\n  access: \(.access)\n  url:    \(.url)\n  objects: \(.num_objects)\(if (.sample_keys|length)>0 then "  keys: "+(.sample_keys|join(", ")) else "" end)"'
  rm -f "$cf" "$rf"
}

cmd_results() {
  local n="${1:-15}"
  echo "== CONFIRMED public-write =="
  tail -n "$n" "$CONFIRMED" 2>/dev/null | jq -r '"\(.ts // "?")  \(.severity)  \(.bucket) (\(.provider)) ← \(.host)  [\(.access)]"' 2>/dev/null || true
  echo
  echo "== LEADS (read / read-acl / takeover) =="
  tail -n "$n" "$LEADS" 2>/dev/null | jq -r '"\(.ts // "?")  \(.kind)  \(.bucket) (\(.provider)) ← \(.host // .source_host)  [\(.access)]"' 2>/dev/null || true
}

# -----------------------------------------------------------------------------
case "${1:-scan}" in
  scan|"")        cmd_scan ;;
  check)          shift; cmd_check "$@" ;;
  writecheck)     shift; cmd_writecheck "$@" ;;
  seed)           shift
                  mx=100000; [[ "${1:-}" == "--max" ]] && mx="${2:-100000}"
                  seed_es="$(mktemp)"; es_bucket_refs > "$seed_es" 2>/dev/null || true
                  python3 "$HELPER" extract --jsintel "$JSINTEL" --params-dir "$PARAMS_DIR" --es-refs "$seed_es" --max "$mx"
                  rm -f "$seed_es" ;;
  results|list)   shift; cmd_results "$@" ;;
  *) echo "usage: $0 [scan|check <bucket> [provider]|writecheck <bucket> [region]|seed|results [N]]" >&2; exit 2 ;;
esac

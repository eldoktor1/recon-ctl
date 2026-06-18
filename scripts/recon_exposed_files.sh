#!/usr/bin/env bash
# =============================================================================
# recon_exposed_files.sh — high-signal EXPOSED-FILE / SERVICE confirmer (audit fix #9).
#
# U1 only mines JS-derived routes; the classic high-signal exposed surface (.git / .env /
# Spring actuator / swagger) was never ACTIVELY probed. This lane fixes that: for fresh
# in-scope+paying hosts it GETs a curated set of paths via the vetted recon_safe_probe.sh
# and confirms ONLY on a CONTENT SIGNATURE (not status 200 — kills SPA-shell/HTML FPs):
#   /.git/HEAD        -> "ref: refs/heads/" | 40-hex sha     (source-code exposure)
#   /.git/config      -> "[core]" + repositoryformatversion
#   /.env             -> KEY=VALUE w/ sensitive keys, non-HTML (creds)
#   /actuator/env     -> JSON "propertySources"              (Spring secrets; CVE-2026-40976)
#   /actuator/heapdump-> octet-stream / heapdump disposition / big  (heap -> AWS creds)
#   /actuator         -> JSON _links + actuator              (LEAD to the juicy endpoints)
#   /swagger|/openapi|/api-docs -> JSON swagger/openapi/paths (API surface disclosure)
# Confirmed -> state.py record-confirmed -> ai-pending -> 2IC verify -> SUBMIT. Evidence is
# REDACTED (signature + counts, never the raw secret). GET-only, in-scope+pays+VPN+rate-limited.
# Target-facing -> run via run_scanner (reconrun) from the daemon. Killswitch v2_exposed_files.
# =============================================================================
set -uo pipefail
IFS=$'\n\t'
log()  { printf '[%s EXPFILES] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s EXPFILES WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/recon_net.sh" 2>/dev/null || true; setup_es_netrc 2>/dev/null || true
BASE_DIR="${BASE_DIR:-$HOME/recon}"; STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
V3_DB="${V3_DB:-$BASE_DIR/v3/findings.db}"; STATE_PY="${STATE_PY:-$REPO_DIR/engine/state.py}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"; INDEX_NAME="${INDEX_NAME:-recon_alive}"
NETRC="${NETRC:-$HOME/.recon_es_netrc}"
SAFE_PROBE="${SAFE_PROBE:-$SCRIPT_DIR/recon_safe_probe.sh}"
SEEN="${EXPFILES_SEEN:-$STATE_DIR/exposed_files_seen.tsv}"
EXPFILES_HOSTS="${EXPFILES_HOSTS:-20}"        # hosts per cycle
COOLDOWN_SECS="${EXPFILES_COOLDOWN:-1209600}" # 14d per host

es() { curl -fsS -m 20 --netrc-file "$NETRC" -H 'Content-Type: application/json' "$@"; }
mkdir -p "$STATE_DIR" "$(dirname "$V3_DB")" 2>/dev/null || true
exec 9>"$STATE_DIR/exposed_files.lock"; flock -n 9 || { warn "already running"; exit 0; }
[[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down — skipping (fail-closed)"; exit 0; }
command -v jq >/dev/null 2>&1 || { warn "jq missing"; exit 0; }
command -v python3 >/dev/null 2>&1 || { warn "python3 missing"; exit 0; }
[[ -f "$SAFE_PROBE" ]] || { warn "safe probe missing"; exit 0; }
NOW="$(date -u +%s)"
if [[ -f "$SEEN" ]]; then awk -F'\t' -v cut="$((NOW-COOLDOWN_SECS))" 'NF>=2 && ($2+0)>=cut' "$SEEN" > "$SEEN.tmp" 2>/dev/null && mv "$SEEN.tmp" "$SEEN" 2>/dev/null || true; fi
seen_recent() { [[ -f "$SEEN" ]] && awk -F'\t' -v h="$1" -v cut="$((NOW-COOLDOWN_SECS))" 'NF>=2 && $1==h && ($2+0)>=cut{f=1} END{exit f?0:1}' "$SEEN"; }
mark_seen() { printf '%s\t%s\n' "$1" "$(date -u +%s)" >> "$SEEN" 2>/dev/null || true; }

# candidate hosts: in-scope+paying, not benched, freshest first
q="$(jq -nc --argjson n "$EXPFILES_HOSTS" '{size:($n*3),_source:["host","triage_program"],
  query:{bool:{filter:[{term:{triage_in_scope:true}},{term:{triage_pays:true}}],
               must_not:[{term:{triage_out_of_scope:true}},{range:{ignore_expires_at:{gt:"now"}}}]}},
  sort:[{triage_true_fresh:{order:"desc",missing:"_last"}},{triage_score:{order:"desc",missing:"_last"}}]}')"
mapfile -t cand < <(es "$ES_URL/$INDEX_NAME/_search" -d "$q" 2>/dev/null \
  | jq -r '.hits.hits[]._source | [.host,(.triage_program//"")] | @tsv' 2>/dev/null)
[[ "${#cand[@]}" -gt 0 ]] || { log "no candidate hosts"; exit 0; }

PATHS=( "/.git/HEAD|git" "/.git/config|gitconfig" "/.env|env" "/actuator/env|actuator-env"
        "/actuator/heapdump|actuator-heapdump" "/actuator|actuator-index"
        "/swagger.json|swagger" "/openapi.json|swagger" "/v3/api-docs|swagger" "/api-docs|swagger" )

# classify: stdin probe JSON, $1=type -> prints "conf|signal_class|vuln_class|reason" or nothing
classify() {
  local type="$1" pj; pj="$(cat)"
  local st ct body bytes cdisp
  st="$(printf '%s' "$pj" | jq -r '.status // 0' 2>/dev/null)"
  [[ "$st" == "200" ]] || return 0
  ct="$(printf '%s' "$pj" | jq -r '(.headers["content-type"]//"")|ascii_downcase' 2>/dev/null)"
  body="$(printf '%s' "$pj" | jq -r '.body_snippet // ""' 2>/dev/null)"
  bytes="$(printf '%s' "$pj" | jq -r '.body_bytes // 0' 2>/dev/null)"
  cdisp="$(printf '%s' "$pj" | jq -r '(.headers["content-disposition"]//"")|ascii_downcase' 2>/dev/null)"
  # universal HTML/SPA-shell guard for the text types
  case "$type" in
    git|gitconfig|env) printf '%s' "$body" | grep -qiE '<html|<!doctype html' && return 0 ;;
  esac
  case "$type" in
    git)        printf '%s' "$body" | grep -qE '^ref: refs/heads/|^[0-9a-f]{40}' && echo "0.85|exposed-git|info-disclosure|/.git/HEAD exposed (ref: refs/heads — source-code reconstruction possible)";;
    gitconfig)  { printf '%s' "$body" | grep -qF '[core]' && printf '%s' "$body" | grep -qi 'repositoryformatversion'; } && echo "0.85|exposed-git|info-disclosure|/.git/config exposed (full repo cloneable)";;
    env)        { printf '%s' "$body" | grep -cE '^[A-Z0-9_]+=' | grep -qvx 0; } 2>/dev/null && printf '%s' "$body" | grep -qiE '(secret|passw|api[_-]?key|aws_|token|db_|database_url|private_key)' && echo "0.85|exposed-env|data-leak|/.env exposed with credential-shaped keys";;
    actuator-env)       { [[ "$ct" == *json* ]] && printf '%s' "$body" | grep -qi 'propertysources'; } && echo "0.9|exposed-actuator|data-leak|Spring /actuator/env exposed (property sources / secrets; cf CVE-2026-40976)";;
    actuator-heapdump)  { [[ "$ct" == *octet-stream* || "$cdisp" == *heapdump* ]] || [[ "${bytes:-0}" -gt 200000 ]]; } && echo "0.9|exposed-actuator-heapdump|data-leak|Spring /actuator/heapdump downloadable (heap → live creds/tokens)";;
    actuator-index)     { [[ "$ct" == *json* ]] && printf '%s' "$body" | grep -qi '_links' && printf '%s' "$body" | grep -qi 'actuator'; } && echo "0.7|exposed-actuator|info-disclosure|/actuator index exposed (enumerate env/heapdump/mappings)";;
    swagger)    { [[ "$ct" == *json* ]] && printf '%s' "$body" | grep -qiE '"(swagger|openapi)"' || { printf '%s' "$body" | grep -qF '"paths"' && printf '%s' "$body" | grep -qF '"info"'; }; } && echo "0.7|exposed-swagger|info-disclosure|swagger/openapi spec exposed (full API surface)";;
  esac
}

probed=0; confirmed=0; hosts_done=0
for line in "${cand[@]}"; do
  [[ "$hosts_done" -ge "$EXPFILES_HOSTS" ]] && break
  IFS=$'\t' read -r host program <<<"$line"
  [[ -n "$host" ]] || continue
  seen_recent "$host" && continue
  [[ -f "$STATE_DIR/vpn_down" ]] && break
  reachable=0
  for pt in "${PATHS[@]}"; do
    p="${pt%%|*}"; type="${pt##*|}"
    url="https://${host}${p}"
    pj="$(bash "$SAFE_PROBE" "$url" GET 2>/dev/null)"
    err="$(printf '%s' "$pj" | jq -r '.error // ""' 2>/dev/null)"
    case "$err" in
      *out-of-scope*|*nonpaying*) reachable=-1; break ;;
      *global-probe-pause*) log "global probe pause — ending cycle"; mark_seen "$host"; break 2 ;;
      *rate-limited*|*cooldown*) sleep 3; continue ;;
    esac
    reachable=1; probed=$((probed+1))
    verdict="$(printf '%s' "$pj" | classify "$type")"
    [[ -n "$verdict" ]] || continue
    IFS='|' read -r conf sigcls vuln reason <<<"$verdict"
    ev="$(jq -nc --arg u "$url" --arg r "$reason" --arg ct "$(printf '%s' "$pj" | jq -r '(.headers["content-type"]//"")' 2>/dev/null)" \
          '{probe:"exposed-file",url:$u,content_type:$ct,reason:$r}' 2>/dev/null)"
    V3_DB="$V3_DB" python3 "$STATE_PY" record-confirmed "$host" "$url" "$program" "$sigcls" "$vuln" "12" "$conf" "$ev" >/dev/null 2>&1 \
      && { confirmed=$((confirmed+1)); log "   💥 ${sigcls} CONFIRMED · $url (conf $conf)"; }
  done
  [[ "$reachable" -ne 0 ]] && { mark_seen "$host"; hosts_done=$((hosts_done+1)); }
done

log "cycle done · hosts=$hosts_done probed=$probed confirmed=$confirmed"
exit 0

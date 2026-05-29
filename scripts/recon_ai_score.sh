#!/usr/bin/env bash
# Optional local AI review scorer for already-prioritized triage targets.
set -Eeuo pipefail
IFS=$'\n\t'

log()  { printf '[%s AI] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s AI WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="${BASE_DIR:-$HOME/recon}"
AI_DIR="${AI_DIR:-$BASE_DIR/ai_review}"
IN="${1:-$BASE_DIR/triage/agent_targets.jsonl}"
OUT="$AI_DIR/ai_scored.jsonl"
TMP_DIR="$AI_DIR/tmp"
REJECTED_DIR="$AI_DIR/rejected"

OLLAMA_URL="${OLLAMA_URL:-http://127.0.0.1:11434}"
OLLAMA_MODEL_LEAD="${OLLAMA_MODEL_LEAD:-llama3.1:8b-instruct-q4_K_M}"
AI_MAX_LEADS="${AI_MAX_LEADS:-50}"
AI_MIN_SCORE="${AI_MIN_SCORE:-12}"

ES_URL="${ES_URL:-http://127.0.0.1:9200}"
INDEX_NAME="${INDEX_NAME:-recon_alive}"
ES_USER="${ES_USER:-elastic}"
ES_PASS="${ES_PASS:-$(tr -d '[:space:]' < "$HOME/.recon_es_pass" 2>/dev/null || true)}"

mkdir -p "$TMP_DIR" "$REJECTED_DIR"
: > "$OUT"

ai_banner() {
  log '+--------------------------------------------------+'
  log '|  [AI] OLLAMA REVIEW LAYER                       |'
  log '|       deterministic triage is done              |'
  log '|       scoring high-value leads now              |'
  log '+--------------------------------------------------+'
}

extract_ai_json() {
  local raw_file
  raw_file="$(mktemp)"
  cat > "$raw_file"
  set +e
  python3 - "$raw_file" <<'PYEOF'
import json, pathlib, sys

raw = pathlib.Path(sys.argv[1]).read_text(errors="replace").strip()

def valid(obj):
    obj.setdefault("ai_relevance_score", 0)
    obj.setdefault("confidence", "low")
    obj.setdefault("recommendation", "watch")
    obj.setdefault("route", "human")
    obj.setdefault("reason", "")
    obj.setdefault("safe_checks", [])
    obj.setdefault("risk_flags", [])
    return obj

try:
    print(json.dumps(valid(json.loads(raw)), separators=(",", ":")))
    raise SystemExit(0)
except Exception:
    pass

start = raw.find("{")
if start == -1:
    raise SystemExit(1)

depth = 0
in_str = False
esc = False
for i, ch in enumerate(raw[start:], start):
    if in_str:
        if esc:
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == '"':
            in_str = False
        continue
    if ch == '"':
        in_str = True
    elif ch == "{":
        depth += 1
    elif ch == "}":
        depth -= 1
        if depth == 0:
            try:
                obj = json.loads(raw[start:i + 1])
                print(json.dumps(valid(obj), separators=(",", ":")))
                raise SystemExit(0)
            except Exception:
                raise SystemExit(1)

raise SystemExit(1)
PYEOF
  local rc=$?
  set -e
  rm -f "$raw_file"
  return "$rc"
}

[[ -s "$IN" ]] || { log "no triage input"; exit 0; }
curl -fsS -m 3 "$OLLAMA_URL/api/tags" >/dev/null 2>&1 || {
  warn "Ollama not reachable at $OLLAMA_URL; skipping AI scoring"
  exit 0
}
curl -fsS -m 5 "$OLLAMA_URL/api/tags" \
  | jq -e --arg model "$OLLAMA_MODEL_LEAD" '.models[]?.name == $model' >/dev/null 2>&1 || {
    warn "Ollama model not installed: $OLLAMA_MODEL_LEAD; skipping AI scoring"
    exit 0
  }

candidates_tmp="$(mktemp)"
all_candidates_tmp="$(mktemp)"
updates_tmp="$(mktemp)"
trap "rm -f '$updates_tmp' '$candidates_tmp' '$all_candidates_tmp'" EXIT

# v2.6: require in_scope (a real matched program), not merely "not out-of-scope".
# With the AI_MAX_LEADS budget cap, also prioritise the candidates that matter:
# true-fresh first, then paying, then score — so Ollama cycles are spent on
# fresh paying leads, not stale unmatched hosts.
jq -c --argjson min "$AI_MIN_SCORE" '
  select((.priority == "P0" or .priority == "P1") and (.score // 0) >= $min)
  | select((.in_scope // false) == true)
  | select((.out_of_scope // false) == false)
  | select(((.signals // []) | length) > 0)
' "$IN" \
| jq -s -c 'sort_by([ (if (.triage_true_fresh // false) then 0 else 1 end),
                      (if (.pays // false) then 0 else 1 end),
                      -(.score // 0) ]) | .[]' \
> "$all_candidates_tmp"
head -n "$AI_MAX_LEADS" "$all_candidates_tmp" > "$candidates_tmp"

total_candidates="$(wc -l < "$candidates_tmp" | tr -d ' ')"
ai_banner
log "model=$OLLAMA_MODEL_LEAD candidates=$total_candidates max=$AI_MAX_LEADS min_score=$AI_MIN_SCORE"

attempted=0
scored=0
rejected=0

while IFS= read -r lead; do
  attempted=$((attempted + 1))
  host="$(jq -r '.host' <<< "$lead")"
  prompt="$TMP_DIR/${host//[^a-zA-Z0-9_.-]/_}.prompt"
  reject_file="$REJECTED_DIR/${host//[^a-zA-Z0-9_.-]/_}.raw.txt"

  jq -r '
    "You are a senior bug bounty hunter reviewing a pre-filtered recon lead.\n\n" +
    "LEAD SUMMARY:\n" +
    "  score=" + (.score|tostring) + "  priority=" + (.priority // "?") +
    "  payout=" + (.payout_tier // "unclassified") + "\n" +
    "  signals: " + ((.signals // []) | join(", ")) + "\n" +
    "  technologies: " + ((.tech // []) | join(", ")) + "\n" +
    (if ((.cves // []) | length) > 0 then "  CVEs matched: " + ((.cves // []) | join(", ")) + "\n" else "" end) +
    (if .kev_hit // false then "  *** KEV FLAG: actively exploited CVE matched ***\n" else "" end) +
    (if .template_available // false then "  Nuclei template or public PoC exists\n" else "" end) +
    "\nSIGNAL GUIDE (use for safe_checks — passive/low-impact only):\n" +
    "  tech:jenkins        -> /script Groovy console; /asynchPeople user-enum; CVE-2024-23897 CLI file-read\n" +
    "  tech:confluence     -> CVE-2023-22527 OGNL /template/aui/text-inline.vm; CVE-2023-22515 /setup/setupadministrator.action\n" +
    "  tech:gitlab         -> unauthenticated GraphQL introspection; /explore public repos; CVE-2023-7028 ATO\n" +
    "  tech:grafana        -> CVE-2021-43798 GET /public/plugins/alertlist/../../../etc/passwd; /api/datasources\n" +
    "  tech:kibana         -> CVE-2019-7609 Timelion; /api/console/proxy?path=_cat/indices&method=GET\n" +
    "  tech:kubernetes     -> GET /api/v1/secrets unauth; skip-login dashboard; /metrics; pods exec\n" +
    "  tech:argocd         -> /api/v1/applications unauth; CVE-2022-29165; default admin:admin\n" +
    "  tech:rancher        -> CVE-2022-21951; /v3/clusters; default admin:admin\n" +
    "  tech:portainer      -> POST /api/users/admin/init unauth admin creation; CVE-2021-21315\n" +
    "  tech:harbor         -> CVE-2019-16097 unauth admin; /api/v2.0/projects anon list\n" +
    "  tech:docker-registry -> GET /v2/_catalog; /v2/<image>/tags/list; pull for secrets\n" +
    "  tech:es-exposed     -> GET /_cat/indices?v; /_cluster/health; /_nodes\n" +
    "  tech:minio          -> CVE-2023-28432 /minio/health/cluster; default minioadmin:minioadmin\n" +
    "  tech:phpmyadmin     -> default root:root root:(empty); /setup/ misconfig\n" +
    "  tech:adminer        -> CVE-2023-45196 SSRF; localhost connect; blank password\n" +
    "  tech:wordpress      -> /wp-json/wp/v2/users; xmlrpc.php pingback; plugin enum /wp-content/plugins/\n" +
    "  tech:drupal         -> CVE-2018-7600 Drupalgeddon2; /CHANGELOG.txt version\n" +
    "  tech:joomla         -> CVE-2023-23752 /api/index.php/v1/users; /administrator/\n" +
    "  tech:magento        -> CVE-2024-34102 CosmicSting; /admin or /index.php/admin\n" +
    "  tech:spring         -> GET /actuator/env (creds); /actuator/heapdump (tokens); /actuator/mappings\n" +
    "  tech:laravel-debug  -> CVE-2021-3129 /_ignition/execute-solution; .env leak (DEBUG=true)\n" +
    "  tech:laravel-telescope -> GET /telescope (req/auth/db logs); tokens in request logs\n" +
    "  tech:django-debug   -> /admin/ admin:admin; DEBUG=True env/settings\n" +
    "  tech:nextjs         -> CVE-2025-29927 x-middleware-subrequest bypass; /_next/data/<buildId>/index.json\n" +
    "  tech:graphql        -> POST {__schema{types{name}}}; aliases bypass rate limits\n" +
    "  tech:swagger        -> enumerate /admin /internal /debug routes; IDOR/mass-assign from spec\n" +
    "  tech:struts         -> CVE-2023-50164 file upload; CVE-2017-5638 Content-Type OGNL\n" +
    "  tech:weblogic       -> CVE-2020-14882 console bypass; /_async/AsyncResponseService\n" +
    "  tech:citrix         -> CVE-2023-3519 unauth RCE; CVE-2023-4966 Citrix Bleed session token\n" +
    "  tech:fortinet       -> CVE-2024-21762 unauth RCE FortiOS; CVE-2018-13379 path traversal\n" +
    "  tech:ivanti-pulse   -> CVE-2024-21887/CVE-2023-46805 RCE chain; CVE-2019-11510\n" +
    "  tech:vmware         -> CVE-2024-37079 vCenter RCE; CVE-2021-21972 unauth RCE\n" +
    "  tech:f5-bigip       -> CVE-2022-1388 iControl REST unauth RCE\n" +
    "  tech:paloalto       -> CVE-2024-3400 OS cmd injection unauth; CVE-2020-2021 auth bypass\n" +
    "  tech:exchange-owa   -> CVE-2021-26855 ProxyLogon; CVE-2021-34473 ProxyShell\n" +
    "  tech:manageengine   -> CVE-2022-47966 SAML unauth RCE; CVE-2021-44515\n" +
    "  tech:moveit         -> CVE-2023-34362 unauth SQLi→RCE; /human.aspx\n" +
    "  tech:connectwise    -> CVE-2024-1709 ScreenConnect auth bypass + RCE\n" +
    "  tech:veeam          -> CVE-2024-40711 unauth RCE; CVE-2023-27532 cred extraction\n" +
    "  tech:telerik        -> CVE-2019-18935 deserialization; /Telerik.Web.UI.WebResource.axd\n" +
    "  tech:coldfusion     -> CVE-2023-26360 unauth RCE; /CFIDE/administrator/\n" +
    "  tech:thinkphp       -> CVE-2018-20062 /?s=index/think\\app/invokefunction\n" +
    "  tech:airflow        -> default admin:admin; /api/v1/dags; DAG execution = RCE\n" +
    "  tech:nexus          -> CVE-2019-7238 unauth RCE; default admin:admin123\n" +
    "  tech:artifactory    -> /artifactory/api/system/info; /api/repositories anon access\n" +
    "  tech:solr           -> CVE-2019-17558 Velocity RCE; /solr/admin/cores\n" +
    "  tech:activemq       -> CVE-2023-46604 OpenWire RCE; /admin/ admin:admin\n" +
    "  tech:metabase       -> CVE-2023-38646 pre-auth RCE; /api/setup/properties\n" +
    "  tech:superset       -> CVE-2023-27524 default SECRET_KEY session forge to admin\n" +
    "  tech:nifi           -> CVE-2023-34468 H2 driver RCE; /nifi-api/flow/about often unauth\n" +
    "  tech:jupyter        -> code exec by design; check token requirement; /api/kernels\n" +
    "  tech:keycloak       -> /auth/admin/master/console; OAuth/SAML flow flaws\n" +
    "  tech:splunk         -> CVE-2023-46214 RCE; CVE-2024-36991 path traversal\n" +
    "  tech:zimbra         -> CVE-2022-27925 RCE; CVE-2022-37042 auth bypass\n" +
    "  tech:sonarqube      -> CVE-2020-27986 unauth source leak; default admin:admin\n" +
    "  tech:pgadmin        -> CVE-2023-5002 path traversal; CVE-2024-3116 RCE binary path\n" +
    "  tech:hasura         -> /v1/graphql full DB schema if admin secret missing\n" +
    "  tech:glpi           -> CVE-2023-35924 unauth file read; default glpi:glpi\n" +
    "  tech:liferay        -> CVE-2020-7961 unauth RCE deserialization\n" +
    "  tech:sitecore       -> CVE-2021-42237 unauth RCE; /sitecore/login\n" +
    "  tech:aem            -> GET /system/console Felix admin:admin; /crx/de\n" +
    "  tech:tomcat-manager -> GET /manager/html tomcat:tomcat; WAR upload = RCE; CVE-2020-1938 GhostCat\n" +
    "  tech:teamcity       -> CVE-2024-27198 auth bypass; CVE-2024-27199 path traversal\n" +
    "  tech:drone-ci       -> GET /api/user; /api/repos; DRONE_RPC_SECRET extraction\n" +
    "  tech:gitea          -> GET /explore/repos; /api/v1/repos/search; default admin:admin\n" +
    "  tech:zabbix         -> CVE-2022-23131 SAML bypass; default Admin:zabbix\n" +
    "  tech:prometheus     -> GET /metrics; /api/v1/targets; /api/v1/query?query=up\n" +
    "  tech:jira           -> CVE-2019-11581 SSTI RCE; /rest/api/2/user/picker?query=.\n" +
    "  port:docker-api     -> GET /version; /containers/json; POST /containers/create\n" +
    "  port:redis          -> redis-cli INFO; CONFIG SET dir+dbfilename = SSH key write\n" +
    "  port:mongodb        -> mongosh <host> --norc; show dbs; getCollectionNames()\n" +
    "  port:couchdb        -> GET /_all_dbs; CVE-2017-12635 admin party\n" +
    "  port:consul         -> GET /v1/agent/self; /v1/kv/?recurse; service reg RCE\n" +
    "  takeover:dangling-cname -> PROBABLE TAKEOVER — verify unclaimed subdomain via platform\n" +
    "  title:dir-listing   -> browse for .env .git *.bak; wget --mirror\n" +
    "  title:phpinfo       -> full env vars, paths, xdebug = RCE primitive\n" +
    "  host:non-prod       -> DEBUG often true, weaker auth, source maps, robots.txt\n" +
    "  host:ci-pattern     -> CI surface — source + secrets if accessible\n" +
    "  host:internal       -> should not be public — misconfig, AD/SSO IdP\n" +
    "\nSCORING GUIDE:\n" +
    "  90-100: KEV CVE matched, RCE/auth-bypass signal, or exposed admin panel with known default creds\n" +
    "  70-89:  high-confidence misconfig, SSRF/CORS exploitable, nuclei template + responsive target\n" +
    "  50-69:  partial signal (1-2 indicators), manual confirmation needed\n" +
    "  20-49:  weak signal, version disclosure only, or low-impact class\n" +
    "  0-19:   likely FP, CDN/WAF blocked, or insufficient signal\n" +
    "\nBe aggressive: if multiple signals align with a known exploit path, score high.\n\n" +
    "Return ONLY valid JSON — no markdown fences, no text outside the JSON object:\n" +
    "{\n" +
    "  \"ai_relevance_score\": <0-100 integer>,\n" +
    "  \"confidence\": \"low|medium|high\",\n" +
    "  \"recommendation\": \"skip|watch|manual_review|test_now\",\n" +
    "  \"reason\": \"<1-2 sentences citing the specific signals and CVE/path and why they matter>\",\n" +
    "  \"safe_checks\": [\"<specific passive or low-impact verification step — include exact URL path or tool flag>\"],\n" +
    "  \"risk_flags\": [\"<reason score might be inflated or this is a FP>\"]\n" +
    "}\n\nFull lead JSON:\n" +
    tostring
  ' <<< "$lead" > "$prompt"

  log "[${attempted}/${total_candidates}] scoring $host"
  raw="$(bash "$SCRIPT_DIR/recon_ollama.sh" "$OLLAMA_MODEL_LEAD" "$prompt" 2>/dev/null || true)"
  ai_json="$(extract_ai_json <<< "$raw" || true)"
  if [[ -z "$ai_json" ]] || ! jq -e . >/dev/null 2>&1 <<< "$ai_json"; then
    rejected=$((rejected + 1))
    printf '%s\n' "$raw" > "$reject_file"
    warn "invalid AI JSON for $host (saved raw: $reject_file)"
    continue
  fi

  enriched="$(jq -c --argjson ai "$ai_json" --arg model "$OLLAMA_MODEL_LEAD" '
    . + {ai: ($ai + {model:$model, route:"human"})}
  ' <<< "$lead")"
  printf '%s\n' "$enriched" >> "$OUT"

  jq -c --arg idx "$INDEX_NAME" --arg model "$OLLAMA_MODEL_LEAD" '
    {"update":{"_index":$idx,"_id":.host}},
    {"doc":{
      ai_relevance_score:(.ai.ai_relevance_score // 0),
      ai_confidence:(.ai.confidence // "low"),
      ai_recommendation:(.ai.recommendation // "watch"),
      ai_reason:(.ai.reason // ""),
      ai_safe_checks:(.ai.safe_checks // []),
      ai_risk_flags:(.ai.risk_flags // []),
      ai_model:$model,
      ai_reviewed_at:(now | strftime("%Y-%m-%dT%H:%M:%SZ"))
    }}
  ' <<< "$enriched" >> "$updates_tmp"
  scored=$((scored + 1))
  log "[${attempted}/${total_candidates}] accepted $host ai_score=$(jq -r '.ai.ai_relevance_score // 0' <<< "$enriched") route=$(jq -r '.ai.route // "human"' <<< "$enriched")"
done < "$candidates_tmp"

if [[ -s "$updates_tmp" && -n "$ES_PASS" ]]; then
  curl -fsS -m 30 -u "$ES_USER:$ES_PASS" -H 'Content-Type: application/x-ndjson' \
    -X POST "$ES_URL/_bulk" --data-binary @"$updates_tmp" >/dev/null 2>&1 \
    || warn "AI ES writeback failed"
fi

log "AI-scored $scored/$attempted lead(s), rejected=$rejected: $OUT"

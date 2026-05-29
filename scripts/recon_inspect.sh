#!/usr/bin/env bash
# =============================================================================
# recon_inspect.sh — fast manual-triage helper
#
# Pulls everything you need to evaluate a single host without leaving terminal:
#   - Full ES record (tech, status, title, IP, CNAME, etc.)
#   - Scope verdict (in scope / out / hard-excluded / which program)
#   - KEV match details (which CVEs, which signal triggered)
#   - Live HTTP probe (current status, redirect chain, server header)
#   - Suggested manual probes (curl one-liners for the matched tech)
#
# Usage:
#   ./recon_inspect.sh <host>
#   ./recon_inspect.sh --json <host>     # raw output for piping
# =============================================================================

set -uo pipefail

HOST_ARG="${1:-}"
JSON_MODE=0
if [[ "$HOST_ARG" == "--json" ]]; then
  JSON_MODE=1
  HOST_ARG="${2:-}"
fi

if [[ -z "$HOST_ARG" ]]; then
  echo "Usage: $0 [--json] <host>" >&2
  exit 2
fi

ES_URL="${ES_URL:-http://127.0.0.1:9200}"
ES_USER="${ES_USER:-elastic}"
ES_PASS="${ES_PASS:-$(tr -d '[:space:]' < "$HOME/.recon_es_pass" 2>/dev/null || true)}"
setup_es_netrc
INDEX="${INDEX_NAME:-recon_alive}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/recon_net.sh"
SCOPE_CHECK="${SCOPE_CHECK:-$SCRIPT_DIR/recon_scope_check.sh}"
[[ -f "$SCOPE_CHECK" ]] || SCOPE_CHECK="$HOME/recon_scope_check.sh"
KEV_FILE="$HOME/recon/cve/kev_targets.jsonl"
IGNORE_FILE="${IGNORE_FILE:-$HOME/recon/state/ignored.jsonl}"
IGNORE_TTL_DAYS="${IGNORE_TTL_DAYS:-7}"

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; C='\033[0;36m'; N='\033[0m'

# Normalize host
host="$(echo "$HOST_ARG" | tr '[:upper:]' '[:lower:]' | sed -E 's#^https?://##; s#/.*$##')"

# Fix 12: check ignored.jsonl at query time — if host is ignored and TTL not expired, warn
ignore_cutoff="$(date -u -d "-${IGNORE_TTL_DAYS} days" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u '+%Y-%m-%dT%H:%M:%SZ')"
ignore_entry="null"
if [[ -s "$IGNORE_FILE" ]]; then
  ignore_entry="$(jq -c --arg h "$host" --arg cutoff "$ignore_cutoff" \
    'select(.host == $h and (.added_at // "") >= $cutoff)' \
    "$IGNORE_FILE" 2>/dev/null | tail -1 || echo "null")"
  [[ -z "$ignore_entry" ]] && ignore_entry="null"
fi

# 1. ES record
es_doc="$(curl -sS --netrc-file "$HOME/.recon_es_netrc" "$ES_URL/$INDEX/_doc/$host" 2>/dev/null \
          | jq '._source // null' 2>/dev/null)"

# 2. Scope verdict
scope="$(echo "$host" | bash "$SCOPE_CHECK" --batch 2>/dev/null | head -1)"

# 3. KEV match
kev_match="null"
if [[ -s "$KEV_FILE" ]]; then
  kev_match="$(jq -c --arg h "$host" 'select(.host == $h)' "$KEV_FILE" 2>/dev/null | head -1)"
  [[ -z "$kev_match" ]] && kev_match="null"
fi

# 4. Live probe
probe_json="null"
if command -v curl >/dev/null 2>&1; then
  probe="$(curl_net -sS -k -L --max-redirs 3 -m 10 \
    -A 'Mozilla/5.0 (recon-inspect)' \
    -o /dev/null \
    -w '{"status":%{http_code},"final_url":"%{url_effective}","redirect_count":%{num_redirects},"time_total":%{time_total},"server":"%{header.server}"}' \
    "https://$host/" 2>/dev/null || echo 'null')"
  if echo "$probe" | jq -e . >/dev/null 2>&1; then
    probe_json="$probe"
  fi
fi

if [[ "$JSON_MODE" -eq 1 ]]; then
  jq -n \
    --arg host "$host" \
    --argjson es "$([[ -n "$es_doc" && "$es_doc" != "null" ]] && echo "$es_doc" || echo null)" \
    --argjson scope "$([[ -n "$scope" ]] && echo "$scope" || echo null)" \
    --argjson kev "$kev_match" \
    --argjson probe "$probe_json" \
    '{host:$host, es:$es, scope:$scope, kev:$kev, probe:$probe}'
  exit 0
fi

# ----- Pretty output --------------------------------------------------------
hdr() { printf "\n${B}═══ %s ═══${N}\n" "$1"; }
kv()  { printf "  ${C}%-15s${N} %s\n" "$1" "$2"; }
warn_kv() { printf "  ${Y}%-15s${N} %s\n" "$1" "$2"; }
err_kv()  { printf "  ${R}%-15s${N} %s\n" "$1" "$2"; }
ok_kv()   { printf "  ${G}%-15s${N} %s\n" "$1" "$2"; }

printf "${B}┌────────────────────────────────────────${N}\n"
printf "${B}│${N} Host: ${C}%s${N}\n" "$host"
printf "${B}└────────────────────────────────────────${N}\n"

# Fix 12: show ignored status prominently
if [[ "$ignore_entry" != "null" && -n "$ignore_entry" ]]; then
  ig_reason="$(printf '%s' "$ignore_entry" | jq -r '.reason // "manual"' 2>/dev/null)"
  ig_expires="$(printf '%s' "$ignore_entry" | jq -r '.expires_at // "?"' 2>/dev/null)"
  printf "\n  ${Y}⚠️  HOST IS IGNORED (TTL active until %s) — reason: %s${N}\n" "$ig_expires" "$ig_reason"
  printf "  ${Y}Results suppressed from fresh/fetch queries. Use 'recon-ignore' to re-add.${N}\n"
fi

hdr "Scope"
if [[ -z "$scope" || "$scope" == "null" ]]; then
  warn_kv "verdict" "no scope check result"
else
  hard_ex="$(echo "$scope" | jq -r '.hard_excluded // false')"
  if [[ "$hard_ex" == "true" ]]; then
    err_kv "verdict" "HARD EXCLUDED — $(echo "$scope" | jq -r '.reason')"
    err_kv "action" "DO NOT scan. Skipping all suggestions."
  else
    in_scope="$(echo "$scope" | jq -r '.in_scope')"
    out_scope="$(echo "$scope" | jq -r '.out_of_scope')"
    pays="$(echo "$scope" | jq -r '.pays')"
    program="$(echo "$scope" | jq -r '.program // "—"')"
    platform="$(echo "$scope" | jq -r '.platform // "—"')"
    pattern="$(echo "$scope" | jq -r '.pattern // "—"')"
    tier="$(echo "$scope" | jq -r '.payout_tier // "none"')"

    if [[ "$out_scope" == "true" ]]; then
      err_kv "verdict" "OUT OF SCOPE"
    elif [[ "$in_scope" == "true" && "$pays" == "true" ]]; then
      case "$tier" in
        elite) ok_kv  "verdict" "IN SCOPE — ELITE payout (≥\$10k)" ;;
        high)  ok_kv  "verdict" "IN SCOPE — HIGH payout (\$3k-\$10k)" ;;
        mid)   ok_kv  "verdict" "IN SCOPE — paying (mid)" ;;
        low)   ok_kv  "verdict" "IN SCOPE — paying (low)" ;;
        *)     ok_kv  "verdict" "IN SCOPE — paying" ;;
      esac
      ok_kv  "program"     "$program ($platform)"
      ok_kv  "payout_tier" "$tier"
      kv     "matched on"  "$pattern"
    elif [[ "$in_scope" == "true" ]]; then
      warn_kv "verdict"     "IN SCOPE — VDP only (no payout)"
      warn_kv "program"     "$program ($platform)"
      warn_kv "payout_tier" "$tier"
    else
      warn_kv "verdict" "UNKNOWN — no matching program"
    fi
  fi
fi

hdr "ES record"
if [[ "$es_doc" == "null" || -z "$es_doc" ]]; then
  warn_kv "status" "host not in recon_alive (not yet validated by httpx)"
else
  kv "status" "$(echo "$es_doc" | jq -r '.status_code // "?"')"
  kv "title"  "$(echo "$es_doc" | jq -r '.title // "—"' | head -c 80)"
  kv "tech"   "$(echo "$es_doc" | jq -r '(.tech // []) | join(", ")' | head -c 200)"
  kv "server" "$(echo "$es_doc" | jq -r '.webserver // "—"')"
  kv "ip"     "$(echo "$es_doc" | jq -r '.ip // "—"')"
  cname="$(echo "$es_doc" | jq -r '.cname // ""')"
  [[ -n "$cname" && "$cname" != "—" ]] && kv "cname" "$cname"
  cdn="$(echo "$es_doc" | jq -r '.cdn_name // ""')"
  [[ -n "$cdn" && "$cdn" != "—" ]] && kv "cdn" "$cdn"
  kv "last seen" "$(echo "$es_doc" | jq -r '.last_seen // "?"')"
fi

hdr "KEV match"
if [[ "$kev_match" == "null" || -z "$kev_match" ]]; then
  kv "match" "none"
else
  signal="$(echo "$kev_match" | jq -r '.matched_signal')"
  cve_ids="$(echo "$kev_match" | jq -r '[.matched_cves[] | select(.kev) | .id] | join(", ")')"
  cvss_max="$(echo "$kev_match" | jq -r '[.matched_cves[].cvss] | max')"
  warn_kv "signal" "$signal"
  warn_kv "KEV CVEs" "$cve_ids"
  warn_kv "max CVSS" "$cvss_max"
fi

hdr "Live probe"
if [[ "$probe_json" == "null" || -z "$probe_json" ]]; then
  warn_kv "probe" "could not connect"
else
  status="$(echo "$probe_json" | jq -r '.status')"
  final="$(echo "$probe_json" | jq -r '.final_url')"
  server="$(echo "$probe_json" | jq -r '.server')"
  rc="$(echo "$probe_json" | jq -r '.redirect_count')"
  case "$status" in
    200) ok_kv  "status" "$status" ;;
    301|302|307|308) warn_kv "status" "$status (redirect)" ;;
    401|403) warn_kv "status" "$status (auth required)" ;;
    404|410) err_kv  "status" "$status (not found / gone)" ;;
    *)       kv "status" "$status" ;;
  esac
  kv "final URL"  "$final"
  kv "redirects"  "$rc"
  kv "server"     "$server"
fi

# Suggest probes if we have a KEV signal AND the host is scope-valid (not hard-excluded)
if [[ "$kev_match" != "null" && "$kev_match" != "" ]]; then
  hard_ex="$(echo "$scope" | jq -r '.hard_excluded // false' 2>/dev/null)"
  if [[ "$hard_ex" != "true" ]]; then
    hdr "Suggested manual probes"
    signal="$(echo "$kev_match" | jq -r '.matched_signal')"
    base="https://$host"
    case "$signal" in
      tech:jenkins)
        kv "asset"      "Jenkins"
        kv "endpoint"   "$base/asynchPeople (user enum, no auth)"
        kv "endpoint"   "$base/script (Groovy console, RCE if accessible)"
        kv "CVE-2024-23897" "$base/manage/cli — POST connect command for arbitrary file read"
        kv "default cred" "admin:admin"
        ;;
      tech:confluence)
        kv "asset"      "Confluence"
        kv "endpoint"   "$base/login.action (version on response)"
        kv "endpoint"   "$base/rest/api/content (anon read attempt)"
        kv "CVE-2023-22527" "OGNL template injection — POST /template/aui/text-inline.vm"
        kv "CVE-2022-26134" "OGNL via URL — GET /\${...}/"
        ;;
      tech:jira)
        kv "asset"      "Jira"
        kv "endpoint"   "$base/rest/api/2/user/picker?query=. (user enum, often anon)"
        kv "endpoint"   "$base/secure/Dashboard.jspa"
        kv "CVE-2019-11581" "SSTI in /secure/ContactAdministrators!default.jspa"
        ;;
      tech:moveit)
        kv "asset"      "MOVEit Transfer"
        kv "CVE-2023-34362" "/human.aspx — actively exploited SQLi → RCE"
        kv "endpoint"   "$base/api/v1/files (auth check)"
        ;;
      tech:exchange-owa)
        kv "asset"      "Exchange / OWA"
        kv "endpoint"   "$base/owa/auth/logon.aspx (version pivot)"
        kv "CVE-2021-26855" "ProxyLogon SSRF"
        kv "CVE-2021-34473" "ProxyShell RCE chain"
        ;;
      tech:fortinet)
        kv "asset"      "Fortinet (FortiOS/FortiGate)"
        kv "CVE-2024-21762" "Unauth RCE — sslvpnd buffer overflow"
        kv "CVE-2018-13379" "Path traversal /remote/fgt_lang"
        ;;
      tech:citrix)
        kv "asset"      "Citrix NetScaler/Gateway"
        kv "CVE-2023-4966" "Citrix Bleed — session token leak"
        kv "CVE-2023-3519" "Unauth RCE"
        ;;
      tech:vmware)
        kv "asset"      "VMware vCenter/vSphere"
        kv "CVE-2024-37079" "vCenter RCE"
        kv "CVE-2021-44228" "Log4Shell"
        ;;
      tech:gitlab)
        kv "asset"      "GitLab"
        kv "CVE-2023-7028" "Account takeover via password reset"
        kv "endpoint"   "$base/explore (public repos)"
        ;;
      tech:weblogic)
        kv "asset"      "Oracle WebLogic"
        kv "endpoint"   "$base/console/login/LoginForm.jsp"
        kv "CVE-2020-14882" "Console auth bypass + RCE"
        ;;
      tech:magento)
        kv "asset"      "Magento"
        kv "CVE-2024-34102" "CosmicSting — XML deserialization"
        kv "endpoint"   "$base/magento_version"
        ;;
      tech:manageengine)
        kv "asset"      "ManageEngine"
        kv "CVE-2022-47966" "Unauth RCE via SAML"
        kv "endpoint"   "$base/webclient/index.html"
        ;;
      tech:kibana)
        kv "asset"      "Kibana"
        kv "endpoint"   "$base/api/status (version)"
        kv "endpoint"   "$base/app/dev_tools (full ES query if accessible)"
        ;;
      tech:phpmyadmin)
        kv "asset"      "phpMyAdmin"
        kv "endpoint"   "$base/index.php (default creds: root:root, root:empty)"
        kv "endpoint"   "$base/setup/ (config bypass)"
        ;;
      *)
        kv "signal"     "$signal"
        kv "next"       "consult triage.sh actions list, or run nuclei manually"
        ;;
    esac
  fi
fi

echo

#!/usr/bin/env bash
# =============================================================================
# recon_jsintel.sh — UNIQUE JS-intelligence vertical (not the commodity grep).
#
# The crowd greps JS for token-shaped strings -> ~53% false-positive noise (our own
# doctrine). We do it the way that actually pays:
#   1. GATHER every JS asset of a live in-scope host (subjs + katana -jc + gau).
#   2. EXTRACT endpoints with jsluice (the hidden API surface in the bundle).
#   3. VERIFY secrets are LIVE with trufflehog --only-verified — a verified live key is a
#      clean, high-impact, NON-DUPLICATE finding, not a guess.
#   4. The extracted endpoints become the feedstock for the IDOR/logic worklist (Claude
#      reads them in the next stage).
# SAFE: read-only fetch of public JS + trufflehog live-verify (it authenticates the leaked
# key to prove it's real — that IS the PoC, never a data harvest). Scope+VPN gated,
# rate-limited. Verified secret -> SQLite -> Claude consensus verify -> #review.
# Runs as d0k (target-facing). Freshest, highest-value hosts first.
# =============================================================================
set -uo pipefail
IFS=$'\n\t'
log()  { printf '[%s JSINTEL] %s\n'      "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s JSINTEL WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/recon_net.sh" 2>/dev/null || true
BASE_DIR="${BASE_DIR:-$HOME/recon}"; STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
V3_DB="${V3_DB:-$BASE_DIR/v3/findings.db}"; STATE_PY="${STATE_PY:-$REPO_DIR/engine/state.py}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"; INDEX_NAME="${INDEX_NAME:-recon_alive}"
NETRC="${NETRC:-$HOME/.recon_es_netrc}"
EP_STORE="${JS_ENDPOINT_STORE:-$BASE_DIR/js_recon/endpoints.jsonl}"   # feeds the IDOR stage
JS_HOSTS="${JS_HOSTS:-15}"
JS_PER_HOST="${JS_PER_HOST:-40}"        # max JS files fetched per host (bound load)
JS_MAXBYTES="${JS_MAXBYTES:-3000000}"   # 3MB cap per JS file
JS_TIMEOUT="${JS_TIMEOUT:-300}"         # per-host hard cap
SEEN="${JS_SEEN:-$STATE_DIR/jsintel_seen_hosts.txt}"
es() { curl -fsS -m 25 --netrc-file "$NETRC" -H 'Content-Type: application/json' "$@"; }
in_scope_now() {
  # AUTHORITATIVE scope DB (recon_scope_check.sh) — not stale ES triage_* (matches recon_safe_probe.sh / xss_confirm / param_confirm).
  local _sc="$SCRIPT_DIR/recon_scope_check.sh"
  if [[ -f "$_sc" ]]; then
    [[ "$(bash "$_sc" "$1" 2>/dev/null | jq -r \
       '((.in_scope//false)==true) and ((.pays//false)==true) and ((.out_of_scope//false)!=true)' 2>/dev/null)" == "true" ]]
  else
    [[ "$(es "$ES_URL/$INDEX_NAME/_source/$1" 2>/dev/null | jq -r \
       '((.triage_in_scope//false)==true) and ((.triage_pays//false)==true) and ((.triage_out_of_scope//false)!=true)' 2>/dev/null)" == "true" ]]
  fi
}

mkdir -p "$STATE_DIR" "$(dirname "$EP_STORE")"; touch "$SEEN"
exec 9>"$STATE_DIR/jsintel.lock"; flock -n 9 || { warn "already running"; exit 0; }
[[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down — refusing (fail-closed)"; exit 0; }
for t in jsluice trufflehog subjs jq curl; do command -v "$t" >/dev/null 2>&1 || { warn "$t missing"; exit 0; }; done

# Host selection: VALUE-WEIGHTED freshness. IDOR/BOLA on high-value programs is the
# #1 paid class (the money pillar this feeds), and fresh-first alone never reached the
# elite API/dev/staging hosts (fresh mid-tier always jumped ahead). So sort payout_tier
# first (elite>high>... alphabetical asc), then true_fresh (fresh WITHIN tier — keeps the
# be-first-to-fresh edge for new high-value hosts), then score. Mines elite API surface
# first -> richer feedstock for recon_idor_candidates.py. (2026-06-13)
q="$(jq -nc --argjson n "$JS_HOSTS" '{size:($n*5),_source:["host"],
  query:{bool:{filter:[{term:{triage_in_scope:true}},{term:{triage_pays:true}},{term:{status_code:200}}],
               must_not:[{term:{triage_out_of_scope:true}}]}},
  sort:[{triage_payout_tier:{order:"asc",missing:"_last"}},{triage_true_fresh:{order:"desc",missing:"_last"}},{triage_score:{order:"desc",missing:"_last"}}]}')"
mapfile -t hosts < <(es "$ES_URL/$INDEX_NAME/_search" -d "$q" 2>/dev/null \
  | jq -r '.hits.hits[]._source.host // empty' 2>/dev/null | awk 'NF && !s[$0]++' \
  | grep -vxF -f "$SEEN" 2>/dev/null | head -n "$JS_HOSTS")
[[ "${#hosts[@]}" -gt 0 ]] || { log "no fresh in-scope hosts to mine"; exit 0; }
log "🧬 ─── JS INTEL ─── ${#hosts[@]} host(s) · gather JS → jsluice endpoints + trufflehog LIVE-secret verify ───"

secrets=0; eps=0; mined=0
for host in "${hosts[@]}"; do
  [[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down mid-run — stopping"; break; }
  in_scope_now "$host" || { printf '%s\n' "$host" >> "$SEEN"; continue; }
  wd="$(mktemp -d)"; mkdir -p "$wd/js"
  # 1) GATHER JS URLs (page scripts + crawl + passive), dedup, cap
  { printf 'https://%s/\nhttp://%s/\n' "$host" "$host" | timeout 60 subjs 2>/dev/null
    timeout 90 katana -u "https://$host/" -d 2 -jc -silent -nc 2>/dev/null | grep -aiE '\.js(\?|$)'
    printf '%s\n' "$host" | timeout 45 gau --threads 5 2>/dev/null | grep -aiE '\.js(\?|$)'
  } | awk 'NF && !s[$0]++' | grep -aiE '^https?://' | head -n "$JS_PER_HOST" > "$wd/jsurls.txt"
  njs="$(wc -l < "$wd/jsurls.txt" 2>/dev/null | tr -d ' ')"
  printf '%s\n' "$host" >> "$SEEN"; mined=$((mined+1))
  if [[ "${njs:-0}" -eq 0 ]]; then log "   · $host — 0 JS assets"; rm -rf "$wd"; continue; fi
  # fetch each JS (size-capped)
  i=0; while IFS= read -r ju; do
    [[ -z "$ju" ]] && continue
    curl -fsSL -m 20 --max-filesize "$JS_MAXBYTES" -A 'Mozilla/5.0' "$ju" 2>/dev/null | tr -d '\0' > "$wd/js/$i.js"
    [[ -s "$wd/js/$i.js" ]] || rm -f "$wd/js/$i.js"
    i=$((i+1))
  done < "$wd/jsurls.txt"
  log "   🧬 $host — $njs JS asset(s) → jsluice + trufflehog"
  prog="$(es "$ES_URL/$INDEX_NAME/_source/$host" 2>/dev/null | jq -r '.triage_program // ""' 2>/dev/null)"

  # 2) EXTRACT endpoints (jsluice) — FILTER to the real API surface (drop static assets,
  #    vendor dirs, CDNs) so the IDOR/logic feedstock is clean for the Claude stage.
  hep=0
  if compgen -G "$wd/js/*.js" >/dev/null; then
    while IFS= read -r u; do
      [[ -z "$u" ]] && continue
      jq -nc --arg h "$host" --arg p "$prog" --arg u "$u" --arg t "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
         '{host:$h,program:$p,endpoint:$u,source:"jsluice",at:$t}' >> "$EP_STORE" 2>/dev/null
      hep=$((hep+1))
    done < <(timeout 60 jsluice urls "$wd"/js/*.js 2>/dev/null \
              | jq -r '.url // empty' 2>/dev/null \
              | grep -aiE '^https?://|^/[A-Za-z0-9_]' \
              | grep -aivE '\.(css|js|mjs|cjs|map|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|otf|scss|sass|less|md|txt|html?|xml|yml|yaml|pdf)(\?|$)' \
              | grep -aivE 'node_modules|/static/|/assets/|/dist/|/build/|/fonts?/|/img/|/images/|/css/|/vendor/|cdn\.|googleapis|gstatic|fontawesome|jsdelivr|unpkg' \
              | awk 'length($0)>2 && NF && !s[$0]++' | head -150)
  fi
  eps=$((eps+hep))
  [[ "$hep" -gt 0 ]] && log "      ↳ 🔗 $hep endpoint(s) extracted → IDOR feedstock"

  # 3) VERIFY LIVE secrets (trufflehog --only-verified) — the clean, non-dupe finding
  th="$(timeout 120 trufflehog filesystem "$wd/js" --only-verified --json --no-update 2>/dev/null)"
  if [[ -n "$th" ]]; then
    while IFS= read -r sline; do
      [[ -z "$sline" ]] && continue
      det="$(printf '%s' "$sline" | jq -r '.DetectorName // "?"' 2>/dev/null)"
      [[ "$det" == "?" || -z "$det" ]] && continue
      file="$(printf '%s' "$sline" | jq -r '.SourceMetadata.Data.Filesystem.file // ""' 2>/dev/null)"
      red="$(printf '%s' "$sline" | jq -r '(.Raw // "")[0:12]' 2>/dev/null)"
      ev="$(jq -nc --arg d "$det" --arg f "$file" --arg r "$red" \
            '{probe:"trufflehog-verified",detector:$d,verified:true,file:$f,redacted:($r+"…")}' 2>/dev/null)"
      db_confirm "$host" "https://$host/" "$prog" "data-leak" "verified-secret" "60" "0.95" "$ev" 2>/dev/null || true
      secrets=$((secrets+1))
      log "   💥 LIVE SECRET CONFIRMED · $host · $det (verified) → SQLite → Claude verify"
    done <<< "$th"
  fi
  rm -rf "$wd"
done
tail -n 20000 "$SEEN" > "$SEEN.tmp" 2>/dev/null && mv "$SEEN.tmp" "$SEEN" 2>/dev/null || true
log "🧬 js-intel done · 💥 $secrets verified-live-secret(s) · 🔗 $eps endpoint(s) · $mined host(s) mined"

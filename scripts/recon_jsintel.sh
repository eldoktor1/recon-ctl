#!/usr/bin/env bash
# =============================================================================
# recon_jsintel.sh — UNIQUE JS-intelligence vertical (not the commodity grep).
#
# The crowd greps JS for token-shaped strings -> ~53% false-positive noise (our own
# doctrine). We do it the way that actually pays:
#   1. GATHER every JS asset of a live in-scope host (subjs + katana -jc + gau).
#   1b. RECONSTRUCT leaked source maps (sourcemapper) — the ORIGINAL un-minified source, a far
#       richer endpoint+secret surface the crowd never un-maps. Optional/best-effort, EXTERNAL .map only.
#   2. EXTRACT endpoints with jsluice urls (AST — the hidden API surface) over the bundles AND any
#      reconstructed source (proven: jsluice cleanly pulls GraphQL/extranet/payouts routes regex missed).
#   3. SECRETS two ways: trufflehog --only-verified = LIVE-verified CONFIRMED finding (→ SQLite → #review);
#      jsluice secrets (AST) = candidate LEADs for key shapes trufflehog has no detector for — review-only,
#      capped, NEVER auto-confirmed (keeps the 53%-FP secret-noise trap shut).
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
       '((.triage_in_scope//false)==true) and ((.triage_pays//false)==true) and ((.triage_out_of_scope//false)!=true) and ((.triage_scan_deny//false)!=true)' 2>/dev/null)" == "true" ]]
  fi
}

mkdir -p "$STATE_DIR" "$(dirname "$EP_STORE")"; touch "$SEEN"
exec 9>"$STATE_DIR/jsintel.lock"; flock -n 9 || { warn "already running"; exit 0; }
[[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down — refusing (fail-closed)"; exit 0; }
for t in jsluice trufflehog subjs jq curl; do command -v "$t" >/dev/null 2>&1 || { warn "$t missing"; exit 0; }; done
SOURCEMAPPER="$(command -v sourcemapper 2>/dev/null || true)"          # OPTIONAL: reconstruct leaked .map → deeper mine
SECRET_LEADS="${JS_SECRET_LEADS:-$BASE_DIR/js_recon/secret_leads.jsonl}"  # jsluice AST secret CANDIDATES (review-only LEADs)
# RETAINED reconstructed source (added 2026-08-16). A leaked .map is the ORIGINAL application
# source. Regexing it for URLs/secrets and deleting it throws away the only artifact that shows
# HOW the app works — authz checks, roles, object ownership, money flows. That reasoning surface
# is what pays 5-figures; endpoint strings pay 3. Keep the tree so the app-model pass can read it.
SRC_STORE="${JS_SRC_STORE:-$BASE_DIR/js_recon/src}"                      # persisted per-host source trees
SRC_KEEP_MB="${JS_SRC_KEEP_MB:-40}"                                      # per-host cap (anti-disk-blowup)
SRC_INDEX="${JS_SRC_INDEX:-$BASE_DIR/js_recon/src_index.jsonl}"          # what we retained, per host

# Host selection: VALUE-WEIGHTED freshness. IDOR/BOLA on high-value programs is the
# #1 paid class (the money pillar this feeds), and fresh-first alone never reached the
# elite API/dev/staging hosts (fresh mid-tier always jumped ahead). So sort payout_tier
# first (elite>high>... alphabetical asc), then true_fresh (fresh WITHIN tier — keeps the
# be-first-to-fresh edge for new high-value hosts), then score. Mines elite API surface
# first -> richer feedstock for recon_idor_candidates.py. (2026-06-13)
# FOCUS-FIRST (added 2026-08-16). The operator COMMITS to a program in the Program Workspace
# (~/recon/workspaces/<key>.json with current:true) — but every lane ignored that commitment and
# mined the ES-wide ranking instead. Because the global sort is payout_tier ASC (elite>high>mid),
# a committed MID-tier program is structurally unreachable and its workspace stays empty of
# endpoints/source forever. That is why a committed program's WSTG walk had no app data to work
# from. The workspace `key` IS the ES `triage_program`, so focusing is a direct term filter.
# Focused hosts are mined FIRST, then the global ranking fills the remaining budget (so committing
# never starves global coverage). Disable with JS_FOCUS=0.
FOCUS_PROG=""
if [[ "${JS_FOCUS:-1}" == "1" && -d "$BASE_DIR/workspaces" ]]; then
  FOCUS_PROG="$(jq -rs 'map(select(.current==true)) | .[0].key // empty' \
                  "$BASE_DIR"/workspaces/*.json 2>/dev/null | head -1)"
fi
focus_hosts=()
if [[ -n "$FOCUS_PROG" ]]; then
  fq="$(jq -nc --arg p "$FOCUS_PROG" '{size:500,_source:["host"],
    query:{bool:{filter:[{term:{triage_in_scope:true}},{term:{triage_pays:true}},{bool:{must_not:{term:{triage_scan_deny:true}}}},{term:{triage_program:$p}}],
                 must_not:[{term:{triage_out_of_scope:true}},{range:{ignore_expires_at:{gt:"now"}}}]}},
    sort:[{triage_score:{order:"desc",missing:"_last"}}]}')"
  mapfile -t focus_hosts < <(es "$ES_URL/$INDEX_NAME/_search" -d "$fq" 2>/dev/null \
    | jq -r '.hits.hits[]._source.host // empty' 2>/dev/null | awk 'NF && !s[$0]++' \
    | grep -vxF -f "$SEEN" 2>/dev/null | head -n "$JS_HOSTS")
  [[ "${#focus_hosts[@]}" -gt 0 ]] \
    && log "🎯 FOCUS: committed program '$FOCUS_PROG' — ${#focus_hosts[@]} host(s) mined FIRST" \
    || log "🎯 FOCUS: '$FOCUS_PROG' committed but 0 un-mined hosts (already covered, or none in scope)"
fi
q="$(jq -nc --argjson n "$JS_HOSTS" '{size:2000,_source:["host"],
  query:{bool:{filter:[{term:{triage_in_scope:true}},{term:{triage_pays:true}},{bool:{must_not:{term:{triage_scan_deny:true}}}},{term:{status_code:200}}],
               must_not:[{term:{triage_out_of_scope:true}}]}},
  sort:[{triage_payout_tier:{order:"asc",missing:"_last"}},{triage_true_fresh:{order:"desc",missing:"_last"}},{triage_score:{order:"desc",missing:"_last"}}]}')"
mapfile -t hosts < <( { printf '%s\n' "${focus_hosts[@]}"; \
    es "$ES_URL/$INDEX_NAME/_search" -d "$q" 2>/dev/null \
      | jq -r '.hits.hits[]._source.host // empty' 2>/dev/null; } \
  | awk 'NF && !s[$0]++' | grep -vxF -f "$SEEN" 2>/dev/null | head -n "$JS_HOSTS")
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

  # 1b) RECONSTRUCT source maps — a leaked .map is the ORIGINAL un-minified source (far richer
  #     endpoint + secret surface the crowd never un-maps). Only when the bundle advertises an
  #     EXTERNAL sourceMappingURL (skip inline data: maps). sourcemapper OPTIONAL (absent ⇒ mine
  #     bundles only). Same-host (scope already gated above), bounded by JS_PER_HOST.
  if [[ -n "$SOURCEMAPPER" ]]; then
    smaps=0
    for jf in "$wd"/js/*.js; do
      [[ -e "$jf" ]] || continue
      grep -aoiE 'sourcemappingurl=[^[:space:]*]+' "$jf" 2>/dev/null | grep -qiv 'data:' || continue
      idx="$(basename "$jf" .js)"; ju="$(sed -n "$((idx+1))p" "$wd/jsurls.txt" 2>/dev/null)"
      [[ -n "$ju" ]] || continue
      timeout 30 "$SOURCEMAPPER" -jsurl "$ju" -output "$wd/srcmap/$idx" >/dev/null 2>&1 && smaps=$((smaps+1))
    done
    [[ "$smaps" -gt 0 ]] && log "      ↳ 🗺️  $smaps source map(s) reconstructed → deeper mine"
    # RETAIN the reconstructed tree (2026-08-16). Without this the source dies with $wd and the
    # app-model pass has nothing to reason over. Size-capped; skips node_modules/vendor noise.
    if [[ "${smaps:-0}" -gt 0 && -d "$wd/srcmap" ]]; then
      _sz="$(du -sm "$wd/srcmap" 2>/dev/null | cut -f1)"; _sz="${_sz:-0}"
      if [[ "$_sz" -le "$SRC_KEEP_MB" ]]; then
        mkdir -p "$SRC_STORE/$host" 2>/dev/null
        # copy only real source; drop dependency trees (not the target's code, pure noise)
        (cd "$wd/srcmap" 2>/dev/null && find . -type f \
            \( -name '*.js' -o -name '*.jsx' -o -name '*.ts' -o -name '*.tsx' -o -name '*.vue' -o -name '*.mjs' \) \
            ! -path '*/node_modules/*' ! -path '*/vendor/*' ! -path '*/webpack/bootstrap*' \
            -print0 2>/dev/null | tar --null -cf - --files-from=- 2>/dev/null) \
          | (cd "$SRC_STORE/$host" 2>/dev/null && tar -xf - 2>/dev/null)
        _n="$(find "$SRC_STORE/$host" -type f 2>/dev/null | wc -l | tr -d ' ')"
        jq -nc --arg h "$host" --arg p "$prog" --argjson maps "$smaps" --argjson files "${_n:-0}" \
               --argjson mb "$_sz" --arg t "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
           '{host:$h,program:$p,source_maps:$maps,files:$files,mb:$mb,at:$t}' >> "$SRC_INDEX" 2>/dev/null
        log "      ↳ 💾 retained $_n source file(s) → $SRC_STORE/$host  (app-model feedstock)"
      else
        log "      ↳ ⚠️  srcmap tree ${_sz}MB > cap ${SRC_KEEP_MB}MB — not retained"
      fi
    fi
  fi
  # Source set for the AST miners = bundles + any reconstructed original source (capped —
  # reconstructed trees can be large).
  mapfile -t SRCFILES < <( { compgen -G "$wd/js/*.js"; find "$wd/srcmap" -type f \( -name '*.js' -o -name '*.jsx' -o -name '*.ts' -o -name '*.tsx' -o -name '*.vue' -o -name '*.mjs' \) 2>/dev/null; } | head -800 )

  # 2) EXTRACT endpoints (jsluice) — FILTER to the real API surface (drop static assets,
  #    vendor dirs, CDNs) so the IDOR/logic feedstock is clean for the Claude stage.
  hep=0
  if [[ "${#SRCFILES[@]}" -gt 0 ]]; then
    while IFS= read -r u; do
      [[ -z "$u" ]] && continue
      jq -nc --arg h "$host" --arg p "$prog" --arg u "$u" --arg t "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
         '{host:$h,program:$p,endpoint:$u,source:"jsluice",at:$t}' >> "$EP_STORE" 2>/dev/null
      hep=$((hep+1))
    done < <(timeout 90 jsluice urls "${SRCFILES[@]}" 2>/dev/null \
              | jq -r '.url // empty' 2>/dev/null \
              | grep -aiE '^https?://|^/[A-Za-z0-9_]' \
              | grep -aivE '\.(css|js|mjs|cjs|map|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|otf|scss|sass|less|md|txt|html?|xml|yml|yaml|pdf)(\?|$)' \
              | grep -aivE 'node_modules|/static/|/assets/|/dist/|/build/|/fonts?/|/img/|/images/|/css/|/vendor/|cdn\.|googleapis|gstatic|fontawesome|jsdelivr|unpkg' \
              | awk 'length($0)>2 && NF && !s[$0]++' | head -150)
  fi
  eps=$((eps+hep))
  [[ "$hep" -gt 0 ]] && log "      ↳ 🔗 $hep endpoint(s) extracted → IDOR feedstock"

  # 2b) SECRET CANDIDATES (jsluice AST) — LEADs only. trufflehog --only-verified (below) stays the
  #     CONFIRMED path; jsluice's AST catches custom/internal key shapes trufflehog has no detector for
  #     (the Bokun-class miss). Written to a review store, deduped + capped, NEVER auto-confirmed — so it
  #     surfaces real internal-key leaks without reopening the 53%-FP token-noise trap.
  if [[ "${#SRCFILES[@]}" -gt 0 ]]; then
    sl=0
    while IFS= read -r sline; do
      [[ -z "$sline" ]] && continue
      printf '%s\n' "$sline" >> "$SECRET_LEADS" 2>/dev/null; sl=$((sl+1))
    done < <(timeout 60 jsluice secrets "${SRCFILES[@]}" 2>/dev/null \
              | jq -c --arg h "$host" --arg p "$prog" --arg t "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
                  'select(.kind!=null) | {host:$h,program:$p,kind:.kind,severity:(.severity//"info"),
                   file:(.filename//""),context:((.context//.data//{})|tostring|.[0:160]),source:"jsluice-secret",at:$t}' 2>/dev/null \
              | awk '!s[$0]++' | head -40)
    [[ "$sl" -gt 0 ]] && log "      ↳ 🔑 $sl jsluice secret-candidate LEAD(s) → secret_leads.jsonl (unverified; review)"
  fi

  # 3) VERIFY LIVE secrets (trufflehog --only-verified) — the clean, non-dupe finding. Scans the
  #    whole workdir so reconstructed source-map output is covered too (not just the raw bundles).
  th="$(timeout 120 trufflehog filesystem "$wd" --only-verified --json --no-update 2>/dev/null)"
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

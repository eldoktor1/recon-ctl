#!/usr/bin/env bash
# =============================================================================
# recon_cognito_nighthunt.sh — autonomous overnight Cognito unauth-cred hunt.
# One resumable CYCLE: walk the next batch of in-scope+paying hosts (search_after
# cursor over the whole corpus), harvest Cognito pool IDs from Amplify config /
# root main-JS, test unauth issuance, blast-radius assess the issuers, and PING
# DISCORD (#review) + mint ONLY on a REAL finding — issued creds + a role that
# actually reaches resources (blast_radius.allowed non-empty). RUM/zero-perm
# pools are logged as FP and never fire. Fail-closed on vpn_down.
# Run one cycle per invocation; a scheduler re-invokes it all night.
# =============================================================================
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/recon_net.sh" 2>/dev/null || true
source "$SCRIPT_DIR/recon_notes.sh" 2>/dev/null || true   # note_add for OOS-carveout downgrade
type setup_es_netrc >/dev/null 2>&1 && setup_es_netrc || true
NETRC="$HOME/.recon_es_netrc"; ES="http://127.0.0.1:9200/recon_alive"
BASE="$HOME/recon"; STATE="$BASE/state"; DIR="$BASE/cognito"; mkdir -p "$DIR"
POOLS="$DIR/pools.jsonl"; CONFIRMED="$DIR/confirmed_real.jsonl"; FP="$DIR/fp.jsonl"
CURSOR="$DIR/nighthunt_cursor.txt"; LEDGER="$DIR/nighthunt_scanned.txt"
STOPFILE="$DIR/STOP"; LOG="$DIR/nighthunt.log"
TESTER="$SCRIPT_DIR/../engine/recon_cognito_test.py"
SCOPE_CHECK="$SCRIPT_DIR/recon_scope_check.sh"
UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36'
POOL_RE='[a-z]{2}-[a-z]+-[0-9]:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
BATCH="${BATCH:-4000}"; PAR="${PAR:-14}"
touch "$POOLS" "$CONFIRMED" "$FP" "$LEDGER" 2>/dev/null || true
log(){ printf '[%s NIGHT] %s\n' "$(date -u '+%FT%TZ')" "$*" | tee -a "$LOG" >&2; }
# Shared program-scope carve-out guard (Amazon VRP / AWS VDP dead zone) — cognito_carveout_reason
source "$SCRIPT_DIR/recon_cognito_carveout.sh" 2>/dev/null || true

[ -f "$STOPFILE" ] && { log "STOP file present — halting"; exit 0; }
[ -f "$STATE/vpn_down" ] && { log "vpn_down — fail-closed, skip cycle"; exit 0; }

# ---- 1) next batch: walk APP-ISH in-scope+paying hosts (the ones that ship Amplify
# SPAs) alphabetically by a SINGLE strictly-increasing key (host asc) — deterministic
# search_after, no stall. Exclude UUID-prefixed shared-tenant + tumblr noise.
# Cursor: JSON array [first_seen_str, host_str] for search_after on (first_seen desc, host asc).
# Sorts newest hosts first so newly-discovered in-scope+paying surface gets hit immediately.
# Resets to top when the corpus is fully walked.
cursor_raw="$(cat "$CURSOR" 2>/dev/null || echo '[]')"
after_fs="$(jq -r '.[0] // ""' <<<"$cursor_raw" 2>/dev/null || echo '')"
after_host="$(jq -r '.[1] // ""' <<<"$cursor_raw" 2>/dev/null || echo '')"
Q=$(jq -nc --argjson n "$BATCH" --arg afs "$after_fs" --arg ah "$after_host" '
  {size:$n,_source:["host","triage_program","first_seen"],
   sort:[{"first_seen":{"order":"desc","missing":"_last"}},{"host":"asc"}],
   query:{bool:{
     filter:[{term:{triage_in_scope:true}},{term:{triage_pays:true}},{term:{status_code:200}}],
     must_not:[{range:{ignore_expires_at:{gt:"now"}}},{term:{triage_out_of_scope:true}},
       {wildcard:{host:"*.tumblr.com"}},{wildcard:{host:"*.statuspage.io"}},
       {wildcard:{host:"*.myshopify.com"}},{wildcard:{host:"*.zendesk.com"}},{wildcard:{host:"*.github.io"}},
       {wildcard:{host:"*.fanbox.cc"}},{wildcard:{host:"*.lemonsqueezy.com"}},{wildcard:{host:"*.hubspotpagebuilder.com"}},
       {wildcard:{host:"*.gumroad.com"}},{wildcard:{host:"*.notion.site"}},{wildcard:{host:"*.webflow.io"}},
       {wildcard:{host:"*.framer.website"}},{wildcard:{host:"*.carrd.co"}},{wildcard:{host:"*.substack.com"}},
       {wildcard:{host:"*.wixsite.com"}},{wildcard:{host:"*.medium.com"}},{wildcard:{host:"*.blogspot.com"}},
       {regexp:{host:"[0-9a-f]{8}-[0-9a-f]{4}-.*"}},
       {wildcard:{host:"*.unifi-hosting.ui.com"}},{wildcard:{host:"*.ui.com"}}]}}}
  | if ($afs|length)>0 then . + {search_after:[($afs|if . == "" then null else . end),$ah]} else . end')
resp="$(curl -sS -m60 --netrc-file "$NETRC" -H 'Content-Type: application/json' -X POST "$ES/_search" -d "$Q" 2>/dev/null)"
mapfile -t rows < <(jq -r '.hits.hits[]? | [(._source.host//""),(._source.triage_program//"")] | @tsv' <<<"$resp" 2>/dev/null)
last_host="$(jq -r '.hits.hits[-1]?._source.host // empty' <<<"$resp" 2>/dev/null)"
last_fs="$(jq -r '.hits.hits[-1]?._source.first_seen // ""' <<<"$resp" 2>/dev/null)"
if [ "${#rows[@]}" -eq 0 ]; then
  log "app-ish corpus fully walked — resetting cursor to restart from top (new hosts will surface first)"
  : > "$CURSOR"; exit 0
fi
if [ "$last_host" = "$after_host" ] && [ "$last_fs" = "$after_fs" ]; then
  log "cursor stall guard tripped ($last_host) — resetting"; : > "$CURSOR"; exit 0
fi
log "batch: ${#rows[@]} app-ish hosts (newest-first; from '${after_host:0:30}') -> next '${last_host:0:40}'"

# ---- 2) harvest pools from this batch (amplify config paths + root main-JS)
CAND="$(mktemp)"; printf '%s\n' "${rows[@]}" | awk -F'\t' 'NF{print $1"\t"$2}' > "$CAND"
NEW="$(mktemp)"; : > "$NEW"
harvest(){
  local host="$1" program="$2" body pools mainjs u p
  grep -qxF "$host" "$LEDGER" 2>/dev/null && return 0
  for p in aws-exports.js amplifyconfiguration.json; do
    body="$(curl -sS -m8 -A "$UA" "https://${host}/${p}" 2>/dev/null | head -c 200000)" || continue
    pools="$(grep -aoE "$POOL_RE" <<<"$body" | sort -u)"
    [ -n "$pools" ] && while read -r pool; do [ -n "$pool" ] && jq -nc --arg h "$host" --arg pr "$program" --arg pool "$pool" --arg r "${pool%%:*}" --arg k "$p" --arg t "$(date -u +%FT%TZ)" '{provenance:$h,program:$pr,pool:$pool,region:$r,source_key:$k,kind:"night-amplify",at:$t}'; done <<<"$pools"
  done
  body="$(curl -sS -m9 -A "$UA" "https://${host}/" 2>/dev/null | head -c 400000)" || return
  mainjs="$(grep -aoE '(src|href)="[^"]*(main|app|runtime|index|vendor|chunk)[.-][0-9a-zA-Z]+\.js"' <<<"$body" | sed -E 's/.*"([^"]+)".*/\1/' | head -4)"
  while read -r j; do
    [ -z "$j" ] && continue
    case "$j" in http*) u="$j";; /*) u="https://${host}${j}";; *) u="https://${host}/${j}";; esac
    pools="$(curl -sS -m12 -A "$UA" "$u" 2>/dev/null | grep -aoE "$POOL_RE" | sort -u)"
    [ -n "$pools" ] && while read -r pool; do [ -n "$pool" ] && jq -nc --arg h "$host" --arg pr "$program" --arg pool "$pool" --arg r "${pool%%:*}" --arg k "$u" --arg t "$(date -u +%FT%TZ)" '{provenance:$h,program:$pr,pool:$pool,region:$r,source_key:$k,kind:"night-mainjs",at:$t}'; done <<<"$pools"
  done <<<"$mainjs"
}
export -f harvest; export UA POOL_RE LEDGER
awk -F'\t' '{print $1"\t"$2}' "$CAND" | xargs -P "$PAR" -I{} bash -c 'IFS=$'"'"'\t'"'"' read -r h p <<<"$1"; harvest "$h" "$p"' _ {} 2>/dev/null >> "$NEW"
# record batch hosts as scanned + advance cursor (JSON [first_seen, host] for search_after)
awk -F'\t' '{print $1}' "$CAND" >> "$LEDGER"
[ -n "$last_host" ] && jq -nc --arg fs "$last_fs" --arg h "$last_host" '[$fs,$h]' > "$CURSOR"
cat "$NEW" >> "$POOLS"
nnew="$(jq -r '.pool' "$NEW" 2>/dev/null | sort -u | grep -c . || true)"
log "harvested $nnew new pool id(s) this batch"
[ "${nnew:-0}" -eq 0 ] && { rm -f "$CAND" "$NEW"; exit 0; }

# ---- 3) test issuance -> assess issuers -> REAL gate -> ping+mint
declare -A TESTED
while IFS= read -r line; do
  pool="$(jq -r '.pool' <<<"$line")"; region="$(jq -r '.region' <<<"$line")"
  prov="$(jq -r '.provenance' <<<"$line")"; program="$(jq -r '.program' <<<"$line")"
  [ -z "$pool" ] && continue; [ -n "${TESTED[$pool]:-}" ] && continue; TESTED[$pool]=1
  v="$(python3 "$TESTER" "$pool" --region "$region" 2>/dev/null)"
  verdict="$(jq -r '.verdict//"error"' <<<"$v")"
  [ "$verdict" != "issued" ] && { printf '%s\n' "$(jq -c --arg p "$prov" --arg pr "$program" '.+{provenance:$p,program:$pr}' <<<"$v")" >> "$FP"; continue; }
  role="$(jq -r '.assumed_role_arn//""' <<<"$v")"
  # RUM roles are by-design; skip assess, log FP
  if grep -qiE 'rum|RUM-Monitor' <<<"$role"; then
    log "  FP (CloudWatch RUM by-design): $pool <- $prov"
    printf '%s\n' "$(jq -c --arg p "$prov" --arg pr "$program" '.+{provenance:$p,program:$pr,fp_reason:"cw-rum-by-design"}' <<<"$v")" >> "$FP"; continue
  fi
  va="$(python3 "$TESTER" "$pool" --region "$region" --assess 2>/dev/null)"
  nallow="$(jq -r '(.blast_radius.allowed//[])|length' <<<"$va" 2>/dev/null || echo 0)"
  if [ "${nallow:-0}" -ge 1 ]; then
    # provenance must be in-scope+paying to mint
    if bash "$SCOPE_CHECK" --filter in-scope-paying <<<"$prov" 2>/dev/null | grep -qxF "$prov"; then
      allowed="$(jq -rc '.blast_radius.allowed' <<<"$va")"
      acct="$(jq -r '.account//"?"' <<<"$va")"
      # PROGRAM-SCOPE CARVE-OUT: real but unreportable (Amazon VRP / AWS VDP dead zone) ->
      # downgrade to a permanent host_note, do NOT db_confirm or ping #review.
      if carve="$(cognito_carveout_reason "$program" "$prov" "$acct")"; then
        log "  ⛔ REAL but OOS program carve-out [$carve]: $pool <- $prov [$program] acct=$acct allowed=$allowed — host_note, no #review"
        NOTES_NO_SCOPE=1 note_add "$prov" \
          "cognito-real-but-OOS-program-carveout [$carve]: unauth Cognito pool $pool issues guest creds -> role $role (AWS acct $acct) reaches $allowed, but the program excludes AWS/customer-asset findings (Amazon VRP carves out 'AWS and AWS customer assets' + lists disclosed-creds->pivot as invalid; AWS VDP excludes customer misconfig, no bounty). REAL finding, no valid venue -> not reported. ($(date -u +%F))" \
          "cognito-nighthunt" "" "$program" 2>/dev/null || true
        printf '%s\n' "$(jq -c --arg p "$prov" --arg pr "$program" --arg r "$carve" '.+{provenance:$p,program:$pr,fp_reason:"oos-program-carveout",carveout:$r}' <<<"$va")" >> "$FP"
        continue
      fi
      log "  🔥 REAL FINDING: $pool <- $prov [$program] role=$role acct=$acct allowed=$allowed"
      printf '%s\n' "$(jq -c --arg p "$prov" --arg pr "$program" '.+{provenance:$p,program:$pr}' <<<"$va")" >> "$CONFIRMED"
      # mint into findings.db (verify gate)
      type db_confirm >/dev/null 2>&1 && db_confirm "$prov" "https://$prov/" "$program" "cognito-unauth" "unauth-cognito-cred-issuance-permissive-role" "9" "0.9" "$va" || true
      # PING DISCORD #review
      hook="$(discord_hook review 2>/dev/null || true)"
      if [ -n "$hook" ]; then
        payload="$(jq -nc --arg t "🔥 REAL unauth Cognito finding — $program" \
          --arg d "**$prov** ($program)\nPool: \`$pool\`\nAccount: $acct\nRole: \`$role\`\nUnauth role REACHES: $allowed\n(issued via GetId+GetCredentialsForIdentity, no auth; blast-radius = safe list/describe only)" \
          '{embeds:[{title:$t,description:$d,color:15158332}]}')"
        discord_post "$hook" "$payload" && log "     ✅ pinged Discord #review" || log "     ⚠️ Discord ping failed"
      else
        log "     ⚠️ no #review webhook configured"
      fi
    else
      log "  issued+permissive but provenance not in-scope-paying (scope_check): $pool <- $prov"
      printf '%s\n' "$(jq -c --arg p "$prov" '.+{provenance:$p,fp_reason:"scope-gate"}' <<<"$va")" >> "$FP"
    fi
  else
    log "  FP (zero-perm role): $pool <- $prov role=$role"
    printf '%s\n' "$(jq -c --arg p "$prov" --arg pr "$program" '.+{provenance:$p,program:$pr,fp_reason:"zero-perm-role"}' <<<"$va")" >> "$FP"
  fi
done < "$NEW"
rm -f "$CAND" "$NEW"
log "cycle done. real-findings total: $(grep -c . "$CONFIRMED" 2>/dev/null || echo 0)"

#!/usr/bin/env bash
# =============================================================================
# recon_cognito_mobile.sh — MOBILE-APK prong of the cognito lane.
# Legacy AWS MobileHub pools (the permissive ones — Logitech's Critical) live in
# mobile apps. For each in-scope+paying Android package: apkeep-download the APK
# (from APKPure — 3rd-party CDN, NOT the bug-bounty target), extract Amplify /
# awsconfiguration / hardcoded Cognito pool IDs, test unauth issuance, blast-radius
# assess, and PING #review + mint ONLY on a REAL finding (issued + role reaches
# resources). RUM/zero-perm = FP. APK download is not target traffic, but the
# cognito/sts test hits AWS → keep VPN-gated (fail-closed).
# Usage: recon_cognito_mobile.sh [max_packages] [--all]   (default: paying only)
# =============================================================================
set -uo pipefail
SD="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SD/recon_net.sh" 2>/dev/null || true
source "$SD/recon_notes.sh" 2>/dev/null || true          # note_add for OOS-carveout downgrade
source "$SD/recon_cognito_carveout.sh" 2>/dev/null || true  # cognito_carveout_reason guard
DIR="$HOME/recon/cognito"; mkdir -p "$DIR"
APKS="$DIR/apks.jsonl"; POOLS="$DIR/pools.jsonl"
CONFIRMED="$DIR/confirmed_real.jsonl"; FP="$DIR/fp.jsonl"
LEDGER="$DIR/apk_scanned.txt"; LOG="$DIR/mobile.log"
TESTER="$SD/../engine/recon_cognito_test.py"; SCOPE_CHECK="$SD/recon_scope_check.sh"
APKEEP="$(command -v apkeep || echo "$HOME/.cargo/bin/apkeep")"
POOL_RE='[a-z]{2}-[a-z]+-[0-9]:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
MAX="${1:-40}"; ONLY_PAYS=1; [ "${2:-}" = "--all" ] && ONLY_PAYS=0
touch "$POOLS" "$CONFIRMED" "$FP" "$LEDGER"
log(){ printf '[%s MOBILE] %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$LOG" >&2; }
[ -f "$DIR/STOP_MOBILE" ] && { log "STOP_MOBILE present"; exit 0; }
[ -f "$HOME/recon/state/vpn_down" ] && { log "vpn_down — fail-closed"; exit 0; }
[ -x "$APKEEP" ] || { log "apkeep not installed ($APKEEP)"; exit 1; }
[ -s "$APKS" ] || { log "no apks.jsonl — run engine/recon_cognito_apks.py first"; exit 1; }

# candidate packages (paying first, dedup vs ledger), highest-value keywords first
mapfile -t pkgs < <(
  jq -r --argjson pays "$ONLY_PAYS" 'select($pays==0 or .pays==true) | "\(.package)\t\(.program)"' "$APKS" \
  | awk -F'\t' 'NF && !s[$1]++' \
  | grep -aviE '^(app\.bitrise|cdn\.|amazon\.speech)' \
  | grep -aivFf <(cut -f1 "$LEDGER" 2>/dev/null || true) 2>/dev/null || \
    jq -r --argjson pays "$ONLY_PAYS" 'select($pays==0 or .pays==true)|"\(.package)\t\(.program)"' "$APKS" | awk -F'\t' 'NF && !s[$1]++'
)
log "candidate packages: ${#pkgs[@]} (max this run: $MAX)"

pooled=0; realhits=0; done=0
for row in "${pkgs[@]}"; do
  [ "$done" -ge "$MAX" ] && break
  [ -f "$DIR/STOP_MOBILE" ] && break
  pkg="${row%%$'\t'*}"; program="${row#*$'\t'}"
  grep -qxF "$pkg" <(cut -f1 "$LEDGER" 2>/dev/null) && continue
  done=$((done+1))
  wd="$(mktemp -d)"
  log "[$done/$MAX] $pkg [$program] — downloading"
  timeout 240 "$APKEEP" -a "$pkg" -d apk-pure "$wd" >>"$LOG" 2>&1 || true
  printf '%s\t%s\n' "$pkg" "$(date -u +%FT%TZ)" >> "$LEDGER"
  # unpack: xapk (zip of apks) and apk (zip) — recurse one level
  find "$wd" -maxdepth 1 -type f \( -iname '*.xapk' -o -iname '*.apk' -o -iname '*.apkm' \) 2>/dev/null | while read -r f; do
    unzip -o -qq "$f" -d "$wd/x" 2>/dev/null || true
  done
  find "$wd/x" -type f -iname '*.apk' 2>/dev/null | while read -r inner; do unzip -o -qq "$inner" -d "$wd/x" 2>/dev/null || true; done
  # extract pool ids: text/config resources + dex strings
  pools="$( { grep -arohE "$POOL_RE" "$wd/x" 2>/dev/null;
              find "$wd/x" -type f -iname '*.dex' -exec strings {} \; 2>/dev/null | grep -aoE "$POOL_RE";
              find "$wd/x" -type f \( -iname 'amplifyconfiguration.json' -o -iname 'awsconfiguration.json' -o -iname 'aws-exports*' \) -exec grep -aoE "$POOL_RE" {} \; 2>/dev/null;
            } | sort -u )"
  if [ -n "$pools" ]; then
    while read -r pool; do
      [ -z "$pool" ] && continue
      pooled=$((pooled+1))
      jq -nc --arg h "apk:$pkg" --arg pr "$program" --arg pool "$pool" --arg r "${pool%%:*}" --arg t "$(date -u +%FT%TZ)" \
        '{provenance:$h,program:$pr,pool:$pool,region:$r,source_key:$h,kind:"apk",at:$t}' >> "$POOLS"
      log "   POOL $pool  <- $pkg [$program]"
      # test issuance
      v="$(python3 "$TESTER" "$pool" --region "${pool%%:*}" 2>/dev/null)"
      verdict="$(jq -r '.verdict//"error"' <<<"$v")"
      role="$(jq -r '.assumed_role_arn//""' <<<"$v")"
      if [ "$verdict" != "issued" ]; then log "     $verdict (not issued)"; printf '%s\n' "$(jq -c --arg p "apk:$pkg" --arg pr "$program" '.+{provenance:$p,program:$pr}' <<<"$v")" >> "$FP"; continue; fi
      if grep -qiE 'rum|RUM-Monitor' <<<"$role"; then log "     FP RUM by-design"; printf '%s\n' "$(jq -c --arg p "apk:$pkg" '.+{provenance:$p,fp_reason:"cw-rum"}' <<<"$v")" >> "$FP"; continue; fi
      va="$(python3 "$TESTER" "$pool" --region "${pool%%:*}" --assess 2>/dev/null)"
      nallow="$(jq -r '(.blast_radius.allowed//[])|length' <<<"$va" 2>/dev/null || echo 0)"
      if [ "${nallow:-0}" -ge 1 ]; then
        allowed="$(jq -rc '.blast_radius.allowed' <<<"$va")"; acct="$(jq -r '.account//"?"' <<<"$va")"
        # PROGRAM-SCOPE CARVE-OUT: real but unreportable (Amazon VRP / AWS VDP dead zone,
        # e.g. com.amazon.relay) -> host_note, do NOT db_confirm or ping #review.
        if carve="$(cognito_carveout_reason "$program" "apk:$pkg" "$acct")"; then
          log "   ⛔ REAL but OOS program carve-out [$carve]: $pool <- apk:$pkg [$program] acct=$acct allowed=$allowed — host_note, no #review"
          NOTES_NO_SCOPE=1 note_add "apk:$pkg" \
            "cognito-real-but-OOS-program-carveout [$carve]: unauth Cognito pool $pool (mobile apk:$pkg) issues guest creds -> role $role (AWS acct $acct) reaches $allowed, but the program excludes AWS/customer-asset findings (Amazon VRP carves out 'AWS and AWS customer assets' + lists disclosed-creds->pivot as invalid; AWS VDP excludes customer misconfig, no bounty). REAL finding, no valid venue -> not reported. ($(date -u +%F))" \
            "cognito-mobile" "" "$program" 2>/dev/null || true
          printf '%s\n' "$(jq -c --arg p "apk:$pkg" --arg pr "$program" --arg r "$carve" '.+{provenance:$p,program:$pr,fp_reason:"oos-program-carveout",carveout:$r}' <<<"$va")" >> "$FP"
          continue
        fi
        realhits=$((realhits+1))
        log "   🔥 REAL FINDING: $pool <- apk:$pkg [$program] acct=$acct allowed=$allowed"
        printf '%s\n' "$(jq -c --arg p "apk:$pkg" --arg pr "$program" '.+{provenance:$p,program:$pr}' <<<"$va")" >> "$CONFIRMED"
        type db_confirm >/dev/null 2>&1 && db_confirm "apk:$pkg" "https://play.google.com/store/apps/details?id=$pkg" "$program" "cognito-unauth" "unauth-cognito-cred-issuance-permissive-role-mobile" "9" "0.9" "$va" || true
        hook="$(discord_hook review 2>/dev/null || true)"
        if [ -n "$hook" ]; then
          discord_post "$hook" "$(jq -nc --arg t "🔥 REAL unauth Cognito finding (mobile) — $program" --arg d "**APK:** \`$pkg\` ($program)\nPool: \`$pool\`\nAccount: $acct\nRole: \`$role\`\nUnauth role REACHES: $allowed\n(GetId+GetCredentialsForIdentity, no auth; blast-radius = safe list/describe only)" '{embeds:[{title:$t,description:$d,color:15158332}]}')" && log "     ✅ pinged #review" || log "     ⚠️ ping failed"
        fi
      else
        log "     FP zero-perm role"; printf '%s\n' "$(jq -c --arg p "apk:$pkg" '.+{provenance:$p,fp_reason:"zero-perm"}' <<<"$va")" >> "$FP"
      fi
    done <<<"$pools"
  fi
  rm -rf "$wd"
done
log "mobile run done: scanned=$done packages, pools=$pooled, REAL findings=$realhits"

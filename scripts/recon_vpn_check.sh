#!/usr/bin/env bash
# =============================================================================
# recon_vpn_check.sh — the ONE egress check for the whole pipeline.
# Multi-method + CACHED so we never rate-limit am.i.mullvad:
#   1. exit IP via neutral echo (rotate ipify/ifconfig/icanhazip/ipinfo — robust, NOT Mullvad)
#   2. local KNOWN-Mullvad cache  -> instant confirm, ZERO external Mullvad calls
#   3. local LEAK cache           -> instant leak detection
#   4. am.i.mullvad (authoritative) — called ONLY for a NEW/unknown exit IP, then cached
#   5. org/ASN fallback (ipinfo)  — if am.i.mullvad is down on a new IP (hosting provider = tunneled)
# Writes ~/recon/state/vpn_status.json {mullvad,ip,method,checked_at} for everyone else to READ.
# Exit: 0 = Mullvad-confirmed | 1 = LEAK | 2 = unknown (caller stays fail-closed). Prints a status word.
# Usage: recon_vpn_check.sh [--cached]   (--cached reuses vpn_status.json if younger than VPN_CACHE_TTL)
# =============================================================================
set -uo pipefail
STATE_DIR="${STATE_DIR:-$HOME/recon/state}"; mkdir -p "$STATE_DIR"
KNOWN="$STATE_DIR/vpn_known_mullvad_ips.txt"; LEAK="$STATE_DIR/vpn_leak_ips.txt"
STATUS="$STATE_DIR/vpn_status.json"; CACHE_TTL="${VPN_CACHE_TTL:-45}"
_now(){ date +%s; }
_write(){ printf '{"mullvad":%s,"ip":"%s","method":"%s","checked_at":%s}\n' "$1" "$2" "$3" "$(_now)" > "$STATUS"; }

# --cached: reuse a fresh verdict (callers that don't need a live probe)
if [[ "${1:-}" == "--cached" && -f "$STATUS" ]]; then
  age=$(( $(_now) - $(jq -r '.checked_at // 0' "$STATUS" 2>/dev/null || echo 0) ))
  if [[ "$age" -lt "$CACHE_TTL" ]]; then
    case "$(jq -r '.mullvad' "$STATUS" 2>/dev/null)" in
      true) echo mullvad-cached; exit 0 ;; false) echo leak-cached; exit 1 ;; *) echo unknown-cached; exit 2 ;;
    esac
  fi
fi

# 1) exit IP via neutral echo (rotate + validate) — these are reliable and NOT Mullvad endpoints
exip=""
for u in https://api.ipify.org https://ifconfig.me/ip https://icanhazip.com https://ipinfo.io/ip; do
  exip="$(curl -sS -m8 "$u" 2>/dev/null | tr -d ' \r\n')"
  [[ "$exip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] && break || exip=""
done
[[ -n "$exip" ]] || { _write null "" no-network; echo unknown; exit 2; }

# 2/3) local caches — ZERO external Mullvad calls for a known IP (the rate-limit killer)
if grep -qxF "$exip" "$LEAK"  2>/dev/null; then _write false "$exip" leak-cache;  echo leak;    exit 1; fi
if grep -qxF "$exip" "$KNOWN" 2>/dev/null; then _write true  "$exip" known-cache; echo mullvad; exit 0; fi

# 4) NEW ip -> authoritative am.i.mullvad (retry 3) — the ONLY place we touch it, and only on a new IP
m=""
for t in 1 2; do m="$(curl -sS -m6 https://am.i.mullvad.net/json 2>/dev/null | jq -r '.mullvad_exit_ip // empty' 2>/dev/null)"; [[ -n "$m" ]] && break; sleep 1; done
if [[ "$m" == "true"  ]]; then grep -qxF "$exip" "$KNOWN" 2>/dev/null || echo "$exip" >> "$KNOWN"; _write true  "$exip" am.i.mullvad; echo mullvad; exit 0; fi
if [[ "$m" == "false" ]]; then grep -qxF "$exip" "$LEAK"  2>/dev/null || echo "$exip" >> "$LEAK";  _write false "$exip" am.i.mullvad; echo leak;    exit 1; fi

# 5) am.i.mullvad unreachable on a NEW ip -> org/ASN fallback (ipinfo = different host). For a Mullvad-only
#    operator, a hosting/datacenter exit (NOT the residential ISP) means tunneled. Confirm but DON'T cache.
org="$(curl -sS -m8 "https://ipinfo.io/$exip/org" 2>/dev/null | tr 'A-Z' 'a-z')"
if printf '%s' "$org" | grep -qE 'tzulo|m247|31173|datapacket|xtom|blix|qrator|creanova|mullvad|globalconnect|estnoc|netcup|servinga|cdn77|31173 services'; then
  _write true "$exip" "org:${org:0:40}"; echo mullvad-via-org; exit 0
fi
# 6) can't confirm -> fail-closed (caller refuses/pauses)
_write null "$exip" "unconfirmed:${org:0:40}"; echo unknown; exit 2

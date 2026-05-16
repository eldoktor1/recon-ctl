#!/usr/bin/env bash
# Shared fail-closed network helpers.

PROXY_URL="${PROXY_URL:-socks5h://127.0.0.1:9050}"
USE_PROXYCHAINS="${USE_PROXYCHAINS:-1}"

proxy_required() { [[ "${USE_PROXYCHAINS:-1}" == "1" ]]; }

proxy_listener_ready() {
  ss -ltn 2>/dev/null | grep -q '127\.0\.0\.1:9050'
}

ensure_proxy_ready() {
  proxy_required || return 0
  command -v proxychains4 >/dev/null 2>&1 || {
    printf '[recon-net] USE_PROXYCHAINS=1 but proxychains4 is missing\n' >&2
    return 1
  }
  proxy_listener_ready || {
    printf '[recon-net] USE_PROXYCHAINS=1 but Tor SOCKS listener 127.0.0.1:9050 is not up\n' >&2
    return 1
  }
}

run_net() {
  ensure_proxy_ready || return 1
  if proxy_required; then
    proxychains4 -q "$@"
  else
    "$@"
  fi
}

# v2.5.5: curl_direct — bypass Tor entirely. Use for non-target-facing,
# trusted-destination traffic ONLY: Discord (api.discord.com is on the public
# internet but Discord blocks Tor exits, breaking webhooks + bot polling),
# crt.sh polling, certstream, our local services. Never use this for any
# scan/probe against a bug-bounty target — that's what curl_net is for.
curl_direct() {
  curl "$@"
}

curl_net() {
  if proxy_required; then
    # curl_net uses --proxy, not proxychains4; only check the SOCKS listener.
    proxy_listener_ready || {
      printf '[recon-net] Tor SOCKS not available at 127.0.0.1:9050 — skipping call\n' >&2
      return 1
    }
    curl --proxy "$PROXY_URL" "$@"
  else
    curl "$@"
  fi
}

# -----------------------------------------------------------------------------
# Browser-like HTTP helpers (v2.5)
# random_user_agent: prints one UA from $UA_FILE (one per line).
# browser_curl: wraps curl_net with a random real-browser UA + matching headers.
#   Any flags passed are appended after the synthesized headers, so callers can
#   still set -m/-X/-o/-d/-H etc. Sec-Ch-Ua headers are added only for Chrome.
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

  # Derive platform string for Sec-Ch-Ua-Platform
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

  curl_net "${base_headers[@]}" --compressed "$@"
}

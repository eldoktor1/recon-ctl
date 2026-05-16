#!/usr/bin/env bash
# Shared network helpers.
# All recon traffic egresses via the host's default route (Mullvad WireGuard).

# Thin wrappers — call sites use these so any future proxy layer only needs
# to change here.
run_net()    { "$@"; }
curl_net()   { curl "$@"; }
curl_direct() { curl "$@"; }

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

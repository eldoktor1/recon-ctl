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

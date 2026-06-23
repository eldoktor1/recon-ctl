#!/usr/bin/env bash
# =============================================================================
# recon_multitunnel.sh — parallel Mullvad egress via gluetun proxy containers.
#
# WHY: one Mullvad exit IP caps polite scan throughput (anti-ban). N WireGuard
# tunnels to N different relays = N distinct exit IPs; run one scanner worker per
# proxy, each at the polite per-IP rate => ~Nx aggregate with no single IP banned.
#
# WHAT: builds one gluetun container per ~/.config/mullvad-tunnels/*.conf, each
# exposing a local HTTP proxy on 127.0.0.1:888N with gluetun's built-in
# FAIL-CLOSED killswitch (FIREWALL=on => tunnel down = NO traffic, never the real
# IP). Emits the proxy list to $STATE/egress_proxies.txt for the pipeline to read.
#
# HARD LINE (egress safety): this NEVER touches host nftables/iptables or the live
# Mullvad egress. The containers are an ISOLATED, additive capability. Pointing the
# pipeline's scanners at these proxies (the CUTOVER) is a SEPARATE, operator-
# reviewed step — do NOT wire it autonomously. Each tunnel is fail-closed by design;
# re-prove that at cutover (kill a tunnel, confirm its proxy blocks, never leaks).
#
# Mullvad .conf gotcha: the Address line carries IPv4+IPv6; gluetun rejects the
# IPv6 unless IPv6 is enabled in the container, so we pass the IPv4 /32 only.
#
# SUBCOMMANDS: build | up | down | test | status | proxies
# =============================================================================
set -uo pipefail
CFGDIR="${MT_CFGDIR:-$HOME/.config/mullvad-tunnels}"
WORK="${MT_WORK:-$HOME/recon/multitunnel}"
STATE="${STATE_DIR:-$HOME/recon/state}"
BASE_PORT="${MT_BASE_PORT:-8881}"
COMPOSE="$WORK/docker-compose.yml"
PROXY_LIST="$STATE/egress_proxies.txt"

log(){ printf '[multitunnel] %s\n' "$*" >&2; }
parse(){ grep -iE "^[[:space:]]*$1[[:space:]]*=" "$2" 2>/dev/null | head -1 | cut -d= -f2- | tr -d ' \t\r'; }

cmd_build(){
  mkdir -p "$WORK" "$STATE"; chmod 700 "$WORK"
  mapfile -t confs < <(ls "$CFGDIR"/*.conf 2>/dev/null | grep -v ':Zone')
  [ "${#confs[@]}" -gt 0 ] || { log "no .conf files in $CFGDIR"; exit 1; }
  echo "services:" > "$COMPOSE"; : > "$PROXY_LIST"
  local port="$BASE_PORT" c name svc pk addr pub ep epip epport envf n=0
  for c in "${confs[@]}"; do
    name="$(basename "$c" .conf)"; svc="tun_$(echo "$name" | tr -c 'a-zA-Z0-9' '_')"
    pk="$(parse PrivateKey "$c")"; addr="$(parse Address "$c")"; addr="${addr%%,*}"   # IPv4 only
    pub="$(parse PublicKey "$c")"; ep="$(parse Endpoint "$c")"; epip="${ep%:*}"; epport="${ep##*:}"
    envf="$WORK/${svc}.env"
    { echo "VPN_SERVICE_PROVIDER=custom"; echo "VPN_TYPE=wireguard"
      echo "WIREGUARD_PRIVATE_KEY=$pk"; echo "WIREGUARD_ADDRESSES=$addr"
      echo "WIREGUARD_PUBLIC_KEY=$pub"; echo "WIREGUARD_ENDPOINT_IP=$epip"
      echo "WIREGUARD_ENDPOINT_PORT=$epport"; echo "HTTPPROXY=on"; echo "FIREWALL=on"
      echo "HEALTH_VPN_DURATION_INITIAL=30s"; } > "$envf"
    chmod 600 "$envf"
    cat >> "$COMPOSE" <<EOF
  ${svc}:
    image: qmcgaw/gluetun
    container_name: ${svc}
    cap_add: [NET_ADMIN]
    devices: ["/dev/net/tun:/dev/net/tun"]
    env_file: ["${envf}"]
    ports: ["127.0.0.1:${port}:8888"]
    restart: unless-stopped
EOF
    if [ -n "$pk" ] && [ -n "$addr" ] && [ -n "$pub" ] && [ -n "$epip" ]; then
      echo "http://127.0.0.1:${port}" >> "$PROXY_LIST"
      log "✓ $name -> 127.0.0.1:$port (addr=$addr endpoint=$epip:$epport)"
    else
      log "⚠ $name -> SKIPPED proxy emit (missing fields)"
    fi
    port=$((port+1)); n=$((n+1))
  done
  log "built $n tunnel(s): $COMPOSE | proxies -> $PROXY_LIST"
}

TOGGLE="$STATE/multitunnel_on"
cmd_on(){  mkdir -p "$STATE"; touch "$TOGGLE"; log "multitunnel ENABLED (toggle set) — restart the pipeline (recon-start) to apply"; }
cmd_off(){ rm -f "$TOGGLE"; log "multitunnel DISABLED — restart the pipeline (recon-start) to apply"; }
cmd_up(){   [ -f "$COMPOSE" ] || cmd_build; ( cd "$WORK" && docker compose up -d ); }
cmd_down(){ [ -f "$COMPOSE" ] && ( cd "$WORK" && docker compose down ); }
cmd_status(){ echo "toggle: $( [ -f "$TOGGLE" ] && echo ON || echo off ) | proxies: $(wc -l < "$PROXY_LIST" 2>/dev/null || echo 0)"; [ -f "$COMPOSE" ] && ( cd "$WORK" && docker compose ps ); }
cmd_proxies(){ cat "$PROXY_LIST" 2>/dev/null; }
cmd_test(){
  [ -s "$PROXY_LIST" ] || { log "no proxy list — run build/up first"; exit 1; }
  local p r ip srv mx
  while read -r p; do
    [ -z "$p" ] && continue
    r="$(curl -s -m 20 -x "$p" https://am.i.mullvad.net/json 2>/dev/null)"
    if [ -n "$r" ]; then
      ip="$(echo "$r" | grep -o '"ip":"[^"]*"' | cut -d'"' -f4)"
      srv="$(echo "$r" | grep -o '"mullvad_exit_ip_hostname":"[^"]*"' | cut -d'"' -f4)"
      mx="$(echo "$r" | grep -o '"mullvad_exit_ip":[a-z]*' | cut -d: -f2)"
      echo "✓ $p -> mullvad=$mx ip=$ip server=$srv"
    else echo "✗ $p -> NO RESPONSE (tunnel down / fail-closed)"; fi
  done < "$PROXY_LIST"
}

case "${1:-}" in
  build) cmd_build ;; up) cmd_up ;; down) cmd_down ;;
  test) cmd_test ;; status) cmd_status ;; proxies) cmd_proxies ;;
  on) cmd_on ;; off) cmd_off ;;
  *) echo "usage: recon_multitunnel.sh {build|up|down|test|status|proxies|on|off}" >&2; exit 1 ;;
esac

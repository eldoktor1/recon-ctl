#!/usr/bin/env bash
# =============================================================================
# recon_multitunnel.sh — control + HEALTH GATE for the gluetun Mullvad proxy pool.
#
# WHY THIS EXISTS (2026-08-22). The daemon's run_scanner round-robins target traffic
# across state/egress_proxies.txt (MULTITUNNEL=1). It did so BLINDLY: on 2026-08-22
# tun_us_lax_wg_407_ sat "unhealthy" for 4h in a wireguard restart loop (handshake up,
# every DNS lookup i/o-timeout), and the RR kept handing it out — so 1 in 3 scans on the
# confirm/unique lanes silently failed. The watchdog only ever logged "multitunnel: ON".
# Nothing ever checked whether a tunnel actually carried a packet. That is the
# "assert outcomes, not success" failure mode, applied to egress.
#
# DESIGN: the MASTER pool lives in egress_proxies_all.txt; this script probes each exit
# and writes ONLY the healthy ones to egress_proxies.txt — the file the daemon already
# reads. No daemon change, no restart, takes effect on the next run_scanner call.
#
# FAIL-SAFE: if ZERO tunnels are healthy the live list is left UNTOUCHED and #ops is
# alarmed. An empty list would make MULTITUNNEL a silent no-op; the worst case either
# way is traffic on the host Mullvad exit — never the real ISP (gluetun FIREWALL=on and
# the containers sit behind the host tunnel).
#
# MODES: status | health [--quiet] | heal | add <conf> <port> [name]
# =============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/recon_net.sh" 2>/dev/null || true   # discord_hook / discord_post
BASE_DIR="${BASE_DIR:-$HOME/recon}"; STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
MASTER="${MT_PROXY_MASTER:-$STATE_DIR/egress_proxies_all.txt}"
LIVE="${MT_PROXY_LIST:-$STATE_DIR/egress_proxies.txt}"
MARK="$STATE_DIR/.multitunnel_alerted"
REALERT_H="${MT_REALERT_H:-6}"
PROBE_URL="${MT_PROBE_URL:-https://am.i.mullvad.net/json}"
PROBE_TIMEOUT="${MT_PROBE_TIMEOUT:-15}"
CONF_DIR="${MT_CONF_DIR:-$HOME/.config/mullvad-tunnels}"
# self-heal pool: the operator's folder of ALL Mullvad exit .conf files. When a tunnel's exit
# dies, autoheal draws a RANDOM working config from here (never the same dead exit). Read-only —
# this folder is NEVER written to. Falls back to CONF_DIR if the folder is not mounted.
HEAL_POOL="${MT_HEAL_POOL:-/mnt/c/Users/mhabs/Downloads/VPN configs}"
HEAL_MAX_TRIES="${MT_HEAL_MAX_TRIES:-6}"     # random configs to try per dead port before giving up
POOL_TARGET="${MT_POOL_TARGET:-3}"           # desired number of healthy exits in the pool
HEAL_BASE_PORT="${MT_HEAL_BASE_PORT:-8888}"  # base host port when adding a brand-new tunnel

ts()  { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
log() { printf '[%s MTUN] %s\n' "$(ts)" "$*" >&2; }

mkdir -p "$STATE_DIR"
# seed the master list from the live list the first time
[[ -s "$MASTER" ]] || { [[ -s "$LIVE" ]] && cp "$LIVE" "$MASTER"; }

# probe_one <proxy> -> prints "<ip> <hostname>" on success, rc 1 on failure.
# A tunnel is HEALTHY only if it carries a real request AND the exit is a Mullvad IP —
# "the container is up" proves nothing, which is the whole point of this file.
probe_one() {
  local px="$1" out ip mv hn
  out="$(curl -s --max-time "$PROBE_TIMEOUT" -x "$px" "$PROBE_URL" 2>/dev/null)" || return 1
  [[ -n "$out" ]] || return 1
  ip="$(jq -r '.ip // empty'  <<<"$out" 2>/dev/null)"
  mv="$(jq -r '.mullvad_exit_ip // false' <<<"$out" 2>/dev/null)"
  hn="$(jq -r '.mullvad_exit_ip_hostname // "?"' <<<"$out" 2>/dev/null)"
  [[ -n "$ip" && "$mv" == "true" ]] || return 1
  printf '%s %s\n' "$ip" "$hn"
}

container_for_port() {  # container_for_port <hostport> -> container name (best effort)
  local c
  for c in $(docker ps -a --filter name=tun_ --format '{{.Names}}' 2>/dev/null); do
    if docker inspect "$c" --format '{{json .HostConfig.PortBindings}}' 2>/dev/null | grep -q "\"HostPort\":\"$1\""; then
      printf '%s\n' "$c"; return 0
    fi
  done
  return 1
}

alert() {  # cooled-down #ops alarm (action-only, matches the watchdog's pattern)
  local msg="$1" now last hook
  now="$(date +%s)"; last="$(cat "$MARK" 2>/dev/null || echo 0)"
  [[ "$last" =~ ^[0-9]+$ ]] || last=0
  (( now - last >= REALERT_H * 3600 )) || { log "alert suppressed (cooldown)"; return 0; }
  hook=""
  command -v discord_hook >/dev/null 2>&1 && hook="$(discord_hook ops 2>/dev/null || true)"
  if [[ -n "$hook" ]] && command -v discord_post >/dev/null 2>&1; then
    if discord_post "$hook" "$(jq -nc --arg c "MULTITUNNEL - ${msg:0:1800}" '{content:$c}')" >/dev/null 2>&1; then
      echo "$now" > "$MARK"; log "#ops alert posted"
    else
      log "#ops post FAILED"
    fi
  else
    log "#ops webhook unset — alert not delivered: $msg"
  fi
}

cmd_status() {
  local px ok res c n=0 good=0
  while read -r px; do
    [[ -z "$px" || "$px" == \#* ]] && continue
    n=$((n+1))
    if res="$(probe_one "$px")"; then good=$((good+1)); ok="OK   $res"; else ok="DEAD"; fi
    c="$(container_for_port "${px##*:}" || echo '?')"
    printf '  %-26s %-42s [%s]\n' "$px" "$ok" "$c"
  done < "$MASTER"
  printf '  pool: %s/%s healthy\n' "$good" "$n"
}

cmd_health() {
  local quiet="${1:-}" px healthy=() dead=()
  [[ -s "$MASTER" ]] || { log "no master pool ($MASTER) — nothing to check"; return 0; }
  while read -r px; do
    [[ -z "$px" || "$px" == \#* ]] && continue
    if probe_one "$px" >/dev/null; then healthy+=("$px"); else dead+=("$px"); fi
  done < "$MASTER"

  if [[ "${#healthy[@]}" -eq 0 ]]; then
    log "ALL ${#dead[@]} tunnel(s) DEAD — leaving $LIVE untouched (fail-safe); alarming"
    alert "ALL ${#dead[@]} gluetun tunnel(s) failed the exit probe (${dead[*]}). Live pool left unchanged. Check: docker ps --filter name=tun_ ; docker logs <container>"
    return 1
  fi

  # rewrite the live list ONLY when the healthy set actually differs (atomic)
  if ! printf '%s\n' "${healthy[@]}" | cmp -s - "$LIVE" 2>/dev/null; then
    printf '%s\n' "${healthy[@]}" > "$LIVE.tmp" && mv "$LIVE.tmp" "$LIVE"
    log "pool updated: ${#healthy[@]} healthy, ${#dead[@]} removed (${dead[*]:-none})"
  fi

  if [[ "${#dead[@]}" -gt 0 ]]; then
    alert "${#dead[@]} of $(( ${#healthy[@]} + ${#dead[@]} )) gluetun tunnels DEAD (${dead[*]}) — dropped from the round-robin so scans stop failing on them. ${#healthy[@]} still carrying traffic. Fix: recon-multitunnel heal, or replace the Mullvad conf then: recon-multitunnel add <conf> <port>"
    [[ -n "$quiet" ]] || cmd_status
    return 1
  fi
  rm -f "$MARK" 2>/dev/null
  [[ -n "$quiet" ]] || log "pool OK — ${#healthy[@]} tunnel(s) carrying Mullvad traffic"
  return 0
}

cmd_heal() {  # restart the containers behind dead ports, then re-check
  local px c
  while read -r px; do
    [[ -z "$px" || "$px" == \#* ]] && continue
    probe_one "$px" >/dev/null && continue
    if c="$(container_for_port "${px##*:}")"; then
      log "restarting $c ($px)"; docker restart "$c" >/dev/null 2>&1
    else
      log "$px dead, no container found — needs a new conf: recon-multitunnel add <conf> ${px##*:}"
    fi
  done < "$MASTER"
  log "waiting for tunnels to settle"
  while read -r px; do
    [[ -z "$px" || "$px" == \#* ]] && continue
    curl -s --max-time 20 --retry 8 --retry-delay 5 --retry-all-errors -x "$px" "$PROBE_URL" >/dev/null 2>&1 || true
  done < "$MASTER"
  cmd_health
}

# read one field from a Mullvad WireGuard .conf — CRLF-safe (Windows-downloaded configs carry
# \r, which silently corrupts a key/endpoint) and READ-ONLY (the source folder is never modified).
# $1=conf path  $2=key name
_conf_field() { grep -i "^$2" "$1" 2>/dev/null | head -1 | cut -d= -f2- | tr -d ' \t\r'; }

# build_on_port <conf> <hostport> [name] — (re)build a gluetun tunnel from a Mullvad .conf on a
# specific host port, then VERIFY it carries a real Mullvad exit. Returns 0 ONLY if the tunnel
# probes healthy (a half-built tunnel is discarded, never trusted). Removes any container already
# bound to that port first, so a swap frees the old Mullvad device slot instead of orphaning it.
# Keys are read into env vars and never printed.
build_on_port() {
  local conf="$1" port="$2" name="${3:-}"
  [[ -f "$conf" ]] || { log "conf not found: $conf"; return 1; }
  local priv pub addr ep eip eport
  priv="$(_conf_field "$conf" PrivateKey)"
  pub="$(_conf_field  "$conf" PublicKey)"
  addr="$(_conf_field "$conf" Address | cut -d, -f1)"   # IPv4 /32 only (gluetun rejects the v6 unless v6 on)
  ep="$(_conf_field   "$conf" Endpoint)"
  eip="${ep%:*}"; eport="${ep##*:}"
  [[ -n "$priv" && -n "$addr" && -n "$eip" ]] || { log "conf missing PrivateKey/Address/Endpoint: $(basename "$conf")"; return 1; }
  [[ -n "$name" ]] || name="tun_$(basename "$conf" .conf | tr '.-' '__')_"

  # free the port: drop any OTHER container bound to it (avoid an orphaned device slot)
  local old; old="$(container_for_port "$port" 2>/dev/null || true)"
  [[ -n "$old" && "$old" != "$name" ]] && { log "removing stale $old on port $port"; docker rm -f "$old" >/dev/null 2>&1; }
  docker rm -f "$name" >/dev/null 2>&1

  # NOTE: the conf's own `DNS =` line is deliberately NOT propagated. Mullvad hands out
  # 100.64.0.x resolvers that BLOCK ads/trackers/malware — a blocking resolver on a recon
  # tunnel NXDOMAINs live target hosts and the pipeline records them as "dark" negatives.
  # gluetun's own DoT resolver is used instead, matching the other tunnels.
  log "building $name on 127.0.0.1:$port -> $eip:$eport (addr $addr; keys not printed)"
  docker run -d --name "$name" --cap-add=NET_ADMIN --restart unless-stopped \
    -p "127.0.0.1:$port:8888/tcp" \
    -e VPN_SERVICE_PROVIDER=custom -e VPN_TYPE=wireguard -e VPN_INTERFACE=tun0 \
    -e WIREGUARD_PRIVATE_KEY="$priv" -e WIREGUARD_PUBLIC_KEY="$pub" \
    -e WIREGUARD_ADDRESSES="$addr" \
    -e WIREGUARD_ENDPOINT_IP="$eip" -e WIREGUARD_ENDPOINT_PORT="$eport" \
    -e WIREGUARD_IMPLEMENTATION=auto \
    -e FIREWALL=on -e FIREWALL_IPTABLES_LOG_LEVEL=info \
    -e HTTPPROXY=on -e HTTPPROXY_LISTENING_ADDRESS=:8888 -e HTTPPROXY_LOG=off -e HTTPPROXY_STEALTH=off \
    -e DNS_SERVER=on -e DNS_CACHING=on -e DNS_UPSTREAM_RESOLVER_TYPE=DoT -e DNS_UPSTREAM_IPV6=off \
    -e BLOCK_ADS=off -e BLOCK_SURVEILLANCE=off -e BLOCK_MALICIOUS=on \
    -e HEALTH_SERVER_ADDRESS=127.0.0.1:9999 -e HEALTH_VPN_DURATION_INITIAL=30s \
    -e HEALTH_RESTART_VPN=on -e HEALTH_SMALL_CHECK_TYPE=icmp \
    -e HEALTH_ICMP_TARGET_IPS=1.1.1.1,8.8.8.8 \
    -e HEALTH_TARGET_ADDRESSES=cloudflare.com:443,github.com:443 \
    -e PUID=1000 -e PGID=1000 -e LOG_LEVEL=info \
    qmcgaw/gluetun >/dev/null || { log "docker run failed for $name"; return 1; }

  # wait for the first handshake, then REQUIRE a confirmed Mullvad exit before trusting it
  curl -s --max-time 20 --retry 12 --retry-delay 6 --retry-all-errors \
       -x "http://127.0.0.1:$port" "$PROBE_URL" >/dev/null 2>&1 || true
  if probe_one "http://127.0.0.1:$port" >/dev/null; then
    grep -qxF "http://127.0.0.1:$port" "$MASTER" 2>/dev/null || echo "http://127.0.0.1:$port" >> "$MASTER"
    return 0
  fi
  log "$name built but did NOT confirm a Mullvad exit — discarding"
  docker rm -f "$name" >/dev/null 2>&1
  return 1
}

cmd_add() {  # add <conf> <hostport> [name] — manual build from a Mullvad .conf
  local conf="$1" port="$2" name="${3:-}"
  [[ -f "$conf" ]] || conf="$CONF_DIR/$1"
  [[ -f "$conf" ]] || { log "conf not found: $1"; return 1; }
  # harden a LOCAL persisted copy only — NEVER modify the operator's read-only /mnt source folder
  case "$conf" in
    /mnt/*) : ;;
    *) chmod 600 "$conf" 2>/dev/null || true; rm -f "$CONF_DIR"/*:Zone.Identifier 2>/dev/null || true ;;
  esac
  build_on_port "$conf" "$port" "$name" && cmd_health
}

# seed the MASTER pool from any running tun_ containers — fixes an empty pool file so
# health/autoheal have something to track (containers can exist before MASTER is written).
seed_master_from_running() {
  [[ -s "$MASTER" ]] && return 0
  local c hp
  for c in $(docker ps --filter name=tun_ --format '{{.Names}}' 2>/dev/null); do
    hp="$(docker inspect "$c" --format '{{range $p,$b := .HostConfig.PortBindings}}{{range $b}}{{.HostPort}} {{end}}{{end}}' 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+$' | head -1)"
    [[ -n "$hp" ]] && { grep -qxF "http://127.0.0.1:$hp" "$MASTER" 2>/dev/null || echo "http://127.0.0.1:$hp" >> "$MASTER"; }
  done
  [[ -s "$MASTER" ]] && log "seeded master pool from running containers"
}

# lowest free host port >= HEAL_BASE_PORT not already claimed in MASTER
next_free_port() {
  local p="$HEAL_BASE_PORT"
  while grep -qxF "http://127.0.0.1:$p" "$MASTER" 2>/dev/null; do p=$((p+1)); done
  echo "$p"
}

# cmd_autoheal — the SELF-HEALING pool. Probe every tunnel; a dead one is first restarted
# (transient fix), then if STILL dead it is REBUILT from a RANDOM working config in the operator's
# all-exits folder ($HEAL_POOL) — never the same dead exit. Then top the pool back up to
# MT_POOL_TARGET healthy exits from the folder. Ends with cmd_health, which writes ONLY
# verified-Mullvad exits to the live pool and keeps the fail-safe (zero healthy => live list left
# untouched + #ops alarm). Fail-closed throughout: gluetun FIREWALL=on means a half-built tunnel
# carries no traffic, and a rebuilt exit only enters the live pool after it returns a Mullvad IP.
cmd_autoheal() {
  local quiet="${1:-}"
  # single-flight lock. NOTE: no `2>/dev/null` on this `exec` — with no command, exec's
  # redirections are PERMANENT for the whole script, so silencing stderr here would swallow
  # every subsequent log() line. Open the fd cleanly and guard flock instead.
  exec 9>"$STATE_DIR/.autoheal.lock"
  flock -n 9 || { log "autoheal already running — skipping"; return 0; }

  seed_master_from_running

  # locate the config pool (operator's all-exits folder; fall back to the local conf dir)
  local POOL_SRC="$HEAL_POOL"
  [[ -d "$POOL_SRC" ]] || POOL_SRC="$CONF_DIR"
  local -a POOL=()
  [[ -d "$POOL_SRC" ]] && mapfile -t POOL < <(find "$POOL_SRC" -maxdepth 1 -type f -name '*.conf' 2>/dev/null | shuf)
  log "autoheal: pool source $POOL_SRC (${#POOL[@]} configs)"

  declare -A USED=()   # exit hostnames/basenames already in play -> keep exits distinct
  local px res hn healthy=0

  # pass 1: probe MASTER, keep the healthy exits, repair the dead ones
  local -a ports=()
  while read -r px; do [[ -z "$px" || "$px" == \#* ]] && continue; ports+=("$px"); done < "$MASTER"
  for px in "${ports[@]}"; do
    if res="$(probe_one "$px")"; then
      healthy=$((healthy+1)); hn="${res##* }"; [[ -n "$hn" && "$hn" != "?" ]] && USED["$hn"]=1
      continue
    fi
    local port="${px##*:}" c
    # transient fix first: restart the existing container behind this port
    if c="$(container_for_port "$port" 2>/dev/null)"; then
      log "restarting $c ($px)"; docker restart "$c" >/dev/null 2>&1
      curl -s --max-time 25 --retry 6 --retry-delay 5 --retry-all-errors -x "$px" "$PROBE_URL" >/dev/null 2>&1 || true
      if res="$(probe_one "$px")"; then
        healthy=$((healthy+1)); hn="${res##* }"; [[ -n "$hn" && "$hn" != "?" ]] && USED["$hn"]=1
        log "$px recovered on restart"; continue
      fi
    fi
    # still dead: swap in a random WORKING exit from the folder, on the SAME port
    log "$px still dead — swapping to a fresh exit from the pool"
    local tries=0 conf base fixed=0
    for conf in "${POOL[@]}"; do
      (( tries >= HEAL_MAX_TRIES )) && break
      base="$(basename "$conf" .conf)"
      [[ -n "${USED[$base]:-}" ]] && continue           # skip an exit already live
      tries=$((tries+1))
      if build_on_port "$conf" "$port"; then
        USED["$base"]=1; healthy=$((healthy+1)); fixed=1; log "$px -> rebuilt as $base (healthy)"; break
      fi
    done
    (( fixed )) || log "$px could NOT be healed after $tries attempt(s) — health will drop it"
  done

  # pass 2: top the pool back up to target strength from the folder
  if (( healthy < POOL_TARGET )) && (( ${#POOL[@]} > 0 )); then
    local conf base port
    for conf in "${POOL[@]}"; do
      (( healthy >= POOL_TARGET )) && break
      base="$(basename "$conf" .conf)"
      [[ -n "${USED[$base]:-}" ]] && continue
      port="$(next_free_port)"
      if build_on_port "$conf" "$port"; then
        USED["$base"]=1; healthy=$((healthy+1)); log "added $base on port $port (pool $healthy/$POOL_TARGET)"
      fi
    done
  fi

  # finalize: rewrite the live pool to the verified-healthy set (keeps the fail-safe + alarm)
  cmd_health "$quiet"
}

case "${1:-status}" in
  status) cmd_status ;;
  health) shift; cmd_health "${1:-}" ;;
  heal)   cmd_heal ;;
  autoheal) shift; cmd_autoheal "${1:-}" ;;
  add)    [[ -n "${2:-}" && -n "${3:-}" ]] || { echo "usage: recon_multitunnel.sh add <conf> <hostport> [name]" >&2; exit 1; }
          cmd_add "$2" "$3" "${4:-}" ;;
  *) echo "usage: recon_multitunnel.sh {status|health [--quiet]|heal|autoheal [--quiet]|add <conf> <port> [name]}" >&2; exit 1 ;;
esac

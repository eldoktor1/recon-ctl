#!/usr/bin/env bash
# =============================================================================
# recon_ai_hunter.sh — the Claude HUNTER lane (research-backed: Big Sleep + XBOW).
#
# Turns Claude from a downstream FILTER into a per-target HUNTER. Per high-value,
# in-scope+paying target it runs the loop the published work converges on
# (docs/knowledge/class-ai-hunter-design.md):
#   SEED        pick one authorized target + its already-collected surface (variant analysis;
#               never open-ended "find bugs here").
#   MODEL+HYPOTHESIZE  Opus reasons over the full app context (endpoints/tech/notes) -> a
#               structured app-model + SPECIFIC, FOCUSED, TESTABLE, dup-aware hypotheses.
#   TEST        the TRUSTED HARNESS (not the model) runs each unauth-safe hypothesis through
#               recon_safe_probe.sh (GET/HEAD/OPTIONS, scope+pays+rate+SSRF+Mullvad gated).
#   ADJUDICATE  Opus judges the REAL probe responses -> confirmed (execution-grounded) / refuted /
#               needs-human (authed/2-account) / needs-account. Overclaiming forbidden.
#   MINT/PLAN   confirmed unauth primitive -> state.py record-confirmed (-> verify gate -> #review);
#               authed/IDOR -> a precise 2-OWNED-ACCOUNT operator plan in the hunter briefing.
#   LEARN       confirmed/FP patterns -> KB (state.py kb-record).
#
# HARD LINES (make it legit AND valid): authorized + in-scope + pays only; UNAUTH GET/HEAD/OPTIONS
# probes only (safe_probe enforces); authed/IDOR is HUMAN-in-the-loop with 2 OWNED accounts, NEVER
# autonomous; confirm-don't-exploit-past-PoC; never third-party data; Mullvad + anti-burn.
# Claude runs as d0k (Max OAuth); the only target traffic is via safe_probe. Killswitch v2_ai_hunter.
#
# EVIDENCE RULE (2026-08-20): a hypothesis is only as good as the response behind it. Every
# hypothesis carries an evidence_state the HARNESS computes — probed (a real HTTP response came
# back), blocked (a probe was attempted but a guard/cooldown/network error swallowed it), or
# not-probed (authed/unsafe by design, i.e. an operator plan). Only `probed` can ever mint, and
# an all-blocked host is WITHHELD and retried rather than written up. This is the fix for the
# heureka.sbb.ch card of 2026-08-20: one WAF 403 on /_common/file/pdf armed a 900s host cooldown,
# every subsequent probe returned host-cooldown-after-block, and the lane still published 6
# ranked hypotheses (one [high]) built on zero response data — 5 of which were false.
#
# MODES:  cycle (autonomous: pick next target) | host <host> (on-demand) | status
# =============================================================================
set -uo pipefail
IFS=$'\n\t'
log()  { printf '[%s HUNTER] %s\n'      "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s HUNTER WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/recon_net.sh" 2>/dev/null || true   # discord_post (alerts)
BASE_DIR="${BASE_DIR:-$HOME/recon}"; STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"; INDEX_NAME="${INDEX_NAME:-recon_alive}"
NETRC="${NETRC:-$HOME/.recon_es_netrc}"
ENDPOINTS="${ENDPOINTS:-$BASE_DIR/js_recon/endpoints.jsonl}"
SAFE_PROBE="${SAFE_PROBE:-$SCRIPT_DIR/recon_safe_probe.sh}"
SCOPE_CHECK="${SCOPE_CHECK:-$SCRIPT_DIR/recon_scope_check.sh}"
STATE_PY="${STATE_PY:-$REPO_DIR/engine/state.py}"
V3_DB="${V3_DB:-$BASE_DIR/v3/findings.db}"
SEEN="${HUNTER_SEEN:-$STATE_DIR/hunter_seen.txt}"        # sliding window of hunted hosts
KILL_FILE="$STATE_DIR/kill/v2_ai_hunter"
BRIEF_DIR="${BRIEF_DIR:-$BASE_DIR/briefings}"
CLAUDE_BIN="${CLAUDE_BIN:-$HOME/.local/bin/claude}"; [[ -x "$CLAUDE_BIN" ]] || CLAUDE_BIN="$(command -v claude 2>/dev/null || echo '')"
# AI failover wrapper — Claude, falling over to the local Ollama model on a usage limit
# (bidirectional; scripts/ai_invoke.sh). Falls back to the raw claude binary if absent.
AI_INVOKE="${AI_INVOKE:-$SCRIPT_DIR/ai_invoke.sh}"; [[ -x "$AI_INVOKE" ]] || AI_INVOKE="$CLAUDE_BIN"
OLLAMA_URL="${OLLAMA_URL:-http://127.0.0.1:11434}"
HUNTER_MODEL="${HUNTER_MODEL:-opus}"            # the creative hunt = frontier model (XBOW model-alloying)
# Adjudication (judging real probe responses vs expected) is discriminative, not creative — a cheaper
# model does it well. Defaults to HUNTER_MODEL (no behaviour change); set HUNTER_ADJ_MODEL=sonnet in
# state/token_budget.env to keep Opus only for hypothesis generation (token economy).
HUNTER_ADJ_MODEL="${HUNTER_ADJ_MODEL:-$HUNTER_MODEL}"
HUNTER_TIMEOUT="${HUNTER_TIMEOUT:-300}"
HUNTER_MAX_HYP="${HUNTER_MAX_HYP:-6}"           # cap probes per target (anti-burn; safe_probe also caps)
HUNTER_PROBE_BUDGET="${HUNTER_PROBE_BUDGET:-8}" # per-target probe budget (passed to safe_probe)
HUNTER_EP_CAP="${HUNTER_EP_CAP:-60}"            # endpoints fed into the model (context size guard)
HUNTER_BODY_CAP="${HUNTER_BODY_CAP:-1200}"      # probe-body chars fed back to adjudication
# probe-availability state written by recon_safe_probe.sh — read (never written) here, so the
# lane can tell BEFORE spending a hunt whether its probes can actually reach the target.
PROBE_RL_DIR="${PROBE_RL_DIR:-$STATE_DIR/probe_rl}"
PROBE_GPAUSE="${PROBE_GPAUSE:-$STATE_DIR/probe_global_pause}"
es() { curl -fsS -m 25 --netrc-file "$NETRC" -H 'Content-Type: application/json' "$@"; }

mkdir -p "$STATE_DIR" "$BRIEF_DIR" "$(dirname "$KILL_FILE")"; touch "$SEEN"
[[ -n "$CLAUDE_BIN" && -x "$CLAUDE_BIN" ]] || curl -s --max-time 5 "$OLLAMA_URL/api/tags" >/dev/null 2>&1 \
  || { warn "claude CLI not found (need Max OAuth as d0k) and no local fallback — skipping"; exit 0; }
command -v jq >/dev/null 2>&1 || { warn "jq missing"; exit 0; }
[[ -f "$KILL_FILE" ]] && { warn "killed by $KILL_FILE"; exit 0; }
[[ -f "$STATE_DIR/vpn_down" ]] && { warn "vpn_down — probes would fail-closed; skip"; exit 0; }

# ---- schemas --------------------------------------------------------------------------------
HYP_SCHEMA='{"type":"object","properties":{
 "app_model":{"type":"string"},
 "hypotheses":{"type":"array","items":{"type":"object","properties":{
   "id":{"type":"string"},"vuln_class":{"type":"string"},"target_url":{"type":"string"},
   "method":{"type":"string","enum":["GET","HEAD","OPTIONS","OTHER"]},
   "rationale":{"type":"string"},"test":{"type":"string"},"expected_positive":{"type":"string"},
   "auth_required":{"type":"boolean"},"safe_to_probe":{"type":"boolean"},
   "dup_risk":{"type":"string","enum":["low","medium","high"]},"confidence":{"type":"number"}},
   "required":["id","vuln_class","target_url","method","rationale","auth_required","safe_to_probe","confidence"]}}},
 "required":["app_model","hypotheses"]}'
ADJ_SCHEMA='{"type":"object","properties":{
 "verdicts":{"type":"array","items":{"type":"object","properties":{
   "id":{"type":"string"},"verdict":{"type":"string","enum":["confirmed","refuted","needs-human","needs-account"]},
   "vuln_class":{"type":"string"},"severity":{"type":"string","enum":["critical","high","medium","low","info"]},
   "evidence":{"type":"string"},"operator_plan":{"type":"string"},"confidence":{"type":"number"}},
   "required":["id","verdict","evidence"]}}},
 "required":["verdicts"]}'

claude_json() {  # claude_json <model> <schema> <prompt>  -> .structured_output on stdout (or empty)
  local model="$1" schema="$2" prompt="$3" out
  out="$(timeout "$HUNTER_TIMEOUT" "$AI_INVOKE" -p "$prompt" --model "$model" \
        --permission-mode dontAsk --json-schema "$schema" --output-format json \
        --no-session-persistence </dev/null 2>/dev/null)" || return 1
  printf '%s' "$out" | jq -c '.structured_output // empty' 2>/dev/null
}

# ---- SEED: scope+pays gate for a host (authoritative per-asset) ------------------------------
in_scope_pays() {  # in_scope_pays <host> -> 0 if in-scope AND paying AND not benched/OOS
  local host="$1" q r
  if [[ -f "$SCOPE_CHECK" ]]; then   # offline + authoritative (local scope files); run via bash (no +x needed)
    bash "$SCOPE_CHECK" "$host" --pays >/dev/null 2>&1 && return 0 || return 1
  fi
  q="$(jq -nc --arg h "$host" '{size:1,_source:["triage_in_scope","triage_pays"],query:{bool:{
        filter:[{term:{host:$h}},{term:{triage_in_scope:true}},{term:{triage_pays:true}}],
        must_not:[{term:{triage_out_of_scope:true}},{range:{ignore_expires_at:{gt:"now"}}}]}}}')"
  r="$(es "$ES_URL/$INDEX_NAME/_search" -d "$q" 2>/dev/null | jq -r '.hits.total.value // 0' 2>/dev/null)"
  [[ "${r:-0}" -ge 1 ]]
}
# Saturated mega-programs the hunter should stay off (dup sea) unless something compelling. Matched
# case-insensitively by whole-word program name, so a capitalized label ("Etsy") is still caught — do
# NOT rely on the saturated_deprioritized flag alone (its backfill can lag / miss case variants).
HUNTER_SATURATED="${HUNTER_SATURATED:-etsy amazonvrp quora elastic epicgames shopify reddit xiaomi automattic}"
dup_sea() {  # dup_sea <host> -> 0 (skip) if it's the mainstream dup sea WITHOUT a compelling override.
  #   - triage_ignored (product-class per-customer / third-party) = HARD skip, no override (never ours).
  #   - saturated mega-program own surface (by flag OR program name) = skip UNLESS fresh or a KEV signal
  #     makes it worth the dup-risk (the "absolutely has to be looked at" carve-out).
  local host="$1" r ign dep prog fresh kev is_giant=0
  r="$(es "$ES_URL/$INDEX_NAME/_search" -d "$(jq -nc --arg h "$host" '{size:1,_source:["triage_ignored","saturated_deprioritized","triage_program","triage_true_fresh","triage_kev_match"],query:{term:{host:$h}}}')" 2>/dev/null \
      | jq -c '.hits.hits[0]._source // {}' 2>/dev/null)"
  [[ -z "$r" || "$r" == "{}" ]] && return 1   # unknown host -> not dup-sea, allow
  ign="$(jq -r '.triage_ignored // false' <<<"$r")"
  dep="$(jq -r '.saturated_deprioritized // false' <<<"$r")"
  prog="$(jq -r '(.triage_program // "") | ascii_downcase' <<<"$r")"
  fresh="$(jq -r '.triage_true_fresh // false' <<<"$r")"
  kev="$(jq -r '.triage_kev_match // false' <<<"$r")"
  [[ "$ign" == "true" ]] && return 0                                   # product-class/third-party: always skip
  [[ "$dep" == "true" ]] && is_giant=1
  case " ${HUNTER_SATURATED} " in *" ${prog} "*) is_giant=1 ;; esac    # program-name catch (case-insensitive)
  if [[ "$is_giant" == "1" ]]; then
    [[ "$fresh" == "true" || "$kev" == "true" ]] && return 1           # compelling override -> look at it
    return 0                                                           # saturated giant, nothing compelling -> skip
  fi
  return 1
}

probe_gate() {  # probe_gate <host> -> rc 0 if probes can actually run NOW; else rc 1 + reason on stdout
  # Hypotheses are worth generating only if the harness can test them. A host under cooldown (or a
  # tripped global circuit-breaker) returns guard errors for every probe, and the lane would then
  # reason over nothing. Checking first costs one stat() and saves an entire blind Opus hunt.
  local host="$1" now exp hsafe
  now="$(date +%s)"
  if [[ -f "$PROBE_GPAUSE" ]]; then
    exp="$(cat "$PROBE_GPAUSE" 2>/dev/null || echo 0)"
    [[ "$now" -lt "${exp:-0}" ]] && { printf 'global-probe-pause, %ss left\n' "$((exp-now))"; return 1; }
  fi
  hsafe="$(printf '%s' "$host" | tr -c 'A-Za-z0-9._-' '_')"
  if [[ -f "$PROBE_RL_DIR/cooldown_$hsafe" ]]; then
    exp="$(cat "$PROBE_RL_DIR/cooldown_$hsafe" 2>/dev/null || echo 0)"
    [[ "$now" -lt "${exp:-0}" ]] && { printf 'host-cooldown, %ss left\n' "$((exp-now))"; return 1; }
  fi
  return 0
}

program_of() {  # scope_check first (offline, authoritative), ES fallback
  local p=""
  [[ -f "$SCOPE_CHECK" ]] && p="$(bash "$SCOPE_CHECK" "$1" 2>/dev/null | jq -r '.program // empty' 2>/dev/null | sed 's/[[:space:]]*$//')"
  [[ -n "$p" ]] || p="$(es "$ES_URL/$INDEX_NAME/_search" -d "$(jq -nc --arg h "$1" '{size:1,_source:["program"],query:{term:{host:$h}}}')" 2>/dev/null | jq -r '.hits.hits[0]._source.program // empty' 2>/dev/null)"
  printf '%s\n' "${p:-unknown}"
}
host_ctx()   { # tech + notes (+ PHP framework-debug hint) for the app model
  local src base blob
  src="$(es "$ES_URL/$INDEX_NAME/_search" -d "$(jq -nc --arg h "$1" '{size:1,_source:["tech","host_notes_text","triage_payout_tier","title","webserver","headers_text","cookies_text"],query:{term:{host:$h}}}')" 2>/dev/null \
    | jq -c '.hits.hits[0]._source // {}' 2>/dev/null)"
  [[ -n "$src" ]] || src='{}'
  base="$(printf '%s' "$src" | jq -r '"tech=\(.tech // "?") tier=\(.triage_payout_tier // "?") server=\(.webserver // "?") title=\(.title // "?")\nnotes: \(.host_notes_text // "none")"' 2>/dev/null)"
  # PHP framework debug-panel hint: Laravel/Symfony leak high-value UNAUTH debug surfaces (the data IS
  # the finding; Ignition can be RCE if APP_DEBUG=true). Surface it so the model proposes safe GET reads.
  blob="$(printf '%s' "$src" | jq -r '[.tech,.webserver,.title,.headers_text,.cookies_text]|map(.//"")|join(" ")' 2>/dev/null | tr 'A-Z' 'a-z')"
  if printf '%s' "$blob" | grep -qE 'laravel|symfony|codeigniter|php|x-debug-token|laravel_session|xsrf-token|ci_session'; then
    base="${base}
FRAMEWORK-DEBUG HINT: PHP/Laravel/Symfony signals present — add UNAUTH-SAFE GET hypotheses for debug/info-disclosure surfaces if plausibly present: Laravel /_ignition/health-check, /telescope, /horizon, /_clockwork, /log-viewer; Symfony /_profiler/, /_wdt/, /_profiler/phpinfo. CONFIRM = the panel/stack-trace/env/route-list actually renders unauth (a 200 SPA-shell, redirect, or 404 = FP). safe_to_probe=true GET reads."
  fi
  printf '%s\n' "$base"
}

# RANKED QUEUE (2026-08-22). This used to be `jq .host endpoints.jsonl | head -2000` and take
# the FIRST unhunted host — i.e. targets were chosen by their position in a mining log. Two
# costs, both measured: (1) 3,885 hosts have endpoints but only the first 2,000 in file order
# were ever reachable, so 1,885 could never be selected no matter how valuable; (2) within the
# window, a freshly-issued elite-tier host and a stale low-tier one were equally likely to be
# picked, because nothing ranked them. The hunt's edge is WHICH host it spends Opus on.
#
# Now: score every endpoint-bearing host from ES — freshness first (be first to new surface =
# the lowest dup-risk material there is), then KEV, payout tier and triage score — and hunt in
# that order. Same gates as before (scope+pays, dup-sea, worked-dead, probe availability).
rank_targets() {  # -> ranked host list on stdout, best first
  [[ -s "$ENDPOINTS" ]] || { warn "no endpoints feedstock ($ENDPOINTS)"; return 1; }
  local tmp_hosts q
  tmp_hosts="$(mktemp)"
  # NB: the host list is piped into jq via stdin, never passed as --argjson. 5,000 hostnames on
  # the command line exceeds ARG_MAX ("jq: Argument list too long"), which silently produced an
  # empty query and an unranked, unfiltered list — including the internal *.corp.* hosts the
  # hard line excludes. Building the query from stdin keeps it bounded regardless of pool size.
  jq -r '.host // empty' "$ENDPOINTS" 2>/dev/null | awk 'NF && !s[$0]++' | head -5000 > "$tmp_hosts"
  [[ -s "$tmp_hosts" ]] || { rm -f "$tmp_hosts"; return 1; }
  q="$(jq -Rsc 'split("\n") | map(select(length > 0)) as $hosts | {
        size:5000,
        _source:["host","triage_true_fresh","triage_kev_match","triage_score",
                 "triage_payout_tier","triage_external_first_seen"],
        query:{bool:{
          filter:[{terms:{host:$hosts}},{term:{triage_in_scope:true}},{term:{triage_pays:true}}],
          must_not:[{term:{triage_out_of_scope:true}},
                    {range:{ignore_expires_at:{gt:"now"}}}]}}}' < "$tmp_hosts")"
  rm -f "$tmp_hosts"
  [[ -n "$q" ]] || return 1
  # ...and the query goes to curl on STDIN (-d @-) for the same reason: a 3,885-host terms
  # query is ~137KB, well past ARG_MAX, so `-d "$q"` fails with "Argument list too long".
  # API-SURFACE DENSITY is the term that decides whether a hunt is worth Opus at all. Program
  # payout tier is a property of the PROGRAM, not the host, so tier alone floated
  # investors.dropbox.com and blog.dropbox.com to the top of the queue — elite-tier marketing
  # pages with nothing to reason about. The count of endpoints jsintel mined from a host
  # separates an application with an API from a brochure, costs nothing (it is already on disk),
  # and is capped so one enormous SPA cannot crowd out everything else.
  # CLONE COLLAPSE. Ranking by density alone filled the queue with www.vwfs.pt / .mx / .kr /
  # .it / .ie — one product deployed per locale, i.e. the product-class fan-out that the
  # doctrine calls a near-certain duplicate. Hosts whose MINED ENDPOINT SET is identical are
  # the same application; hunting the second one cannot produce a non-duplicate finding, it
  # just spends Opus. Group by the endpoint-set fingerprint and keep the best-ranked member.
  local ep_counts; ep_counts="$(mktemp)"
  python3 - "$ENDPOINTS" > "$ep_counts" <<'PY'
import sys, json, hashlib, re, zlib
from urllib.parse import urlsplit

# TWO corrections, both measured on the live feedstock:
#
# 1. FIRST-PARTY ONLY for density. jsluice mines every URL in the bundle, so `www.vwfs.pt`
#    scored 150 "endpoints" — of which a third were youtube.com/vimeo.com/adform embeds. That
#    inflated brochure sites into top-ranked hunt targets. Only relative paths and URLs pointing
#    back at the host itself are this application's attack surface.
#
# 2. NEAR-DUPLICATE, not exact. Locale clones are not byte-identical: vwfs.pt and vwfs.mx share
#    144 of 150 endpoints and differ by 6 (`/audi-ew_it/`, a tracker, a schema.org link). Exact
#    set hashing therefore left all 8 locales in the queue. MinHash + LSH banding groups sets by
#    SIMILARITY, so one product deployed per country collapses to a single representative — the
#    fan-out dup the doctrine warns about, caught before Opus is spent rather than after.
LOC = re.compile(r"^(?:[a-z]{2}|[a-z]{2}[-_][a-z]{2})$", re.I)
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
HEX = re.compile(r"^[0-9a-f]{16,}$", re.I)
BANDS, ROWS = 8, 4          # 32 minhashes as 8 bands of 4 — any shared band => same product


def norm(ep: str) -> str:
    ep = ep.split("?", 1)[0].split("#", 1)[0].lower()
    parts = []
    for seg in ep.split("/"):
        if not seg:
            parts.append(seg)
        elif LOC.match(seg):
            parts.append("{loc}")
        elif UUID.match(seg) or HEX.match(seg):
            parts.append("{id}")
        elif seg.isdigit():
            parts.append("{n}")
        else:
            parts.append(re.sub(r"\d+", "{n}", seg))
    return "/".join(parts)


def first_party(host: str, ep: str) -> str | None:
    if ep.startswith("/"):
        return ep
    if "://" in ep:
        try:
            netloc = urlsplit(ep).netloc.lower().split("@")[-1].split(":")[0]
        except Exception:
            return None
        if netloc == host or netloc.endswith("." + host) or host.endswith("." + netloc):
            return urlsplit(ep).path or "/"
    return None


per: dict[str, set] = {}
with open(sys.argv[1], encoding="utf-8", errors="replace") as fh:
    for line in fh:
        try:
            o = json.loads(line)
        except Exception:
            continue
        h, e = (o.get("host") or "").strip().lower(), (o.get("endpoint") or "").strip()
        if not h or not e:
            continue
        p = first_party(h, e)
        if p:
            per.setdefault(h, set()).add(norm(p))

# MinHash sketch, then LSH banding into product groups
sketches = {}
for h, eps in per.items():
    if not eps:
        continue
    hashes = sorted(zlib.crc32(e.encode()) & 0xFFFFFFFF for e in eps)[:32]
    sketches[h] = (hashes + [0] * 32)[:32]

band_map: dict[tuple, str] = {}
group: dict[str, str] = {}
for h, sk in sketches.items():
    gid = None
    keys = []
    for b in range(BANDS):
        key = (b,) + tuple(sk[b * ROWS:(b + 1) * ROWS])
        keys.append(key)
        if key in band_map and gid is None:
            gid = band_map[key]
    if gid is None:
        gid = hashlib.sha1(h.encode()).hexdigest()[:16]
    for key in keys:
        band_map.setdefault(key, gid)
    group[h] = gid

for h, eps in per.items():
    print(f"{h}\t{len(eps)}\t{group.get(h, 'u_' + h)}")
PY
  printf '%s' "$q" | es "$ES_URL/$INDEX_NAME/_search" -d @- 2>/dev/null | jq -r '
    def tier(t): if t=="elite" then 40 elif t=="high" then 25 elif t=="mid" then 12 else 0 end;
    .hits.hits[]._source
    | [ .host,
        ( (if .triage_true_fresh then 60 else 0 end)
        + (if .triage_kev_match  then 30 else 0 end)
        + tier(.triage_payout_tier // "")
        + ((.triage_score // 0) / 4) ) ]
    | @tsv' 2>/dev/null \
  | awk -F'\t' -v C="$ep_counts" '
      BEGIN { while ((getline line < C) > 0) { split(line, a, "\t"); cnt[a[1]] = a[2]; sig[a[1]] = a[3] } }
      { n = cnt[$1] + 0;
        d = (n > 200 ? 200 : n) / 4;          # capped density bonus, max +50
        # Brochure penalty: an elite-tier program floats its own newsroom to the top of the
        # queue on tier alone. A blog/IR/careers host is not where an unauth finding lives, and
        # an Opus hunt on one is the cost of a hunt on something real.
        b = ($1 ~ /^(blog|investors|press|news|newsroom|careers|jobs|about|media|ir)\./) ? 35 : 0;
        printf "%.2f\t%s\t%s\n", $2 + d - b, $1, (sig[$1] == "" ? "u" NR : sig[$1]) }' \
  | sort -rn \
  | awk -F'\t' '!clone[$3]++' \
  | cut -f2
  rm -f "$ep_counts"
}

# Internal/corp/tenant surface: never worth an Opus hunt and, for tenant consoles, never ours
# to touch. Same hard line freshchain enforces — kept here too so a ranked queue built straight
# from ES cannot walk into it.
hard_skip() {  # hard_skip <host> -> rc 0 if the host must not be hunted at all
  local h="$1"
  [[ "$h" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\. ]] && return 0
  [[ "$h" =~ (^|\.)corp\.|(^|\.)internal\.|\.intranet\.|(^|\.)internal\.api\. ]] && return 0
  [[ "$h" =~ \.unifi-hosting\.ui\.com$ ]] && return 0
  return 1
}

pick_targets() {  # pick_targets <n> -> up to n huntable hosts, best-ranked first
  local want="${1:-1}" h n=0
  local killed_file; killed_file="$(mktemp)"
  # worked-and-killed hosts (host_notes verdict=dead per tools/note_verdict.py) — never re-serve
  # them (fixes the DIG card re-carrying killed hosts like charts.etoro; open/armed hosts survive).
  python3 "$SCRIPT_DIR/../tools/note_verdict.py" killed-hosts "${NOTES_FILE:-$STATE_DIR/host_notes.jsonl}" 2>/dev/null > "$killed_file" || true
  while read -r h; do
    [[ -z "$h" ]] && continue
    [[ "$n" -ge "$want" ]] && break
    grep -qxF "$h" "$SEEN" 2>/dev/null && continue
    hard_skip "$h" && { printf '%s\n' "$h" >> "$SEEN"; continue; }   # internal/tenant: never hunt
    grep -qxF "$h" "$killed_file" 2>/dev/null && { printf '%s\n' "$h" >> "$SEEN"; continue; }  # skip worked-dead
    in_scope_pays "$h" || continue
    dup_sea "$h" && continue                                   # skip the mainstream dup sea (no SEEN mark — fresh/worth can flip)
    probe_gate "$h" >/dev/null || continue                     # cooled/paused: not huntable NOW (no SEEN mark — retried once it lapses)
    printf '%s\n' "$h"; n=$((n+1))
  done < <(rank_targets)
  rm -f "$killed_file"
  [[ "$n" -ge 1 ]]
}

# ============================== the hunt =====================================================
hunt_host() {
  local host="$1" program endpoints ctx hyp_in hyp_out napps brief stamp
  program="$(program_of "$host")"; [[ -n "$program" ]] || program="unknown"
  stamp="$(date -u +%Y-%m-%d)"; brief="$BRIEF_DIR/hunter_${stamp}.md"
  log "🎯 hunting $host (program=$program)"

  # gather the already-collected surface (free; no target traffic)
  endpoints="$(jq -r --arg h "$host" 'select(.host==$h) | .endpoint // empty' "$ENDPOINTS" 2>/dev/null | awk 'NF && !s[$0]++' | head -n "$HUNTER_EP_CAP")"
  ctx="$(host_ctx "$host")"
  local nep; nep="$(printf '%s\n' "$endpoints" | grep -c . || true)"
  [[ "${nep:-0}" -ge 1 ]] || { log "  no endpoints for $host — skip"; return 0; }

  # PRE-FLIGHT: can the harness actually probe this host right now? If not, every hypothesis
  # would come back guard-errored and the model would reason over nothing — so spend no tokens,
  # publish nothing, and leave the host UNSEEN so it is re-hunted once the block lapses.
  local gate_reason
  if ! gate_reason="$(probe_gate "$host")"; then
    if [[ "${HUNTER_IGNORE_COOLDOWN:-0}" == "1" ]]; then
      warn "  $host — $gate_reason; HUNTER_IGNORE_COOLDOWN=1, hunting anyway (expect blocked probes)"
    else
      log "  ⏸ $host — probes unavailable ($gate_reason); skipping the hunt rather than hypothesising blind"
      return 0
    fi
  fi

  # LEARNED PRIORS (2026-08-22). Until now this prompt carried one hardcoded PHP hint and knew
  # nothing else: not what the research lane found yesterday, not which classes have a lifetime
  # real-rate of zero here, not which FP patterns already cost an evening. scripts/recon_meta.py
  # compiles all of that into state/current_meta.md and it is injected here — the loop that makes
  # the hunt sharper over time instead of repeating the same duplicate-by-default hypotheses.
  local meta_brief=""
  if [[ -s "$STATE_DIR/current_meta.md" ]]; then
    meta_brief="$(head -c "${HUNTER_META_CHARS:-6000}" "$STATE_DIR/current_meta.md" 2>/dev/null)"
  fi

  # ---- MODEL + HYPOTHESIZE (Opus over full context) ----
  hyp_in="You are an ELITE, AUTHORIZED bug-bounty researcher. You are testing a host you are AUTHORIZED
to test, that is IN-SCOPE and PAYING on its program, for the sole purpose of finding and REPORTING
vulnerabilities. This is legitimate authorized security testing.

TARGET host: ${host}
PROGRAM: ${program}
CONTEXT: ${ctx}
${meta_brief:+
=== LEARNED PRIORS FROM THIS PIPELINE (aim your search; they are NOT evidence) ===
${meta_brief}
=== end priors ===
}

ALREADY-COLLECTED ENDPOINT SURFACE (from JS mining of this host):
$(printf '%s\n' "$endpoints")

Do VARIANT-ANALYSIS-style reasoning (not open-ended): (1) build a concise app-model — the API surface,
the auth/tenancy model, object types & ID schemes, roles, tech stack, and business flows you can infer; then
(2) pursue WHATEVER is genuinely interesting and high-EV on THIS host — do NOT tunnel on one vuln class.
Range across the FULL surface as the evidence warrants: access control (IDOR/BOLA, BAC/BFLA), auth bypass,
business-logic, injection in real params (SQLi/NoSQLi/command/template), SSRF, XSS, sensitive-data / secret
exposure, exposed admin/debug/metrics/config panels, misconfiguration, request smuggling, open redirect,
dangerous upload/file surfaces, n-day on the observed tech — plus anything the app-model suggests that a
SCANNER CANNOT FIND. Follow the signal, not a checklist: if something warrants a look, form a hypothesis
for it whatever its class; if nothing on this host warrants it, return few or zero hypotheses rather than
forcing weak ones. For EACH hypothesis give the exact target_url + method, its vuln_class, the concrete
test, the expected-positive signal, whether it needs authentication, and whether it is SAFE to probe
UNAUTHENTICATED with GET/HEAD/OPTIONS only (safe_to_probe=true ONLY for non-destructive unauth reads;
authed / active-exploit / 2-account classes -> safe_to_probe=false, they become an operator plan).
DUP-AWARENESS: prefer unique per-app surface; mark product-class/common endpoints dup_risk=high and do
NOT spend hypotheses on saturated commodity surface. Be precise — 'looks interesting' is useless.
Rank by (real exploitability x payout x uniqueness). Return the app_model + up to 10 hypotheses."
  hyp_out="$(claude_json "$HUNTER_MODEL" "$HYP_SCHEMA" "$hyp_in")"
  [[ -n "$hyp_out" ]] || { warn "  hypothesize empty — retry once in 20s (rate-limit?)"; sleep 20; hyp_out="$(claude_json "$HUNTER_MODEL" "$HYP_SCHEMA" "$hyp_in")"; }
  [[ -n "$hyp_out" ]] || { warn "  hypothesize returned nothing for $host"; printf '%s\n' "$host" >> "$SEEN"; return 0; }
  napps="$(printf '%s' "$hyp_out" | jq '.hypotheses | length' 2>/dev/null || echo 0)"
  log "  app-modelled; $napps hypotheses"
  [[ -n "${HUNTER_DEBUG:-}" ]] && printf '%s\n' "$hyp_out" > "$STATE_DIR/hunter_dbg_hyp.json"

  # ---- TEST: harness runs unauth-safe hypotheses through safe_probe (Claude never executes) ----
  local ledger; ledger="$(mktemp)"; local tested="[]" bodies="{}"
  local n=0 nprobed=0 nblocked=0
  while IFS= read -r hyp; do
    [[ -z "$hyp" ]] && continue
    [[ "$n" -ge "$HUNTER_MAX_HYP" ]] && break
    local id vc url method auth safe
    id="$(jq -r '.id' <<<"$hyp")"; vc="$(jq -r '.vuln_class' <<<"$hyp")"
    url="$(jq -r '.target_url' <<<"$hyp")"; method="$(jq -r '.method' <<<"$hyp")"
    auth="$(jq -r '.auth_required' <<<"$hyp")"; safe="$(jq -r '.safe_to_probe' <<<"$hyp")"
    local probe='{"skipped":"authed-or-unsafe — operator/human required, not autonomously probed"}'
    # evidence_state is computed by the HARNESS, never claimed by the model: it is the difference
    # between a finding and a guess, so it must not be something a prompt can talk its way out of.
    local estate="not-probed" ereason="authed/unsafe by design — an operator plan, not an autonomous finding"
    if [[ "$auth" == "false" && "$safe" == "true" && "$method" =~ ^(GET|HEAD|OPTIONS)$ ]]; then
      local purl; purl="$(printf '%s' "$url" | grep -oE 'https?://[^ ,"]+' | head -1)"   # Opus sometimes lists several paths; probe the first valid single URL
      probe="$(SAFE_PROBE_LEDGER="$ledger" SAFE_PROBE_BUDGET="$HUNTER_PROBE_BUDGET" bash "$SAFE_PROBE" "${purl:-$url}" "$method" 2>/dev/null)"
      [[ -n "$probe" ]] || probe='{"ok":false,"error":"probe-empty"}'
      if [[ "$(jq -r '.ok // false' <<<"$probe" 2>/dev/null)" == "true" && "$(jq -r '.status // "null"' <<<"$probe" 2>/dev/null)" != "null" ]]; then
        estate="probed"; ereason="HTTP $(jq -r '.status' <<<"$probe" 2>/dev/null)"; nprobed=$((nprobed+1))
      else
        # a guard denial, a cooldown, a rate-limit, a denylisted burn-trap, a DNS/fetch failure:
        # the request never produced a response, so anything concluded from it is speculation
        estate="blocked"; ereason="$(jq -r '.error // "probe-failed"' <<<"$probe" 2>/dev/null)"; nblocked=$((nblocked+1))
      fi
      # keep the FULL body for the impact gate; the model only needs a bounded slice
      bodies="$(jq -c --arg id "$id" --arg b "$(jq -r '.body_snippet // ""' <<<"$probe" 2>/dev/null)" '. + {($id):$b}' <<<"$bodies" 2>/dev/null || printf '%s' "$bodies")"
      probe="$(jq -c --argjson cap "$HUNTER_BODY_CAP" 'if .body_snippet then .body_snippet |= .[0:$cap] else . end' <<<"$probe" 2>/dev/null || printf '%s' "$probe")"
      n=$((n+1))
    fi
    tested="$(jq -c --argjson h "$hyp" --argjson p "$probe" --arg es "$estate" --arg er "$ereason" '. + [{hypothesis:$h, evidence_state:$es, evidence_note:$er, probe:$p}]' <<<"$tested" 2>/dev/null || printf '%s' "$tested")"
  done < <(printf '%s' "$hyp_out" | jq -c '.hypotheses[]' 2>/dev/null)
  rm -f "$ledger"
  log "  probed $n unauth hypothesis(es) — $nprobed with a real response, $nblocked blocked"

  [[ -n "${HUNTER_DEBUG:-}" ]] && printf '%s\n' "$tested" > "$STATE_DIR/hunter_dbg_tested.json"

  # WITHHOLD an evidence-free hypothesis set. If probes were attempted and NONE came back, the
  # whole set is speculation dressed as a worklist — publishing it is exactly what produced the
  # 6-hypothesis heureka.sbb.ch card. Leave the host UNSEEN so it is re-hunted with evidence.
  # (The debug dump above still runs, so a withheld host is diagnosable.)
  if [[ "$nprobed" -eq 0 && "$nblocked" -gt 0 ]]; then
    warn "  $host — all $nblocked probe(s) blocked, zero responses captured; WITHHOLDING the hypothesis set and leaving the host for a retry"
    return 0
  fi

  # ---- ADJUDICATE: Opus judges the REAL responses (execution-grounded) ----
  local adj_in adj_out
  adj_in="You are the strict adjudicator for an AUTHORIZED bug-bounty hunt on in-scope host ${host}.
Below are bug hypotheses and the ACTUAL unauthenticated probe responses the harness collected
(GET/HEAD/OPTIONS only). For EACH hypothesis judge the verdict from the EVIDENCE, not theory:
- confirmed: the response PROVES an exploitable/exposed primitive. BE STRICT — reflection != XSS,
  a 200 != a leak, an SPA shell != an unauth data exposure; the body must actually show sensitive or
  cross-object data / a working primitive. Overclaiming is FORBIDDEN (it gets reports closed N/A).
- needs-human: real but requires authentication / 2 OWNED accounts (IDOR/BAC) / an active PoC — give a
  precise operator_plan (e.g. the exact 2-account swap with owned ids only). For IDOR/BOLA the plan MUST
  say the confirm is RESPONSE-BODY equality across sessions, not HTTP 200 alone: request the SAME object
  as owner A and as non-owner B and compare the response BODIES — identical sensitive/PII/financial body
  returned to B = IDOR confirmed; B gets 403/404 or only B's own data = access control working (a 200 with
  an empty/generic/SPA body is NOT a leak). Owned ids only; never enumerate third-party ids.
- needs-account: requires signing up an account first.
- refuted: the evidence does not support it.

EVIDENCE STATES ARE BINDING. Each item carries an evidence_state the harness computed:
- probed      = a real HTTP response is attached. Only these may be judged 'confirmed'.
- blocked     = the probe NEVER EXECUTED (evidence_note says why: cooldown, rate-limit, denylisted
                burn-trap, DNS/fetch failure). There is NO response to reason from. You MUST NOT
                return 'confirmed' for these and MUST NOT assign a severity above 'low' — say
                plainly in the evidence field that the probe did not execute and what would settle it.
- not-probed  = authed / unsafe by design. Judge 'needs-human' or 'needs-account' with a precise
                operator_plan; the severity is the plan's potential, not an observed fact.
Inventing a response, or inferring one from the endpoint's name, is the single worst failure mode
of this lane — a plausible guess ranked [high] costs the operator an evening and gets a report
closed N/A. Absent evidence is a reason to say so, never a reason to raise confidence.
Give severity + the evidence string. Hypotheses+probes:
$(printf '%s' "$tested")"
  adj_out="$(claude_json "$HUNTER_ADJ_MODEL" "$ADJ_SCHEMA" "$adj_in")"
  [[ -n "${HUNTER_DEBUG:-}" ]] && printf '%s\n' "$adj_out" > "$STATE_DIR/hunter_dbg_adj.json"

  # ---- MINT / PLAN / LEARN ----
  local minted=0 leads=0 withheld=0
  if [[ -n "$adj_out" ]]; then
    while IFS= read -r v; do
      [[ -z "$v" ]] && continue
      local id verdict vc sev ev plan url
      id="$(jq -r '.id' <<<"$v")"; verdict="$(jq -r '.verdict' <<<"$v")"
      vc="$(jq -r '.vuln_class // "unknown"' <<<"$v")"; sev="$(jq -r '.severity // "info"' <<<"$v")"
      ev="$(jq -r '.evidence // ""' <<<"$v")"; plan="$(jq -r '.operator_plan // ""' <<<"$v")"
      url="$(printf '%s' "$tested" | jq -r --arg id "$id" '.[] | select(.hypothesis.id==$id) | .hypothesis.target_url' 2>/dev/null | head -1)"
      [[ -n "$url" ]] || url="https://$host"
      case "$verdict" in
        confirmed)
          # IMPACT GATE — the model saying "confirmed" is an opinion; the probe RESPONSE is
          # evidence. Re-read the real body this hypothesis produced and ask engine/impact.py
          # what was actually recovered. No recovered credential and no real personal data
          # => score 0 => NOT a finding, whatever the adjudicator claimed.
          #
          # This is why the lane had 37 findings and 0 real verdicts: it minted its own
          # self-assessment. A "request-echo information disclosure, severity low" is an
          # endpoint responding, not something you got. (Added 2026-08-17.)
          local score conf evj body iverd imint iscore iimpact ikinds estate
          # HARNESS GATE, ahead of the impact gate: "confirmed" only means something if a response
          # actually came back. A confirmed verdict on a blocked/unprobed hypothesis is the model
          # narrating, not evidence — record it as an FP pattern, never mint it, never rank it.
          estate="$(printf '%s' "$tested" | jq -r --arg id "$id" \
                    '.[] | select(.hypothesis.id==$id) | .evidence_state // "unknown"' 2>/dev/null | head -1)"
          if [[ "$estate" != "probed" ]]; then
            warn "  ✗ adjudicator said CONFIRMED $vc but no probe response was ever captured \
(evidence_state=$estate) — refusing to mint or rank it"
            python3 "$STATE_PY" kb-record "$host" "$program" "" "ai-hunter" "$vc" "fp" "0.95" "no_evidence" \
              "adjudicator confirmed a hypothesis whose probe never executed ($estate)" >/dev/null 2>&1 || true
            continue
          fi
          # the impact gate reads the FULL captured body. safe_probe_worker returns it as
          # `body_snippet` (never `.body` — reading that was why this gate saw an empty string on
          # every finding and could not mint at all); `bodies` holds it untrimmed, while $tested
          # carries only the bounded slice that was shown to the model.
          body="$(printf '%s' "$bodies" | jq -r --arg id "$id" \
                    '.[$id] // ""' 2>/dev/null | head -c 400000)"
          iverd="$(printf '%s' "$body" | python3 "$REPO_DIR/engine/impact.py" verdict "ai-hunter:$url" 2>/dev/null)"
          imint="$(jq -r '.mint // false' <<<"${iverd:-{\}}" 2>/dev/null)"
          iscore="$(jq -r '.score // 0'  <<<"${iverd:-{\}}" 2>/dev/null)"
          iimpact="$(jq -r '.impact // ""' <<<"${iverd:-{\}}" 2>/dev/null)"
          ikinds="$(jq -r '(.secret_kinds // []) | join(",")' <<<"${iverd:-{\}}" 2>/dev/null)"
          if [[ "$imint" != "true" ]]; then
            leads=$((leads+1))
            log "  ✗ adjudicator said CONFIRMED $vc but the probe body demonstrates NO impact \
(no credential recovered, no personal data) — NOT minted; recorded as a lead"
            { [[ -s "$brief" ]] || printf '# Hunter worklist — %s\n\n' "$stamp" > "$brief"
              printf -- '- **[lead] %s** `%s` — %s\n  - model said confirmed; impact gate found nothing recoverable in the response\n  - %s\n' \
                "$vc" "$url" "$host" "$ev" >> "$brief"; }
            python3 "$STATE_PY" kb-record "$host" "$program" "" "ai-hunter" "$vc" "fp" "0.9" "impact_gate" \
              "adjudicator confirmed but no impact recoverable from the probe body" >/dev/null 2>&1 || true
            continue
          fi
          # Severity comes from what was RECOVERED, not from what the model felt.
          score="$iscore"
          conf="$(jq -r '.confidence // 0.9' <<<"$iverd")"
          evj="$(jq -nc --arg ev "$ev" --arg src "ai_hunter" --arg vc "$vc" --arg sev "$sev" \
                       --arg imp "$iimpact" --arg kinds "$ikinds" --argjson iv "${iverd:-null}" \
                 '{probe:"ai-hunter-unauth",source:$src,vuln_class:$vc,severity:$sev,
                   evidence:$ev,impact:$imp,recovered:$kinds,impact_gate:$iv}')"
          if V3_DB="$V3_DB" python3 "$STATE_PY" record-confirmed "$host" "$url" "$program" "ai-hunter" "$vc" "$score" "$conf" "$evj" >/dev/null 2>&1; then
            minted=$((minted+1)); log "  🔥 CONFIRMED $vc — $iimpact — $url — minted → verify gate → #review"
          fi
          python3 "$STATE_PY" kb-record "$host" "$program" "$(printf '%s' "$ctx"|head -1)" "ai-hunter" "$vc" "real" "${conf:-0.8}" "ai_hunter" "$ev" >/dev/null 2>&1 || true ;;
        needs-human|needs-account)
          leads=$((leads+1))
          local defplan="2-owned-account test; owned ids only; confirm-then-stop" bnote=""
          case "${vc,,}" in
            *idor*|*bola*|*bac*|*bfla*)
              defplan="2 OWNED accounts A/B — request the SAME object as owner A then as non-owner B and COMPARE RESPONSE BODIES: identical sensitive/PII/financial body returned to B = IDOR confirmed; 403/404 or only-B's-own-data = access control working (a 200 with empty/generic/SPA body is NOT a leak). Owned ids only; never enumerate third-party ids; confirm-then-stop." ;;
          esac
          # LABEL BY EVIDENCE. A lead built on a real response and a lead built on nothing must
          # not read the same on the card — the [high] on an unverified guess is what sent the
          # operator after 5 false hypotheses on 2026-08-20. The harness's evidence_state wins.
          local bstate btag
          bstate="$(printf '%s' "$tested" | jq -r --arg id "$id" '.[] | select(.hypothesis.id==$id) | .evidence_state // "unknown"' 2>/dev/null | head -1)"
          bnote="$(printf '%s' "$tested" | jq -r --arg id "$id" '.[] | select(.hypothesis.id==$id) | .evidence_note // ""' 2>/dev/null | head -1)"
          # WITHHOLD PER-HYPOTHESIS, not just per-host (2026-08-22). Labelling a blocked lead
          # was not enough: on the 2026-08-22 card 19 of 42 entries read "[UNVERIFIED — no
          # response captured]" because the per-HOST withhold only fires when EVERY probe on a
          # host is blocked — one landing probe let the other five onto the operator's card.
          # An item whose probe never executed is a retry for the harness, not work for the
          # human. It goes to the retry log, and the host is left unseen so it is hunted again
          # once the block lapses. `not-probed` (authed by design) still belongs on the card:
          # that one is genuinely the operator's 2-account job and it carries a plan.
          if [[ "$bstate" != "probed" && "$bstate" != "not-probed" ]]; then
            leads=$((leads-1)); withheld=$((withheld+1))
            printf '%s\n' "$(jq -nc --arg h "$host" --arg vc "$vc" --arg url "$url" \
                              --arg st "$bstate" --arg note "$bnote" --arg at "$(date -u +%FT%TZ)" \
                              '{host:$h,vuln_class:$vc,url:$url,evidence_state:$st,why:$note,at:$at}')" \
              >> "$STATE_DIR/hunter_retry.jsonl" 2>/dev/null || true
            warn "  ⤺ withheld unverifiable lead ($vc, $bstate: $bnote) — queued for re-hunt, not carded"
            continue
          fi
          case "$bstate" in
            probed)     btag="[$sev]" ;;
            not-probed) btag="[$sev · authed — untested by design]" ;;
          esac
          { [[ -s "$brief" ]] || printf '# Hunter worklist — %s\n\n' "$stamp" > "$brief"
            printf -- '- **%s %s** `%s` — %s\n  - %s\n' "$btag" "$vc" "$url" "$host" "$ev" >> "$brief"
            [[ "$bstate" == "probed" ]] || printf -- '  - ⚠ authed/unsafe by design — never probed; this is a plan to TEST, not a finding\n' >> "$brief"
            printf -- '  - OPERATOR: %s\n' "${plan:-$defplan}" >> "$brief"; } ;;
      esac
    done < <(printf '%s' "$adj_out" | jq -c '.verdicts[]' 2>/dev/null)
  else
    warn "  adjudication returned nothing for $host"
  fi

  # A host that produced withheld (never-executed) hypotheses is NOT finished: leave it out of
  # SEEN so the ranked queue serves it again once the block lapses and it can be probed for real.
  # Marking it seen is precisely how an unprobed host silently became "covered".
  if [[ "${withheld:-0}" -gt 0 && "$minted" -eq 0 ]]; then
    warn "  $host — $withheld unverifiable lead(s) withheld; leaving host unseen for a re-hunt"
  else
    printf '%s\n' "$host" >> "$SEEN"; tail -n 5000 "$SEEN" > "$SEEN.tmp" 2>/dev/null && mv "$SEEN.tmp" "$SEEN" 2>/dev/null || true
  fi
  log "  done $host — $minted confirmed, $leads operator-lead(s)$([ "$leads" -gt 0 ] && echo " → $brief")"
}

case "${1:-cycle}" in
  cycle|"")
    # Hunt N hosts per cycle instead of exactly one, and REPLENISH instead of giving up.
    # Before: one host per invocation, and if the picker found nothing the lane logged
    # "no fresh target" and exited — so once the queue was walked, the finding engine simply
    # stopped, silently, until new endpoints happened to be mined. An empty batch is the
    # trigger to look again, not a reason to stop (operator, 2026-08-22).
    HUNTER_HOSTS_PER_CYCLE="${HUNTER_HOSTS_PER_CYCLE:-2}"
    mapfile -t _targets < <(pick_targets "$HUNTER_HOSTS_PER_CYCLE")
    if [[ "${#_targets[@]}" -eq 0 ]]; then
      # Everything ranked has been hunted. Recycle the OLDEST half of the hunted window so the
      # best-ranked hosts become eligible again — their endpoint surface has been re-mined since
      # (jsintel runs hourly), so a re-hunt reasons over new material rather than repeating.
      # Deliberately NOT "reach further down the ranking": re-hunting a high-value host with
      # fresh data beats hunting a low-value one, and it cannot pull in noise.
      local_n="$(wc -l < "$SEEN" 2>/dev/null | tr -d ' ')"; local_n="${local_n:-0}"
      if [[ "$local_n" -gt 40 ]]; then
        log "ranked queue exhausted ($local_n hunted) — recycling the oldest half and retrying"
        tail -n "$(( local_n / 2 ))" "$SEEN" > "$SEEN.tmp" 2>/dev/null && mv "$SEEN.tmp" "$SEEN"
        mapfile -t _targets < <(pick_targets "$HUNTER_HOSTS_PER_CYCLE")
      fi
    fi
    if [[ "${#_targets[@]}" -eq 0 ]]; then
      log "no huntable in-scope+pays target right now (all cooled, benched or out of scope)"
      exit 0
    fi
    log "ranked queue -> hunting ${#_targets[@]}: ${_targets[*]}"
    for h in "${_targets[@]}"; do hunt_host "$h"; done ;;
  host)
    [[ -n "${2:-}" ]] || { echo "usage: recon_ai_hunter.sh host <host>"; exit 1; }
    in_scope_pays "$2" || { warn "$2 is NOT in-scope+paying (authoritative) — refusing"; exit 1; }
    hunt_host "$2" ;;
  status)
    echo "hunter: model=$HUNTER_MODEL adj=$HUNTER_ADJ_MODEL  hunted(window)=$(wc -l < "$SEEN" 2>/dev/null | tr -d ' ')  endpoints=$( [ -f "$ENDPOINTS" ] && wc -l < "$ENDPOINTS" | tr -d ' ' || echo 0)"
    echo "killswitch: $( [ -f "$KILL_FILE" ] && echo ON || echo off )" ;;
  *) echo "usage: recon_ai_hunter.sh {cycle|host <host>|status}" >&2; exit 1 ;;
esac

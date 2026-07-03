#!/usr/bin/env bash
# =============================================================================
# recon_baddns.sh — takeover lane augmenter (research tooling 2026-07-01, ADOPT).
#
# THE EDGE over our existing takeover heuristics + nuclei: BadDNS's `references`
# module = SECOND-ORDER takeover — it fetches each host's HTML and checks the
# EXTERNAL domains it embeds (<script src>, <link>, CSP, etc.) for takeover-ability.
# The crowd only scans a target's OWN DNS records; a dangling `cdn.abandoned.io`
# JS include is near-uncontested surface. Plus NSEC-walking + auto-synced sigs.
#
# SAFE + LEAD-ONLY: emits `takeover:baddns-lead` to the shared worklist + a dated
# briefing — NEVER auto-mints a CONFIRMED takeover (that needs the multi-stage
# NXDOMAIN/unclaimed-fingerprint verify per the CONFIRMED-vs-LEAD doctrine). The
# `references` module fetches target HTML → VPN-GATED (fail-closed on vpn_down).
# Killswitch: state/kill/v2_baddns.  KB: docs/knowledge/class-* (takeover).
# =============================================================================
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="${BASE_DIR:-$HOME/recon}"; STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"; INDEX_NAME="${INDEX_NAME:-recon_alive}"
NETRC="${NETRC:-$HOME/.recon_es_netrc}"
BRIEF_DIR="${BRIEF_DIR:-$BASE_DIR/briefings}"
WORKLIST="${TAKEOVER_WORKLIST:-$BASE_DIR/idor_worklist.jsonl}"   # shared → briefing
SEEN="${BADDNS_SEEN:-$STATE_DIR/baddns_seen.txt}"
BADDNS_BIN="${BADDNS_BIN:-$(command -v baddns 2>/dev/null || echo "$HOME/.local/bin/baddns")}"
BADDNS_HOSTS="${BADDNS_HOSTS:-20}"          # hosts checked per cycle (sliding window via SEEN)
BADDNS_MODULES="${BADDNS_MODULES:-CNAME,NS,references,TXT,WILDCARD}"
BADDNS_TIMEOUT="${BADDNS_TIMEOUT:-45}"      # per-host wall-clock cap
LOG_PREFIX="[baddns]"
log(){ printf '%s %s %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$LOG_PREFIX" "$*"; }

# --- gates (fail-closed) ---
[[ -f "$STATE_DIR/kill/v2_baddns" ]] && { log "killswitch v2_baddns set — skip"; exit 0; }
[[ -f "$STATE_DIR/vpn_down" ]] && { log "vpn_down — skip (references module fetches target HTML; fail-closed)"; exit 0; }
[[ -x "$BADDNS_BIN" ]] || { log "baddns not installed ($BADDNS_BIN) — skip"; exit 0; }
command -v jq >/dev/null 2>&1 || { log "jq missing — skip"; exit 0; }
mkdir -p "$STATE_DIR" "$BRIEF_DIR" "$(dirname "$WORKLIST")"; touch "$SEEN"
exec 9>"$STATE_DIR/baddns.lock"; flock -n 9 || { log "already running"; exit 0; }
es(){ curl -fsS -m 25 --netrc-file "$NETRC" -H 'Content-Type: application/json' "$@"; }

# --- candidate hosts: in-scope + paying, not benched, not yet checked, freshest first ---
q="$(jq -nc --argjson n "$BADDNS_HOSTS" '{size:($n*4),_source:["host","triage_program"],
  query:{bool:{filter:[{term:{triage_in_scope:true}},{term:{triage_pays:true}}],
    must_not:[{term:{triage_out_of_scope:true}},{range:{ignore_expires_at:{gt:"now"}}},
              {wildcard:{host:"*.unifi-hosting.ui.com"}}]}},
  sort:[{triage_true_fresh:{order:"desc",missing:"_last"}},{triage_score:{order:"desc",missing:"_last"}}]}')"
resp="$(es "$ES_URL/$INDEX_NAME/_search" -d "$q" 2>/dev/null)"
[[ -n "$resp" ]] || { log "ES unreachable — skip"; exit 0; }

today="$(date '+%Y-%m-%d')"; md="$BRIEF_DIR/baddns_leads_$today.md"
checked=0; leads=0
while IFS=$'\t' read -r host prog; do
  [[ -z "$host" ]] && continue
  [[ "$checked" -ge "$BADDNS_HOSTS" ]] && break
  grep -qxF "$host" "$SEEN" 2>/dev/null && continue
  printf '%s\n' "$host" >> "$SEEN"; checked=$((checked+1))

  out="$(timeout "$BADDNS_TIMEOUT" "$BADDNS_BIN" -s -m "$BADDNS_MODULES" "$host" 2>/dev/null)"
  [[ -n "$out" ]] || continue   # -s prints JSON only on a finding; empty = clean

  # each finding object (schema-defensive): pull target/module/confidence/severity/description
  printf '%s' "$out" | jq -c '.' 2>/dev/null | while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    tgt="$(jq -r '(.target // .subdomain // .host // "")' <<<"$f" 2>/dev/null)"; tgt="${tgt:-$host}"
    modu="$(jq -r '(.module // .Module // "?")' <<<"$f" 2>/dev/null)"
    conf="$(jq -r '(.confidence // .Confidence // "?")' <<<"$f" 2>/dev/null)"
    sev="$(jq -r '(.severity // .Severity // "?")' <<<"$f" 2>/dev/null)"
    desc="$(jq -r '((.description // .Description // .signature_name // .technique // "")|tostring)' <<<"$f" 2>/dev/null | head -c 240)"
    second="no"; [[ "$modu" == *references* || "$modu" == *reference* ]] && second="yes"
    ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    jq -nc --arg h "$host" --arg tgt "$tgt" --arg p "$prog" --arg t "$ts" --arg m "$modu" \
      --arg c "$conf" --arg s "$sev" --arg d "$desc" --arg so "$second" \
      '{host:$h,program:$p,endpoint:$tgt,vuln_type:("takeover:baddns-lead"+(if $so=="yes" then "-2ndorder" else "" end)),
        cve:"",why:("BadDNS "+$m+" takeover LEAD"+(if $so=="yes" then " (SECOND-ORDER — embedded 3rd-party domain hijackable)" else "" end)+" on "+$tgt+" (confidence="+$c+", severity="+$s+"): "+$d),
        test:"Verify unclaimed/NXDOMAIN + register-able on the named provider before reporting (multi-stage takeover confirm; LEAD only — never auto-mint).",
        impact:(if $s=="CRITICAL" or $s=="HIGH" then "high" else "medium" end),confidence:0.5,exploit_available:false,at:$t,status:"to-test"}' >> "$WORKLIST" 2>/dev/null
    {
      [[ -s "$md" ]] || printf '# 🩸 BadDNS takeover LEADs — %s\nSecond-order (embedded 3rd-party domain) + dangling CNAME/NS/TXT. LEAD only — verify unclaimed before reporting.\n\n' "$today"
      printf -- '- **%s** via `%s`%s — conf %s / sev %s · %s _(prog: %s)_\n' \
        "$tgt" "$modu" "$([[ "$second" == yes ]] && echo ' 🔗2nd-order')" "$conf" "$sev" "$desc" "${prog:-?}"
    } >> "$md"
    leads=$((leads+1))
    log "   🩸 takeover LEAD · $tgt · $modu$([[ "$second" == yes ]] && echo ' (2nd-order)') · conf $conf/$sev → worklist"
  done
done < <(printf '%s' "$resp" | jq -r '.hits.hits[]?._source | [.host,(.triage_program//"")] | @tsv' 2>/dev/null)

tail -n 8000 "$SEEN" > "$SEEN.tmp" 2>/dev/null && mv "$SEEN.tmp" "$SEEN" 2>/dev/null || true
log "done · $checked host(s) checked · $leads takeover LEAD(s)$([[ "$leads" -gt 0 ]] && echo " → $md")"

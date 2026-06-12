#!/usr/bin/env bash
# =============================================================================
# recon_scope_check.sh — Scope TSV lookup with batch support
#
# Single-host (slow, for one-off lookups):
#   ./recon_scope_check.sh <host>
#
# Batch (fast, for processing kev_targets.jsonl):
#   ./recon_scope_check.sh --batch < hosts.txt
#   jq -r .host kev_targets.jsonl | ./recon_scope_check.sh --batch
#
# Count only:
#   jq -r .host kev_targets.jsonl | ./recon_scope_check.sh --count-in-scope-paying
#
# Filter by predicate:
#   jq -r .host kev_targets.jsonl | ./recon_scope_check.sh --filter in-scope-paying
# =============================================================================

set -uo pipefail
IFS=$'\n\t'

SCOPE_DIR="${SCOPE_DIR:-$HOME/recon/scope}"
INSCOPE_TSV="$SCOPE_DIR/inscope_patterns.tsv"
OUTSCOPE_TSV="$SCOPE_DIR/outscope_patterns.tsv"
KILL_FILE="$HOME/recon/state/kill/v2_scope"

if [[ -f "$KILL_FILE" ]]; then
  echo '{"error":"scope killed"}' >&2
  exit 0
fi

[[ -s "$INSCOPE_TSV" ]] || {
  echo '{"error":"scope DB not populated"}' >&2
  exit 1
}

# =============================================================================
# Awk engine — load patterns once, match many hosts
# =============================================================================
# Output format per line: TAB-separated
#   host  in_scope  out_of_scope  pays  program  platform  pattern  out_program  out_pattern  payout_tier
# in_scope/out_of_scope/pays = "true"/"false"
# program/platform/pattern/payout_tier = "" if no match
#
# v2.2: payout_tier added (10th column). Old TSVs without 5th column → "mid" if pays=true.
# =============================================================================
batch_match() {
  # Optimized 2026-06-05: hash exact patterns + check only the host's own
  # suffixes for wildcards -> O(hosts x labels) instead of O(hosts x 40k patterns).
  # Verified byte-identical to the prior linear matcher on a 5k-host sample.
  awk -v out_tsv="$OUTSCOPE_TSV" -v in_tsv="$INSCOPE_TSV" '
    BEGIN {
      FS = "\t"
      # Load OUT patterns -> exact/wildcard hashes. Keep the LOWEST file index per key
      # so "first match in file order" (the original loop semantics) is preserved.
      oi = 0
      while ((getline line < out_tsv) > 0) {
        n = split(line, f, "\t")
        if (n < 1 || f[1] == "") continue
        oi++
        pat = f[1]
        meta = oi SUBSEP pat SUBSEP (n>=2?f[2]:"") SUBSEP (n>=3?f[3]:"")
        if (substr(pat,1,2) == "*.") {
          apex = substr(pat,3)
          if (!(apex in out_wild)) out_wild[apex] = meta
        } else {
          if (!(pat in out_exact)) out_exact[pat] = meta
        }
      }
      close(out_tsv)
      ii = 0
      while ((getline line < in_tsv) > 0) {
        n = split(line, f, "\t")
        if (n < 1 || f[1] == "") continue
        ii++
        pays = (n>=4?f[4]:"false")
        if (n>=5 && f[5]!="") tier = f[5]; else tier = (pays=="true"?"mid":"none")
        pat = f[1]
        meta = ii SUBSEP pat SUBSEP (n>=2?f[2]:"") SUBSEP (n>=3?f[3]:"") SUBSEP pays SUBSEP tier
        if (substr(pat,1,2) == "*.") {
          apex = substr(pat,3)
          if (!(apex in in_wild)) in_wild[apex] = meta
        } else {
          if (!(pat in in_exact)) in_exact[pat] = meta
        }
      }
      close(in_tsv)
      FS = "\n"
    }
    function rank(t) { return (t=="elite"?0:(t=="high"?1:(t=="mid"?2:(t=="low"?3:4)))) }
    {
      raw = $0
      gsub(/[ \t\r\n]/, "", raw)
      raw = tolower(raw)
      sub(/^https?:\/\//, "", raw)
      sub(/\/.*$/, "", raw)
      if (raw == "") next
      host = raw

      hard_excluded = 0; hard_reason = ""
      if (host ~ /\.mil$/ || host ~ /\.mil\./ ) { hard_excluded=1; hard_reason="hard-exclude:mil-tld" }
      else if (host ~ /\.smil\.mil$/ || host ~ /\.nipr\.mil$/ || host ~ /\.sipr\.mil$/) { hard_excluded=1; hard_reason="hard-exclude:classified-tld" }
      if (hard_excluded) { printf "%s\tfalse\ttrue\tfalse\t\t\t\t\t%s\tnone\n", host, hard_reason; next }

      # ---- OUT: lowest file index among matches (exact host + wildcard suffixes) ----
      out_idx = -1; out_meta = ""
      if (host in out_exact) { split(out_exact[host], m, SUBSEP); out_idx = m[1]+0; out_meta = out_exact[host] }
      c = host
      while (1) {
        if (c in out_wild) { split(out_wild[c], m, SUBSEP); if (out_idx < 0 || (m[1]+0) < out_idx) { out_idx = m[1]+0; out_meta = out_wild[c] } }
        p = index(c, "."); if (p == 0) break; c = substr(c, p+1)
      }

      # ---- IN: best by (rank asc, then file index asc) ----
      in_rank = 99; in_idx = -1; in_meta = ""
      if (host in in_exact) {
        split(in_exact[host], m, SUBSEP); r = rank(m[6])
        if (r < in_rank || (r == in_rank && (in_idx < 0 || (m[1]+0) < in_idx))) { in_rank = r; in_idx = m[1]+0; in_meta = in_exact[host] }
      }
      c = host
      while (1) {
        if (c in in_wild) {
          split(in_wild[c], m, SUBSEP); r = rank(m[6])
          if (r < in_rank || (r == in_rank && (in_idx < 0 || (m[1]+0) < in_idx))) { in_rank = r; in_idx = m[1]+0; in_meta = in_wild[c] }
        }
        p = index(c, "."); if (p == 0) break; c = substr(c, p+1)
      }

      # ---- assemble (mirror original field semantics exactly) ----
      pattern = ""; program = ""; platform = ""; best_pays = "false"; best_tier = "none"
      if (in_meta != "") { split(in_meta, m, SUBSEP); pattern = m[2]; program = m[3]; platform = m[4]; best_pays = m[5]; best_tier = m[6] }
      out_pattern = ""; out_program = ""
      if (out_meta != "") { split(out_meta, m, SUBSEP); out_pattern = m[2]; out_program = m[3] }

      if (out_meta != "") { in_scope = "false"; best_pays = "false"; best_tier = "none" }
      else { in_scope = (in_meta != "" ? "true" : "false") }
      out_of_scope = (out_meta != "" ? "true" : "false")

      printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
             host, in_scope, out_of_scope, best_pays, program, platform, pattern, out_program, out_pattern, best_tier
    }
  '
}

# =============================================================================
# JSON formatter for batch output
# =============================================================================
to_json() {
  awk -F'\t' '
    function esc(s) {
      gsub(/\\/,"\\\\",s)
      gsub(/"/,"\\\"",s)
      gsub(/\r/,"",s)
      gsub(/\t/,"\\t",s)
      return s
    }
  {
    # field order: host  in  out  pays  program  platform  pattern  out_program  out_pattern  payout_tier
    printf "{\"host\":\"%s\",\"in_scope\":%s,\"out_of_scope\":%s,\"pays\":%s",
           esc($1), $2, $3, $4
    if ($5 != "") printf ",\"program\":\"%s\"", esc($5)
    else          printf ",\"program\":null"
    if ($6 != "") printf ",\"platform\":\"%s\"", esc($6)
    else          printf ",\"platform\":null"
    if ($7 != "") printf ",\"pattern\":\"%s\"", esc($7)
    else          printf ",\"pattern\":null"
    # v2.2: payout_tier
    tier = ($10 != "" ? $10 : "none")
    printf ",\"payout_tier\":\"%s\"", tier
    # v2.1.3: hard-exclusion reason (uses out_pattern field $9 when out_program $8 is empty)
    if ($8 == "" && $9 != "" && $9 ~ /^hard-exclude:/) {
      printf ",\"hard_excluded\":true,\"reason\":\"%s\"", esc($9)
    }
    print "}"
  }'
}

# =============================================================================
# Dispatch
# =============================================================================
case "${1:-}" in
  --batch)
    if [[ -n "${2:-}" ]]; then
      cat "$2" | batch_match | to_json
    else
      batch_match | to_json
    fi
    ;;

  --count-in-scope-paying)
    batch_match | awk -F'\t' '$2=="true" && $4=="true" && $3=="false" {n++} END {print n+0}'
    ;;

  --count-in-scope)
    batch_match | awk -F'\t' '$2=="true" && $3=="false" {n++} END {print n+0}'
    ;;

  --filter)
    pred="${2:-in-scope-paying}"
    case "$pred" in
      in-scope-paying)  awk_pred='$2=="true" && $4=="true" && $3=="false"' ;;
      in-scope)         awk_pred='$2=="true" && $3=="false"' ;;
      out-of-scope)     awk_pred='$3=="true"' ;;
      *) echo "predicates: in-scope-paying | in-scope | out-of-scope" >&2; exit 2 ;;
    esac
    batch_match | awk -F'\t' "$awk_pred"' {print $1}'
    ;;

  ""|-h|--help)
    cat <<EOF
Usage:
  $0 <host>                          # JSON for single host
  $0 --batch [file]                  # JSONL output, stdin or file
  $0 --filter in-scope-paying        # emit only host names matching predicate
  $0 --filter in-scope
  $0 --filter out-of-scope
  $0 --count-in-scope-paying         # count only
  $0 --count-in-scope                # count only

Examples:
  jq -r .host ~/recon/cve/kev_targets.jsonl | $0 --batch | head -5
  jq -r .host ~/recon/cve/kev_targets.jsonl | $0 --count-in-scope-paying
  jq -r .host ~/recon/cve/kev_targets.jsonl | $0 --filter in-scope-paying
EOF
    exit 2
    ;;

  *)
    # Single host fallthrough (+ has_notes: signals "I've worked this host/root-domain before")
    _sc_out="$(echo "$1" | batch_match | to_json)"
    _sc_notes="${NOTES_FILE:-$HOME/recon/state/host_notes.jsonl}"
    _sc_hn=false
    if [[ -s "$_sc_notes" ]] && command -v jq >/dev/null 2>&1; then
      _sc_rd="$(awk -F. '{ if (NF>=2) printf "%s.%s",$(NF-1),$NF; else printf "%s",$0 }' <<<"$1")"
      jq -e --arg h "$1" --arg rd "$_sc_rd" 'select(.host==$h or .root_domain==$rd)' "$_sc_notes" >/dev/null 2>&1 && _sc_hn=true
    fi
    if command -v jq >/dev/null 2>&1 && [[ -n "$_sc_out" ]]; then
      printf '%s' "$_sc_out" | jq -c --argjson hn "$_sc_hn" '. + {has_notes:$hn}'
    else
      printf '%s\n' "$_sc_out"
    fi
    ;;
esac

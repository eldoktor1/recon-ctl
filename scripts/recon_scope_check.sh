#!/usr/bin/env bash
# =============================================================================
# recon_scope_check.sh v2.1.2
#
# Fixes from v2.1.1:
#   - Single-host check no longer forks awk twice (was reading both TSVs per call)
#   - NEW: --batch mode reads stdin/file, single awk pass = 1000x faster
#   - NEW: --count-in-scope-paying mode for stats (returns just a number)
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
#   host  in_scope  out_of_scope  pays  program  platform  pattern
# in_scope/out_of_scope/pays = "true"/"false"
# program/platform/pattern = "" if no match
#
# Sentinels:
#   IN-LOOP file 1 (outscope), file 2 (inscope), file 3 (hosts)
# =============================================================================
batch_match() {
  awk -v out_tsv="$OUTSCOPE_TSV" -v in_tsv="$INSCOPE_TSV" '
    BEGIN {
      FS = "\t"

      # Load OUT-of-scope patterns
      while ((getline line < out_tsv) > 0) {
        n = split(line, f, "\t")
        if (n >= 1 && f[1] != "") {
          out_pat[++out_n] = f[1]
          out_prog[out_n] = (n >= 2 ? f[2] : "")
          out_plat[out_n] = (n >= 3 ? f[3] : "")
        }
      }
      close(out_tsv)

      # Load IN-scope patterns
      while ((getline line < in_tsv) > 0) {
        n = split(line, f, "\t")
        if (n >= 1 && f[1] != "") {
          in_pat[++in_n] = f[1]
          in_prog[in_n] = (n >= 2 ? f[2] : "")
          in_plat[in_n] = (n >= 3 ? f[3] : "")
          in_pays[in_n] = (n >= 4 ? f[4] : "false")
        }
      }
      close(in_tsv)

      FS = "\n"  # for stdin
    }

    function host_matches(host, pat,    suf, suflen, apex) {
      if (pat == host) return 1
      if (substr(pat, 1, 2) == "*.") {
        suf = substr(pat, 2)
        suflen = length(suf)
        if (length(host) > suflen && substr(host, length(host) - suflen + 1) == suf) return 1
        apex = substr(pat, 3)
        if (host == apex) return 1
      }
      return 0
    }

    {
      raw = $0
      gsub(/[ \t\r\n]/, "", raw)
      raw = tolower(raw)
      sub(/^https?:\/\//, "", raw)
      sub(/\/.*$/, "", raw)
      if (raw == "") next
      host = raw

      # ============================================================
      # HARD EXCLUSION (v2.1.3): .mil and federal restricted TLDs
      # No automated scanning of military or restricted government infra,
      # regardless of any matching scope pattern.
      # Override behavior: in_scope=false, out_of_scope=true, reason set.
      # ============================================================
      hard_excluded = 0
      hard_reason = ""
      if (host ~ /\.mil$/ || host ~ /\.mil\./ ) {
        hard_excluded = 1; hard_reason = "hard-exclude:mil-tld"
      }
      # Other federal restricted TLDs that explicitly forbid scanning
      else if (host ~ /\.smil\.mil$/ || host ~ /\.nipr\.mil$/ || host ~ /\.sipr\.mil$/) {
        hard_excluded = 1; hard_reason = "hard-exclude:classified-tld"
      }

      if (hard_excluded) {
        printf "%s\tfalse\ttrue\tfalse\t\t\t\t\t%s\n", host, hard_reason
        next
      }

      # Out-of-scope check
      out_match = ""
      for (i = 1; i <= out_n; i++) {
        if (host_matches(host, out_pat[i])) {
          out_match = out_pat[i] "|" out_prog[i] "|" out_plat[i]
          break
        }
      }

      # In-scope check — prefer paying matches
      best_in = ""; best_pays = "false"
      for (i = 1; i <= in_n; i++) {
        if (host_matches(host, in_pat[i])) {
          if (best_in == "" || (in_pays[i] == "true" && best_pays != "true")) {
            best_in = in_pat[i] "|" in_prog[i] "|" in_plat[i]
            best_pays = in_pays[i]
            if (best_pays == "true") break  # paying match is sufficient
          }
        }
      }

      # Emit TSV: host  in_scope  out_of_scope  pays  program  platform  pattern  out_program  out_pattern
      # Out-of-scope OVERRIDES in-scope: a host matching both is effectively out-of-scope
      # (in_scope flag still flipped false in this case so downstream filters work)
      if (out_match != "") {
        in_scope = "false"
        best_pays = "false"
      } else {
        in_scope = (best_in != "" ? "true" : "false")
      }
      out_of_scope = (out_match != "" ? "true" : "false")

      pattern = ""; program = ""; platform = ""
      if (best_in != "") {
        split(best_in, parts, "|")
        pattern = parts[1]; program = parts[2]; platform = parts[3]
      }
      out_pattern = ""; out_program = ""; out_platform = ""
      if (out_match != "") {
        split(out_match, parts, "|")
        out_pattern = parts[1]; out_program = parts[2]; out_platform = parts[3]
      }

      printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
             host, in_scope, out_of_scope, best_pays, program, platform, pattern, out_program, out_pattern
    }
  '
}

# =============================================================================
# JSON formatter for batch output
# =============================================================================
to_json() {
  awk -F'\t' '{
    # field order: host  in  out  pays  program  platform  pattern  out_program  out_pattern
    printf "{\"host\":\"%s\",\"in_scope\":%s,\"out_of_scope\":%s,\"pays\":%s",
           $1, $2, $3, $4
    if ($5 != "") printf ",\"program\":\"%s\"", $5
    else          printf ",\"program\":null"
    if ($6 != "") printf ",\"platform\":\"%s\"", $6
    else          printf ",\"platform\":null"
    if ($7 != "") printf ",\"pattern\":\"%s\"", $7
    else          printf ",\"pattern\":null"
    # v2.1.3: hard-exclusion reason (uses out_pattern field $9 when out_program $8 is empty)
    if ($8 == "" && $9 != "" && $9 ~ /^hard-exclude:/) {
      printf ",\"hard_excluded\":true,\"reason\":\"%s\"", $9
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
    # Single host fallthrough
    echo "$1" | batch_match | to_json
    ;;
esac

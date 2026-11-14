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
#   1 host  2 in_scope  3 out_of_scope  4 pays  5 program  6 platform  7 pattern
#   8 out_program  9 out_pattern  10 payout_tier  11 max_severity  12 submit
# in_scope/out_of_scope/pays/submit = "true"/"false"
# program/platform/pattern/max_severity = "" if no match
#
# v2.2: payout_tier added (10th column). Old TSVs without a 5th column → "mid" if pays=true.
# v2.3 (2026-09-05): PER-ASSET pays. The TSV now carries one row per in-scope
#   ASSET with that asset's own bounty eligibility (col 4), max_severity (col 6)
#   and submission eligibility (col 7), so resolution is two-stage:
#     1. WITHIN a program the MOST SPECIFIC matching asset governs — an exact
#        host beats any wildcard, a longer wildcard apex beats a shorter one.
#        That is what stops jira.logitech.com (eligible_for_bounty:false) from
#        inheriting `*.logitech.com`, while www.logitech.com (eligible:true) and
#        *.streamlabs.com keep paying on the very same program.
#     2. ACROSS programs the best payout tier wins (a host in scope on both a
#        paying program and a VDP is still worth money), tie-broken by file order.
#   Pre-v2.3 TSVs (5 columns) still load: cols 6-7 default to "" / "true".
# v2.4 (2026-09-05): MID-LABEL GLOBS. Everything above indexes a pattern by an
#   exact hostname or by a wildcard APEX, so it only ever understood a clean
#   leading `*.`. 258 of 41,100 in-scope patterns (139 of them bounty-eligible)
#   carry a `*` somewhere else and matched nothing at all — `*vc.logitech.com`
#   alone covers 16 live logitech hosts that were every one reported pays:false.
#   Those patterns now go to a THIRD bucket that is regex-matched; the two hash
#   buckets and their O(hosts x labels) walk are untouched. See the gl_*
#   functions for the glob semantics and the candidate gate that keeps the pass
#   close to free.
# =============================================================================
batch_match() {
  # Optimized 2026-06-05: hash exact patterns + check only the host's own
  # suffixes for wildcards -> O(hosts x labels) instead of O(hosts x 40k patterns).
  # 2026-09-05: each IN bucket now holds EVERY row for that pattern (SUBSEP-
  # joined) rather than only the first. One pattern can legitimately repeat —
  # different programs, or two assets that normalize to the same hostname
  # (www.logitech.com eligible + https://www.logitech.com/blog not) — and
  # keeping only the first silently decided `pays` by file order.
  awk -v out_tsv="$OUTSCOPE_TSV" -v in_tsv="$INSCOPE_TSV" '
    function rank(t) { return (t=="elite"?0:(t=="high"?1:(t=="mid"?2:(t=="low"?3:4)))) }

    # ==== glob patterns (v2.4) ==============================================
    # Reached only by a pattern the hash index cannot hold: one carrying a * that
    # is not a clean leading "*.".
    #
    # SEMANTICS, decided against the live feed rather than from first principles:
    #   * at position 1  -> ".*"      may span dots
    #   * anywhere else  -> "[^.]*"   stays inside one label, never crosses a dot
    #
    # The leading * HAS to span dots. *vc.logitech.com is a bounty-eligible
    # logitech asset and all 16 of its live hosts are multi-label
    # (raiden.vc.logitech.com, hub.raidenapp-qa2.test.vc.logitech.com,
    # wss-dev-api.dev.vc.logitech.com) — a label-local [^.]* there recovers
    # exactly zero of them. It is also the safe place to be permissive: whatever
    # a leading .* swallows, the host still has to END with the literal rest of
    # the pattern, and that rest always carries the program own domain.
    #
    # Everywhere else the label-local reading is both the intended one and the
    # safe one. ab-api-cf.*.aws.indriverapp.com means exactly one label; and a
    # mid or trailing ".*" would run PAST a registrable boundary and mark a THIRD
    # PARTY paying — *.arubanetworks.com* compiled with ".*" swallows
    # x.arubanetworks.com.attacker.net. [^.]* cannot, because it cannot cross a
    # dot. The old behaviour under-reported paying surface, which costs money but
    # never compliance; that asymmetry is what picks [^.]* wherever there is any
    # doubt.
    function gl_compile(p,   i, ch, rx) {
      rx = "^"
      for (i = 1; i <= length(p); i++) {
        ch = substr(p, i, 1)
        if (ch == "*")      rx = rx (i == 1 ? ".*" : "[^.]*")
        else if (ch == ".") rx = rx "\\."
        else                rx = rx ch
      }
      return rx "$"
    }
    # Longest run of literal characters in the pattern — a cheap index()
    # prefilter to run before the regex for globs that have no dot-aligned tail.
    function gl_literal(p,   q, t, seg, best) {
      q = p; best = ""
      while (1) {
        t = index(q, "*")
        if (t == 0) { seg = q; q = "" } else { seg = substr(q, 1, t-1); q = substr(q, t+1) }
        if (length(seg) > length(best)) best = seg
        if (t == 0) break
      }
      return best
    }
    # The dot-aligned suffix a matching host MUST end with, when the run after
    # the last * starts at a dot (analytics-*.8x8.com -> 8x8.com). Those globs
    # ride the SAME O(labels) suffix walk the wildcards use, so finding them is a
    # hash lookup, not a regex. "" => no such anchor, fall back to the prefilter.
    function gl_anchor(p,   q, t) {
      q = p
      while ((t = index(q, "*")) > 0) q = substr(q, t+1)
      if (substr(q, 1, 1) != ".") return ""
      q = substr(q, 2)
      if (q == "" || index(q, ".") == 0) return ""
      return q
    }
    # Specificity on the SAME scale as the wildcard path, which uses
    # length(apex): drop the stars and one character, so a hypothetical
    # "*.logitech.com" scores 12 here exactly as it does there, and
    # "*vc.logitech.com" scores 14 and correctly outranks it.
    function gl_speclen(p,   i, n) {
      n = 0
      for (i = 1; i <= length(p); i++) if (substr(p, i, 1) == "*") n++
      return length(p) - n - 1
    }
    # Is this a pattern the glob pass should own? Rejects the two hash-owned
    # shapes, and rejects anything that is not a hostname pattern at all — the
    # feeds put prose in the asset field ("3rd party services hosted at
    # *.sophos.com", "open redirect at *.epam.com"), regex alternations
    # (*.doctolib.(fr|de|it)), ### placeholders and redacted block runs. Those
    # stay in the exact bucket as the inert rows they already were; compiling
    # them would hand feed-controlled text to the regex engine, and one bare "*"
    # in outscope_patterns.tsv would then exclude the entire internet.
    # recon_scope_db.sh drops them at normalize time too — this is the belt for
    # those braces, so an old or hand-edited TSV cannot inject a regex here.
    function gl_usable(p) {
      if (index(p, "*") == 0) return 0
      if (substr(p, 1, 2) == "*." && index(substr(p, 3), "*") == 0) return 0
      # Same denylist as looks_like_host in recon_scope_db.sh, and a denylist
      # rather than an ASCII allow-list for the same reason: an allow-list
      # silently discards IDN assets (vœux.vinci.com is a live host on a paying
      # program). Reject what a hostname can never contain, then require a dot
      # and one ASCII alphanumeric.
      if (p ~ /[ \t\r\n]/) return 0
      if (p ~ /[(){}|?+^$<>!,;:"#%&=~@]/) return 0
      if (index(p, "[") > 0 || index(p, "]") > 0) return 0
      if (index(p, "\\") > 0 || index(p, "/") > 0) return 0
      if (index(p, APOS) > 0 || index(p, "`") > 0) return 0
      if (index(p, ".") == 0) return 0
      if (p !~ /[a-z0-9]/) return 0
      if (gl_literal(p) == "") return 0
      return 1
    }

    # Fold every row of one matched pattern into the per-program best-so-far.
    # spec = how specific the matched pattern is (exact host >> long apex >
    # short apex). More specific always wins; on a tie the better payout tier
    # wins, so two assets collapsing to one hostname resolve to the payable one.
    function consider(list, spec, patstr,   n, arr, i, e, key, r, keep) {
      n = split(list, arr, GS)
      for (i = 1; i <= n; i++) {
        split(arr[i], e, SUBSEP)
        key = e[2] SUBSEP e[3]          # handle + platform = one program
        r = rank(e[5])
        keep = 0
        if (!(key in gspec))                                keep = 1
        else if (spec > gspec[key])                         keep = 1
        else if (spec == gspec[key] && r < grank[key])      keep = 1
        if (!keep) continue
        gspec[key] = spec; grank[key] = r; gentry[key] = arr[i]; gpat[key] = patstr
      }
    }
    BEGIN {
      FS = "\t"
      # Entry fields are joined with SUBSEP and entries with GS (0x1D) — control
      # characters that cannot occur in the TSV. A printable delimiter is NOT safe:
      # a bugcrowd handle falls back to the program NAME, and one of those names
      # literally contains a pipe (REA Group | realestate.com.au, ...), which
      # shifted every field of that entry. Note: no apostrophes may appear inside
      # this awk program — it is a shell single-quoted string, so one would end it.
      GS = sprintf("%c", 29)
      # No apostrophe may appear in this awk source (it is a shell single-quoted
      # string), so gl_usable tests for one by code point instead.
      APOS = sprintf("%c", 39)
      # Load OUT patterns -> exact/wildcard/glob. Keep the LOWEST file index per key
      # so "first match in file order" (the original loop semantics) is preserved.
      # OUT gets the glob pass too, and that is not optional: teaching IN about
      # *vc.logitech.com while OUT still ignored *dev.ibotta.com and *kohls.com
      # would widen paying surface without honouring the matching exclusions.
      oi = 0
      while ((getline line < out_tsv) > 0) {
        n = split(line, f, "\t")
        if (n < 1 || f[1] == "") continue
        oi++
        pat = f[1]
        meta = oi SUBSEP pat SUBSEP (n>=2?f[2]:"") SUBSEP (n>=3?f[3]:"")
        if (gl_usable(pat)) {
          if (!(pat in og_meta)) {
            og_meta[pat] = meta
            og_rx[pat]   = gl_compile(pat)
            og_lit[pat]  = gl_literal(pat)
            ganc = gl_anchor(pat)
            if (ganc != "") og_anch[ganc] = ((ganc in og_anch) ? og_anch[ganc] GS pat : pat)
            else            og_freestr    = (og_freestr == "" ? pat : og_freestr GS pat)
          }
        } else if (substr(pat,1,2) == "*.") {
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
        sev = (n>=6?f[6]:"")
        submit = (n>=7 && f[7]!="" ? f[7] : "true")
        pat = f[1]
        # entry := idx SUBSEP handle SUBSEP platform SUBSEP pays SUBSEP tier
        #          SUBSEP max_severity SUBSEP submit
        entry = ii SUBSEP (n>=2?f[2]:"") SUBSEP (n>=3?f[3]:"") SUBSEP pays SUBSEP tier SUBSEP sev SUBSEP submit
        if (gl_usable(pat)) {
          if (!(pat in gl_rx)) {
            gl_rx[pat]   = gl_compile(pat)
            gl_spec[pat] = gl_speclen(pat)
            gl_lit[pat]  = gl_literal(pat)
            ganc = gl_anchor(pat)
            if (ganc != "") gl_anch[ganc] = ((ganc in gl_anch) ? gl_anch[ganc] GS pat : pat)
            else            gl_freestr    = (gl_freestr == "" ? pat : gl_freestr GS pat)
          }
          gl_ent[pat] = ((pat in gl_ent) ? gl_ent[pat] GS entry : entry)
        } else if (substr(pat,1,2) == "*.") {
          apex = substr(pat,3)
          in_wild[apex] = ((apex in in_wild) ? in_wild[apex] GS entry : entry)
        } else {
          in_exact[pat] = ((pat in in_exact) ? in_exact[pat] GS entry : entry)
        }
      }
      close(in_tsv)
      # Split the unanchored lists ONCE — they are walked once per host.
      gl_fn = (gl_freestr == "" ? 0 : split(gl_freestr, gl_free, GS))
      og_fn = (og_freestr == "" ? 0 : split(og_freestr, og_free, GS))
      for (k in gl_rx) gl_n++
      for (k in og_rx) og_n++
      FS = "\n"
    }
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
      if (hard_excluded) { printf "%s\tfalse\ttrue\tfalse\t\t\t\t\t%s\tnone\t\tfalse\n", host, hard_reason; next }

      # ---- OUT: lowest file index among matches (exact host + wildcard suffixes) ----
      out_idx = -1; out_meta = ""
      if (host in out_exact) { split(out_exact[host], m, SUBSEP); out_idx = m[1]+0; out_meta = out_exact[host] }
      c = host
      while (1) {
        if (c in out_wild) { split(out_wild[c], m, SUBSEP); if (out_idx < 0 || (m[1]+0) < out_idx) { out_idx = m[1]+0; out_meta = out_wild[c] } }
        p = index(c, "."); if (p == 0) break; c = substr(c, p+1)
      }
      # ---- OUT globs: same lowest-file-index rule ----------------------------
      if (og_n > 0) {
        delete ocand
        gc = host
        while (1) {
          if (gc in og_anch) { gn = split(og_anch[gc], gcl, GS); for (gi=1; gi<=gn; gi++) ocand[gcl[gi]] = 1 }
          gt = index(gc, "."); if (gt == 0) break; gc = substr(gc, gt+1)
        }
        for (gi = 1; gi <= og_fn; gi++) if (index(host, og_lit[og_free[gi]]) > 0) ocand[og_free[gi]] = 1
        for (gp in ocand) {
          if (host !~ og_rx[gp]) continue
          split(og_meta[gp], m, SUBSEP)
          if (out_idx < 0 || (m[1]+0) < out_idx) { out_idx = m[1]+0; out_meta = og_meta[gp] }
        }
      }

      # ---- IN stage 1: per program, the most specific matching asset ---------
      delete gspec; delete grank; delete gentry; delete gpat
      if (host in in_exact) consider(in_exact[host], 1000000, host)
      c = host
      while (1) {
        if (c in in_wild) consider(in_wild[c], length(c), "*." c)
        p = index(c, "."); if (p == 0) break; c = substr(c, p+1)
      }
      # ---- IN stage 1b: the globs the hash index cannot hold ------------------
      # The gate the two hash buckets earn is CANDIDATE-level, not result-level:
      # an anchored glob is found by the same suffix walk as above, an unanchored
      # one by a single index() per pattern, and only survivors are regex-tested.
      # A host with no candidate — 99%+ of them — costs a handful of hash misses.
      # It has to stay unconditional on the hash OUTCOME, because consider()
      # resolves per PROGRAM and stage 2 resolves across programs: a glob can be
      # the more specific asset on the very program the hash already matched
      # (exactly the *vc.logitech.com case, beating *.logitech.com), or the only
      # match on a better-paying one.
      if (gl_n > 0) {
        delete gcand
        gc = host
        while (1) {
          if (gc in gl_anch) { gn = split(gl_anch[gc], gcl, GS); for (gi=1; gi<=gn; gi++) gcand[gcl[gi]] = 1 }
          gt = index(gc, "."); if (gt == 0) break; gc = substr(gc, gt+1)
        }
        for (gi = 1; gi <= gl_fn; gi++) if (index(host, gl_lit[gl_free[gi]]) > 0) gcand[gl_free[gi]] = 1
        for (gp in gcand) if (host ~ gl_rx[gp]) consider(gl_ent[gp], gl_spec[gp], gp)
      }

      # ---- IN stage 2: across programs, best payout tier then file order -----
      in_rank = 99; in_idx = -1; winner = ""
      for (k in gentry) {
        split(gentry[k], w, SUBSEP)
        wr = rank(w[5]); wi = w[1]+0
        if (wr < in_rank || (wr == in_rank && (in_idx < 0 || wi < in_idx))) { in_rank = wr; in_idx = wi; winner = k }
      }

      # ---- assemble ----------------------------------------------------------
      pattern = ""; program = ""; platform = ""; best_pays = "false"; best_tier = "none"
      best_sev = ""; best_submit = "false"
      if (winner != "") {
        split(gentry[winner], w, SUBSEP)
        pattern = gpat[winner]; program = w[2]; platform = w[3]
        best_pays = w[4]; best_tier = w[5]; best_sev = w[6]; best_submit = w[7]
      }
      out_pattern = ""; out_program = ""
      if (out_meta != "") { split(out_meta, m, SUBSEP); out_pattern = m[2]; out_program = m[3] }

      if (out_meta != "") { in_scope = "false"; best_pays = "false"; best_tier = "none"; best_sev = ""; best_submit = "false" }
      else { in_scope = (winner != "" ? "true" : "false") }
      out_of_scope = (out_meta != "" ? "true" : "false")

      printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
             host, in_scope, out_of_scope, best_pays, program, platform, pattern,
             out_program, out_pattern, best_tier, best_sev, best_submit
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
    # field order: host in out pays program platform pattern out_program
    #              out_pattern payout_tier max_severity submit
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
    # v2.3: `pattern` above is now the SPECIFIC asset that decided `pays`, so
    # these two describe that asset rather than the program as a whole.
    if ($11 != "") printf ",\"max_severity\":\"%s\"", esc($11)
    else           printf ",\"max_severity\":null"
    if ($2 == "true") printf ",\"eligible_for_submission\":%s", ($12 == "false" ? "false" : "true")
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

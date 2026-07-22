#!/usr/bin/env bash
# =============================================================================
# recon_cognito_carveout.sh — shared PROGRAM-SCOPE CARVE-OUT guard for the
# cognito unauth-cred lanes (nighthunt web + mobile APK). Sourced lib.
#
# A REAL unauth Cognito issuance can still be UNREPORTABLE because of the
# *program's* rules, not the finding's merit (KB docs/knowledge/class-cognito-unauth.md):
#   - Amazon VRP explicitly carves out "AWS and AWS customer assets" as always
#     out of scope, and lists "disclosed creds -> pivot" as an INVALID example.
#   - AWS VDP excludes customer misconfigurations and pays no bounty.
# So an Amazon-owned pool has no valid venue. When a finding is real but hits
# such a carve-out, the lane DOWNGRADES it to a permanent host_note instead of
# pinging #review / db_confirm, so the operator isn't paged with an unpayable pool.
#
# cognito_carveout_reason <program> <provenance> <account>
#   -> prints a short reason and returns 0 when the finding is unreportable,
#      returns 1 (prints nothing) when it should mint/report normally.
# Signals (any one triggers): (a) a carve-out program label, (b) an Amazon/AWS-
# owned provenance root domain, (c) a known Amazon/AWS-owned AWS account behind
# the assumed role. All three overridable via env for future programs.
# =============================================================================
CARVEOUT_PROGRAM_RE="${COGNITO_CARVEOUT_PROGRAM_RE:-amazonvrp|amazon vulnerability research|amazon vrp|aws vdp|aws vulnerability disclosure}"
CARVEOUT_ROOTS="${COGNITO_CARVEOUT_ROOTS:-amazon.com amazonaws.com aws.amazon.com}"
CARVEOUT_ACCOUNTS="${COGNITO_CARVEOUT_ACCOUNTS:-248058390976}"   # com.amazon.relay pool acct

cognito_carveout_reason() {  # <program> <provenance> <account> -> reason (rc 0) if unreportable
  local program="${1:-}" prov="${2:-}" acct="${3:-}" p_lc prov_lc rd a
  p_lc="$(printf '%s' "$program" | tr '[:upper:]' '[:lower:]')"
  if [ -n "$p_lc" ] && printf '%s' "$p_lc" | grep -qE "$CARVEOUT_PROGRAM_RE"; then
    printf 'program-carveout(%s)' "$program"; return 0
  fi
  prov_lc="$(printf '%s' "$prov" | tr '[:upper:]' '[:lower:]')"
  for rd in $CARVEOUT_ROOTS; do
    case "$prov_lc" in *".$rd"|"$rd") printf 'amazon-owned-provenance(%s)' "$prov"; return 0 ;; esac
  done
  for a in $CARVEOUT_ACCOUNTS; do
    [ -n "$acct" ] && [ "$acct" = "$a" ] && { printf 'amazon-owned-account(%s)' "$acct"; return 0; }
  done
  return 1
}

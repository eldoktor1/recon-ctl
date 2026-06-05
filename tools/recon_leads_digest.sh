#!/usr/bin/env bash
# =============================================================================
# recon_leads_digest.sh — daily entrypoint for the curated lead digest.
#
# Flow: deterministic module pre-selects PROMOTE/HOLD (drowns noise, dedups) ->
# headless Claude (Max plan, OAuth) VERIFIES each lead from the ES evidence
# (tech versions, titles, ollama fields) WITHOUT probing targets -> verdicts are
# attached as a 2nd Discord embed and the digest posts to #leads.
#
# Robust by design: if Claude is missing / errors / times out / returns junk,
# we fall back to the deterministic post so a digest ALWAYS lands before 6:30 PM.
#
# Modes:  (default) verify + post to #leads     |     --dry  = no posting (preview)
# Runs as d0k. NOT target-facing: ES reads + Anthropic API + Discord POST only.
# Invoked by Windows Task Scheduler (ReconLeadsDigest) via recon_leads_digest.vbs.
# =============================================================================
set -uo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MODULE="$REPO_DIR/scripts/recon_digest_leads.sh"
CLAUDE_BIN="${CLAUDE_BIN:-$HOME/.local/bin/claude}"
LOG="${LEADS_LOG:-$HOME/recon/logs/leads_digest.log}"
mkdir -p "$(dirname "$LOG")"

DRY=0; [[ "${1:-}" == "--dry" || "${1:-}" == "dry" ]] && DRY=1

log(){ printf '[%s LEADS-WRAP] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" | tee -a "$LOG" >&2; }

# ── 1) deterministic selection = the context Claude will verify ──────────────
sel="$(bash "$MODULE" emit 2>/dev/null || true)"
if ! printf '%s' "$sel" | jq -e '.counts' >/dev/null 2>&1; then
  log "module emit failed — deterministic fallback"
  [[ $DRY -eq 1 ]] && exec bash "$MODULE" print
  exec bash "$MODULE" post
fi
pc="$(printf '%s' "$sel" | jq '.promote|length')"
hc="$(printf '%s' "$sel" | jq '.hold|length')"
log "context: ${pc} promote / ${hc} hold"

promptfile="$(mktemp)"; notefile="$(mktemp)"
trap 'rm -f "$promptfile" "$notefile"' EXIT

# trim to the fields Claude needs to VERIFY (keeps the prompt small)
ctx="$(printf '%s' "$sel" | jq -c '{
  promote:(.promote|map({host,cls,sig,cves,tech,title,status,score,prog,ptier,ai})),
  hold:(.hold|map({host,cls,sig,cves,tech,title,score,prog,ptier,ai}))}')"

cat > "$promptfile" <<PROMPT
You are the SECOND ENFORCER for a bug-bounty recon pipeline: a skeptical reviewer
that cuts noise but never blindly dismisses. Below are today's PROMOTE and HOLD
leads as JSON (already pre-filtered). Do NOT browse, fetch, or probe anything —
reason ONLY from the data given. The tech[] array often carries the VERSION
(e.g. "Drupal:11", "Magento", "Atlassian Confluence").

For each notable lead output one verdict: KEEP (signal/CVE genuinely applies),
DOWNGRADE (real but version/surface unconfirmed — needs the cheap check first),
or DROP (false positive — give the checkable reason).

Hard rules:
- A KEV/CVE only applies if the tech VERSION is in range. If tech shows a fixed
  version out of range (e.g. Drupal:11 vs CVE-2018-7600 which needs <8.5.1),
  say DROP or DOWNGRADE and state that fact.
- Module-confirmed classes (cls = bypass, nuclei, portcrit, takeover) are
  floor-protected: never DROP — KEEP or DOWNGRADE only.
- Scrutinize ollama (ai field state/score/rec): call out missing/stale/over/under.
- Be terse. Output ONLY GitHub-flavored markdown, max 22 lines, NO preamble,
  NO code fences. Format exactly:
**Verdicts**
- \`host\` — KEEP/DOWNGRADE/DROP — reason (<=14 words)
Lead with the 4-5 highest-impact. Final line: \`ollama:\` <one short clause>.

DATA:
$ctx
PROMPT

# ── 2) headless Claude verification (Max plan OAuth, hard timeout) ───────────
notes=""
if [[ -x "$CLAUDE_BIN" ]]; then
  timeout 240 "$CLAUDE_BIN" -p "$(cat "$promptfile")" > "$notefile" 2>>"$LOG"; rc=$?
  if [[ $rc -eq 0 && "$(wc -c < "$notefile")" -ge 25 ]]; then
    notes="present"
    log "claude verification ok ($(wc -l < "$notefile") lines)"
  else
    : > "$notefile"
    log "claude verification unusable (rc=$rc) — posting without notes"
  fi
else
  : > "$notefile"
  log "claude binary not found at $CLAUDE_BIN — posting without notes"
fi

# ── 3) act ──────────────────────────────────────────────────────────────────
if [[ $DRY -eq 1 ]]; then
  echo "========== DRY RUN — nothing posted =========="
  echo "----- deterministic digest -----"; bash "$MODULE" print
  echo; echo "----- Claude verification notes -----"
  [[ -s "$notefile" ]] && cat "$notefile" || echo "(none)"
  exit 0
fi
bash "$MODULE" post "$notefile"

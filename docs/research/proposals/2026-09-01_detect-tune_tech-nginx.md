# PROPOSAL (proposal) for docs/knowledge/tech-nginx.md — detect-tune 2026-09-01
_Review and apply manually; not auto-merged into the KB._

## CVE-2026-40460 — mechanism detail (2026-09-01)
Previously only in our version table (1.25.0-1.30.0, `nginx:1.29.7` in-range). Mechanism:
NGINX's HTTP/3/QUIC handling trusts the source IP asserted at the QUIC layer without validating
it against actual connection state (UDP has no TCP-style handshake to bind it to) — so
IP-based allowlists, geo-restriction, and rate-limiting keyed on client IP can be bypassed on
vulnerable HTTP/3-enabled hosts. This is an ACCESS-CONTROL BYPASS class, not just DoS — worth
weighting higher than a typical version-only n-day LEAD when the host also gates something
(admin panel, internal API) by IP.
**Safe detect (passive):** `curl -sI https://<host> | grep -i alt-svc` → `h3` present + `Server:
nginx/1.25–1.30.0` = in-range LEAD. Confirming the bypass for real requires sending
spoofed-source QUIC datagrams — active spoofing traffic against the target's own access
controls; keep this operator-reviewed, not in the unattended probe battery.
Source: https://www.sentinelone.com/vulnerability-database/cve-2026-40460/

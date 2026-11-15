# PROPOSAL (proposal) for docs/knowledge/tech-nginx.md — detect-tune 2026-09-06
_Review and apply manually; not auto-merged into the KB._

## Nginx UI (distinct product — NOT vanilla nginx) — CVE-2026-27944 unauth backup+key disclosure

Nginx UI (`0xJacky/nginx-ui`) is a self-hosted web dashboard for managing an Nginx install,
often running alongside/behind the Nginx instances we already fingerprint via the `tech:` field —
treat it as a SEPARATE fingerprint, not a version of Nginx itself.

- **Default port**: 9000. Login page/title identifies as "Nginx UI".
- **Vulnerable versions**: < 2.3.3 (fixed in 2.3.3).
- **Confirm primitive (single unauth GET, non-destructive)**: `GET /api/backup`. A `200` response
  carrying an `X-Backup-Security` response header (base64 `<32-byte-AES-256-key>:<16-byte-IV>`) is
  CONFIRMED unauthenticated backup exposure by itself — the header alone proves the primitive; no
  download required to score it as real.
- **Chain-to-impact (do once per host)**: download the backup, decrypt with the disclosed key/IV
  (AES-256-CBC), run it through `engine/impact.py scan_secrets`/`classify_data` (the backup contains
  user credentials, session tokens, SSL private keys, and the box's Nginx configs) — mint on what's
  actually recovered, redacted, never the raw dump.
- **FP note**: version alone is a LEAD per the KEV-tech-class doctrine — confirm the `/api/backup`
  header actually fires before minting anything above LEAD.
- Source: GHSA-g9w5-qffc-6762, CVE-2026-27944 (CVSS 9.8).

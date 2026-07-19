# PROPOSAL (proposal) for docs/knowledge/class-clientside-secrets.md — tooling 2026-07-19
_Review and apply manually; not auto-merged into the KB._

## Tool: Titus (praetorian-inc/titus) — mobile/binary secret extraction
Added 2026-07-19 (research digest).

Fills a gap trufflehog doesn't cover: native secret extraction+scan from **APK/IPA**, Office docs,
PDFs, and archives (zip/tar/7z), not just git history / plain source. 487 detection rules (from
NoseyParker + Kingfisher), Apache 2.0, actively released (v1.2.7, 2026-07-15).

- `titus scan --validate <path.apk>` — extracts strings from the APK and runs the full rule set;
  `--validate` makes a read-only outbound call to the credential's own API to confirm live/dead
  (same semantics as `trufflehog --only-verified` — safe, not target traffic).
- Use for the APK-based recon lane (`recon_cognito_apks.py` and similar): run Titus over any APK
  pulled for analysis BEFORE hand-rolling unzip+grep secret extraction.
- Keep trufflehog for the existing GH-leaks / git-history lane — different corpus, no reason to swap.
- Source: https://github.com/praetorian-inc/titus

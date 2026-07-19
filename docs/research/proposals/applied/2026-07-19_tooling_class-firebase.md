# PROPOSAL (proposal) for docs/knowledge/class-firebase.md — tooling 2026-07-19
_Review and apply manually; not auto-merged into the KB._

## Tool: OpenFirebase (Icex0/OpenFirebase) — APK/IPA Firebase extraction + probe
Added 2026-07-19 (research digest).

Automates what this KB describes manually: extracts Firebase config from an APK (DEX string pool +
resources) or IPA (`GoogleService-Info.plist` + Mach-O scan), then probes Firestore/Realtime DB/
Storage/Remote Config/Cloud Functions for unauthenticated read+write, and flags hardcoded
service-account keys / PEM private keys recovered from the binary. Python, pipx install, v1.3.0
(2026-04-29), 55★. **License: custom NC (non-commercial) — verify fit before broad adoption.**

- READ probes are unauthenticated and safe — fine for the autonomous lane.
- WRITE probes upload a benign marker string (`OpenFirebase_write_check`) to prove a write-ACL
  gap — same pattern as our bucket-scanner `writecheck`. Per doctrine, gate this behind
  operator-on-demand confirm, same as `recon-buckets confirm`, never run unattended.
- Natural pairing with Titus (secret extraction) in the APK recon pipeline: Titus for leaked
  creds/keys in the binary, OpenFirebase for live-service ACL probing once a Firebase project ID
  is identified.
- Source: https://github.com/Icex0/OpenFirebase

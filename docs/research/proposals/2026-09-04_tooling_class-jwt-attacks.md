# PROPOSAL (proposal) for docs/knowledge/class-jwt-attacks.md — tooling 2026-09-04
_Review and apply manually; not auto-merged into the KB._

## Tooling (added 2026-09-04)
- **`ticarpi/jwt_tool`** (github.com/ticarpi/jwt_tool, 6.8k★, actively maintained) — run this as the
  standard first pass on any captured JWT during authed testing. Modes: `-T` tamper/playground,
  `-M pb` full vulnerability scan (alg:none, RS/HS256 confusion, kid injection, jku/x5u spoof),
  `-C` HMAC-secret dictionary crack. Human-in-the-loop only (needs a real captured token from an
  owned session) — wire into the Program Workspace WSTG ATHN/SESS step, not any autonomous lane.
